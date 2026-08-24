# totan リファクタリング計画

## 1. 目的

現在の通信仕様を維持したまま、IPv4/IPv6で共通して扱える構造へ整理し、負荷時の挙動と保守性を改善する。

対象となる主要経路は次の2種類とする。

1. 平文HTTPを上流HTTPプロキシへ転送する経路
2. HTTPSに対して上流HTTPプロキシへ`CONNECT`し、その後TCPトンネルとして中継する経路

Pingoraは平文HTTP処理に引き続き使用する。HTTPSの`CONNECT`ネゴシエーションと、その後の双方向TCP中継は現在の実装を整理して継続する。

## 2. スコープ

### 対象

- netfilter/eBPFで取得したoriginal destinationの共通表現
- eBPFのtc ingress経路とcgroup host経路の責務整理
- 既存HTTP/HTTPS処理の共通化と境界の明確化
- Pingoraのライフサイクル、エラー処理、接続再利用の見直し
- IPv4/IPv6両対応
- 接続数制限、タイムアウト、後片付け、負荷試験
- 権限要件と起動時検証の明文化
- unit/integration/e2eテストの再構成

### 対象外

- 新しい上流プロキシ方式の追加
- HTTP以外のアプリケーションプロトコル対応
- TLS終端、証明書生成、HTTPSの内容解析
- HTTP/3、QUIC、UDP転送
- Ciliumのhost hairpin構成の導入
- tc経路とcgroup経路をカーネル内で無理に同一方式へ変更すること
- Pingoraの置き換え、またはHTTPパーサーの自前実装
- PACや既存のプロキシ選択仕様の機能拡張

既存のSOCKS/PAC関連コードについては、本リファクタリングで機能追加・仕様変更・削除を行わない。HTTP/HTTPS経路の整理に必要な共通部分だけ、既存挙動を維持して移動する。

## 3. 維持する不変条件

- original destinationのIPアドレスとポートを欠落させない。
- TCP/80の平文HTTPは、上流HTTPプロキシへabsolute-formのrequest-targetで送る。
- TCP/443は、上流HTTPプロキシへの`CONNECT`成功後にだけクライアントデータを中継する。
- `407`や`403`など、上流プロキシが明示的に拒否した通信をDIRECTへ漏らさない。
- totan自身の上流接続を再捕捉しない。
- tc ingressでは`bpf_sk_assign`を使用し、host発通信はcgroup hookを使用する。
- 全捕捉経路で共通の`max_connections`制限を適用する。
- 起動時に一部の必要な設定だけが成功した状態で処理を開始しない。
- IPv4対応を壊さず、IPv6でも同じHTTP/CONNECTの意味になるようにする。

## 4. 目標アーキテクチャ

```text
                     +-------------------------+
netfilter ---------->|                         |
tc ingress v4/v6 --->| OriginalDstResolver     |
cgroup v4/v6 ------->| -> SocketAddr           |
                     +------------+------------+
                                  |
                                  v
                     +-------------------------+
                     | ConnectionContext       |
                     | client/original dst     |
                     | hostname/PAC result     |
                     +------------+------------+
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
          +-------------------+       +-------------------+
          | Plain HTTP       |       | HTTPS             |
          | Pingora          |       | HTTP CONNECT      |
          | forward proxy    |       | TCP relay         |
          +-------------------+       +-------------------+
```

カーネル側の捕捉方法は統一しない。userspaceへ渡す結果を`SocketAddr`と共通の接続コンテキストへ正規化し、それ以降の制御を共通化する。

## 5. 実施フェーズ

### Phase 0: 現行挙動の固定

- 現在のunit/integration/e2eテストを全て実行し、基準結果を記録する。
- HTTP、HTTPS CONNECT、PAC、DIRECT、エラー時処理、自己再捕捉回避のcharacterization testを追加する。
- `toolkit/e2e/stress.sh`で同時接続数、失敗率、FD数、メモリ使用量を記録する。
- Pingora経路とCONNECT経路で、接続確立時間と接続終了理由を観測可能にする。

完了条件:

- リファクタリング前の外部挙動をテストで再現できる。
- HTTP/CONNECTの成功だけでなく、timeout、RST、`407`、上流停止も判定できる。

### Phase 1: 型とモジュール境界の整理

- original destination取得を`OriginalDstResolver`相当の責務へ集約する。
- `SO_ORIGINAL_DST`、`sk_assign`後の`local_addr()`、cgroup map参照を同じ戻り値へ正規化する。
- `InterceptedConnection`をIPv4/IPv6共通の`SocketAddr`ベースに保つ。
- アドレス文字列を直接`format!`せず、IPv6の`[address]:port`を保証するauthority生成関数を用意する。
- capture、policy resolution、upstream establishment、relayのエラー型を分離する。
- BPF/userspace共有構造体について、サイズ、alignment、byte orderをcompile-time testで固定する。

完了条件:

- HTTP/PAC/CONNECTコードがoriginal destinationの取得方式を意識しない。
- IPv4 literal、IPv6 literal、hostnameのauthority生成テストが通る。
- BPF mapの値をuserspaceがfamilyごとの分岐だけで`SocketAddr`へ変換できる。

### Phase 2: Pingora経路の整理

- Pingoraは維持し、平文HTTP専用の境界を明確にする。
- immutableな設定と接続・リクエスト固有contextを分離する。
- 接続ごとに生成している`ServerConf`、proxy app、shutdown channelのうち、安全に共有できるものを起動時に生成する。
- Pingoraの`process_new_http`の結果を握り潰さず、エラー分類とログへ反映する。
- absolute-form変換を専用関数にし、path、query、明示port、IPv6 Hostをテストする。
- upstream connection poolingが実際に共有される構成か確認し、共有されない場合はサービス所有構造を修正する。
- PACの候補選択とPingoraへストリームを渡す「commit point」を明示する。既存のフェイルオーバー仕様は変更しない。

完了条件:

- 1接続ごとの不要な設定オブジェクト生成がなくなる。
- keep-aliveで複数リクエストを処理しても宛先情報が混ざらない。
- absolute-formがIPv4/IPv6の両方でRFCに沿ったwire formatになる。
- Pingora内部エラーが成功として記録されない。

### Phase 3: HTTPS CONNECT/TCP relayの整理

- TCP接続、HTTP CONNECTネゴシエーション、双方向copyを別の段階として扱う。
- connect timeout、handshake timeout、idle timeoutを各段階へ一貫して適用する。
- CONNECT応答ヘッダーの最大サイズを維持し、分割受信を正しく扱う。
- 上流へクライアントデータを送る前をフェイルオーバー可能な範囲として明文化する。
- relay終了時に両方向を適切にshutdownし、half-closeとRSTをテストする。
- HTTPとCONNECTで共通する接続確立、`SO_MARK`、retry、ログ処理を共通部品化する。

完了条件:

- CONNECT拒否と接続失敗を区別できる。
- timeoutや片方向closeでタスク、socket、permitが残らない。
- 現行のDIRECT fallback漏えい防止条件を維持する。

### Phase 4: eBPF dual-stack化

#### tc ingress

- Ethernet typeでIPv4/IPv6を分岐し、共通の「対象port判定・listener lookup・assign」処理へ接続する。
- IPv6用の`bpf_sock_tuple.ipv6`とIPv6 listener lookupを実装する。
- IPv4/IPv6で別listenerを使用し、listener familyとtuple familyを一致させる。
- IPv6 extension headerはverifierで検証可能な回数に限定して走査する。
- fragment、非TCP、TCP/80・443以外は必ずpassする。
- `bpf_sk_assign`の戻り値を確認し、失敗を統計またはログで観測できるようにする。

#### host cgroup

- `cgroup/connect6`を追加し、対象をTCP/80・443に限定する。
- original destinationのfamily、128-bit address、portを保持できるBPF ABIへ変更する。
- IPv4/IPv6のcookieからaccepted socketまでのcorrelation keyが衝突しない構造にする。
- `::1:<redirect_port>`への書き換えと、totan自身の`SO_MARK`除外をIPv6でも適用する。
- LRU mapからの正常削除、未accept entryのeviction、map pressureをテストする。

#### userspace loader

- `connect4`と`connect6`を同じ設定単位でattach/detachする。
- IPv4/IPv6用listener、BPF map、program linkのRAII所有関係を明確にする。
- 一方のfamilyだけattachに失敗した場合は、部分稼働せず明確に起動失敗させる。

完了条件:

- Pod/VM発とhost発の両方でIPv4/IPv6のoriginal destinationが一致する。
- 80/443以外、UDP、QUICを捕捉しない。
- 高並行接続時にcgroup mapの誤対応や取り違えが発生しない。

### Phase 5: netfilter dual-stack化

- nftablesの`inet` familyでIPv4/IPv6双方の対象portを同じ方針で管理する。
- IPv4の`SO_ORIGINAL_DST`とIPv6のoriginal destination取得をfamily別に実装する。
- TPROXY/redirect listenerをfamily別に明示し、dual-stack socketのOS依存挙動に依存しない。
- 自己再捕捉を防ぐmarkをIPv4/IPv6の両ルールで共通に扱う。
- rule追加途中の失敗時に、追加済みruleをRAIIで除去する。

完了条件:

- managed rulesの起動・終了後にIPv4/IPv6ともルールが残留しない。
- 外部管理ルールでもoriginal destination取得方法が文書化されている。

### Phase 6: policy routingと権限の整理

- IPv4の`ip rule`/local routeと対になるIPv6の`ip -6 rule`/`local ::/0`を管理する。
- 起動時に必要なkernel feature、cgroup v2、BPF program type、socket optionを検査する。
- root起動とnon-root起動で必要なcapabilityを実機テストする。
- `CAP_NET_ADMIN`だけで足りる処理と、kernel設定によって`CAP_BPF`、`CAP_PERFMON`等が必要になる処理を区別して記録する。
- capability不足をattach途中ではなく、可能な限り起動前検査で報告する。

完了条件:

- 「rootなら動く」「non-rootならどのcapabilityが必要か」を実測結果付きで説明できる。
- 権限不足で部分的にrule/programだけが残らない。

### Phase 7: 負荷・障害耐性の確認

- 全listenerで1つのconnection semaphoreを共有する現行方針を維持する。
- permit取得、accept、original destination解決、relay終了までの所有関係をテストする。
- accept error時のbackoffと、EMFILE時にbusy loopしないことを確認する。
- Pingora経路とCONNECT経路で同じ接続上限、timeout、shutdown方針を適用する。
- BPF LRU map使用量、active connection、拒否数、timeout数を観測可能にする。
- stress testでIPv4/IPv6、tc/cgroup、HTTP/CONNECTを個別および混在で実行する。

完了条件:

- `max_connections`を超えてuserspace task/FDが無制限に増えない。
- 長時間試験後にBPF map、FD、タスク、nftables ruleが残留しない。
- リファクタリング前と比較して、性能劣化が許容範囲内である。

## 6. テストマトリクス

| 捕捉方式 | 発信元 | Family | HTTP | HTTPS CONNECT | 自己再捕捉 | 負荷試験 |
|---|---|---:|---:|---:|---:|---:|
| netfilter | host | IPv4 | 必須 | 必須 | 必須 | 必須 |
| netfilter | host | IPv6 | 必須 | 必須 | 必須 | 必須 |
| eBPF tc ingress | Pod/VM | IPv4 | 必須 | 必須 | 必須 | 必須 |
| eBPF tc ingress | Pod/VM | IPv6 | 必須 | 必須 | 必須 | 必須 |
| eBPF cgroup | host | IPv4 | 必須 | 必須 | 必須 | 必須 |
| eBPF cgroup | host | IPv6 | 必須 | 必須 | 必須 | 必須 |

各セルで最低限、次を確認する。

- original destinationのIP/port
- Host/SNIによるPAC評価結果
- HTTP absolute-form
- CONNECT authority
- 上流停止時のtimeout/retry
- `407`/`403`時にDIRECTへfallbackしないこと
- client close、upstream close、half-close
- IPv6 literalの`[address]:port`表現

## 7. 実行順序と変更単位

1. Phase 0でテストを固定する。
2. Phase 1からPhase 3までをIPv4のまま完了し、userspaceの責務を整理する。
3. Phase 4とPhase 5で各捕捉方式をdual-stack化する。
4. Phase 6でroute、rule、capabilityを揃える。
5. Phase 7の混在負荷試験を通す。

各Phaseは独立したレビュー可能な変更単位にし、BPF ABI変更とuserspace loader変更は同じ変更内で行う。IPv6対応中もIPv4 e2eを継続して実行し、途中状態で既存経路を壊さない。

## 8. 完了条件

- 平文HTTPはPingora、HTTPSはHTTP CONNECTという現在の構成を維持している。
- 新しい接続方式・プロキシ方式を追加していない。
- netfilter、eBPF tc ingress、eBPF cgroupの全経路がIPv4/IPv6で動作する。
- 捕捉方式によらず、userspaceのHTTP/CONNECT処理が同じ接続コンテキストを使用する。
- `toolkit`のe2eとstress testが全テストマトリクスで成功する。
- root/non-rootの権限要件と制約が文書化されている。
- 負荷時に接続数、FD、タスク、BPF map entryが無制限に増加しない。
