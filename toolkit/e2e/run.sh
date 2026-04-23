#!/usr/bin/env bash
# Unified e2e runner for totan.
#
# Usage: run.sh <netfilter|ebpf>
#
# Both modes share:
#   - Three forward-mode mock proxies on 127.0.0.1:8880 / :8881 / :8882
#   - A mock SOCKS5 proxy on 127.0.0.1:1080
#   - A plain HTTP backend on 127.0.0.1:9080 (via proxy-default / proxy-a)
#   - A TLS backend (self-signed) on 127.0.0.1:9443 (reached through CONNECT)
#   - A PAC file routing "a-*" → 8881, "b-*" → 8882, "fail-*" → failover,
#     "socks-*" → SOCKS5 1080, else → 8880
#
# Scenarios exercise end-to-end data delivery through the chain
#   client → kernel interception → totan → [HTTP-forward | CONNECT-tunnel |
#           SOCKS5] → backend
# and assert both (a) the expected upstream saw the request (log inspection)
# AND (b) the response body round-trips correctly (byte-level diff against
# known fixtures / echoes). This is stronger than the previous suite, which
# only verified the proxy logs and never opened a real TLS tunnel.
#
# Modes differ in how they intercept the client's traffic:
#
#   netfilter: iptables OUTPUT REDIRECT scoped to a dedicated uid. The client
#              (curl) runs as that uid on the host netns; totan listens on
#              127.0.0.1:3129 and reads SO_ORIGINAL_DST on accept.
#
#   ebpf:      pod netns with veth pair. totan attaches a tcx ingress program
#              on the host-side veth, sets up fwmark policy routing, and binds
#              an IP_TRANSPARENT listener that recovers the original dst via
#              getsockname(). bpf_sk_assign is tc-ingress-only at the kernel
#              level, which is why we hook veth-host ingress rather than an
#              uplink egress.
#
# Scenario layout (host→target mapping via curl --resolve, all in TEST-NET):
#   plain.test        → 192.0.2.10  :80   plain HTTP → proxy-default → backend
#   a-site.test       → 192.0.2.11  :443  HTTPS → proxy-a → TLS backend
#   b-site.test       → 192.0.2.12  :443  HTTPS → proxy-b → TLS backend
#   other.test        → 192.0.2.13  :443  HTTPS default PAC → proxy-default
#   192.0.2.14        →             :80   plain HTTP, PAC IP-route → proxy-a
#   fail-over.test    → 192.0.2.15  :443  HTTPS failover: dead:1 then :8880
#   socks-only.test   → 192.0.2.17  :443  HTTPS via SOCKS5 mock
#
# Known gap not tested here: HTTPS on non-443 ports. totan only runs SNI
# extraction when original_dest.port() == 443, so a CONNECT-style flow on
# e.g. :8443 falls through to the pingora plain-HTTP pipeline and breaks
# the TLS handshake. When that is fixed, add a "CONNECT other.test:8443"
# scenario (and widen the netfilter dport set accordingly).
#
# TEST-NET (192.0.2.0/24) is RFC 5737 documentation space: unreachable, so a
# successful response only proves totan actually proxied the flow.

set -euo pipefail

MODE="${1:-}"
case "$MODE" in
    netfilter|ebpf) ;;
    *) echo "usage: $0 <netfilter|ebpf>" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLKIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TOOLKIT_DIR/.." && pwd)"
TOTAN_BIN="${TOTAN_BIN:-$REPO_ROOT/target/release/totan}"

PAC_PATH="$SCRIPT_DIR/test.pac"
LOG_DIR="$(mktemp -d -t totan-e2e.XXXXXX)"
TOTAN_CFG="$LOG_DIR/totan.toml"
TOTAN_LOG="$LOG_DIR/totan.log"

PROXY_DEFAULT_LOG="$LOG_DIR/proxy-default.log"
PROXY_A_LOG="$LOG_DIR/proxy-a.log"
PROXY_B_LOG="$LOG_DIR/proxy-b.log"
SOCKS_LOG="$LOG_DIR/socks5.log"
BACKEND_HTTP_LOG="$LOG_DIR/backend-http.log"
BACKEND_TLS_LOG="$LOG_DIR/backend-tls.log"

# Ports (127.0.0.1-local)
PORT_PROXY_DEFAULT=8880
PORT_PROXY_A=8881
PORT_PROXY_B=8882
PORT_SOCKS=1080
PORT_BACKEND_HTTP=9080
PORT_BACKEND_TLS=9443

# netfilter-mode client uid
TEST_UID=9999
TEST_USER="totan-e2e-client"

# ebpf-mode isolation primitives
POD_NS="totan-e2e-pod"

PROXY_PIDS=()
BACKEND_PIDS=()
TOTAN_PID=""
TLS_CERT=""
TLS_KEY=""

# ─── cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
    set +e
    echo "[e2e] cleanup..."

    [[ -n "$TOTAN_PID" ]] && kill "$TOTAN_PID" 2>/dev/null
    for pid in "${PROXY_PIDS[@]}" "${BACKEND_PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null

    if [[ "$MODE" == "netfilter" ]]; then
        nft delete table ip totan_e2e 2>/dev/null
    else
        ip rule del fwmark 0x7474 lookup 100 2>/dev/null
        ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
        ip netns del "$POD_NS" 2>/dev/null
        ip link del veth-host 2>/dev/null
    fi

    if [[ "${_E2E_PASS:-0}" == "1" ]]; then
        rm -rf "$LOG_DIR"
    else
        echo "[e2e] logs preserved at $LOG_DIR"
        [[ -f "$TOTAN_LOG" ]] && {
            echo "──── totan log (last 100 lines) ────"
            tail -n 100 "$TOTAN_LOG"
        }
        for f in "$PROXY_DEFAULT_LOG" "$PROXY_A_LOG" "$PROXY_B_LOG" \
                 "$SOCKS_LOG" "$BACKEND_HTTP_LOG" "$BACKEND_TLS_LOG"; do
            [[ -f "$f" ]] && {
                echo "──── $(basename "$f") ────"
                cat "$f"
            }
        done
    fi
}
trap cleanup EXIT

# ─── prerequisites ────────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || { echo "must run as root (use sudo)" >&2; exit 1; }
[[ -x "$TOTAN_BIN" ]] || { echo "totan binary missing: $TOTAN_BIN" >&2; exit 1; }
command -v curl    >/dev/null || { echo "curl required"    >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl required" >&2; exit 1; }

# ─── generate self-signed TLS cert for the HTTPS backend ─────────────────────
# All test hostnames resolve via curl --resolve to RFC-5737 IPs, so the cert
# only needs to cover the *.test names curl will ask for. One SAN-listed cert
# serves every HTTPS scenario.
TLS_CERT="$LOG_DIR/backend.crt"
TLS_KEY="$LOG_DIR/backend.key"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$TLS_KEY" -out "$TLS_CERT" \
    -subj "/CN=totan-e2e-backend" \
    -addext "subjectAltName=DNS:a-site.test,DNS:b-site.test,DNS:other.test,DNS:fail-over.test,DNS:socks-only.test,IP:127.0.0.1" \
    2>/dev/null

# netfilter mode runs curl as an unprivileged uid; mkstemp defaults to 0700
# so the cert path would be unreadable. Open the directory tree (and the cert,
# not the key — the key only needs to be readable by the backend, which runs
# as root here) so `curl --cacert` works from every client context.
chmod 755 "$LOG_DIR"
chmod 644 "$TLS_CERT"

# ─── start backends ───────────────────────────────────────────────────────────
echo "[e2e] starting backend servers..."
start_backend() {
    local port="$1" id="$2" logfile="$3" tls="${4:-0}"
    local env_prefix=(env "PORT=$port" "BACKEND_ID=$id" "LOGFILE=$logfile")
    if [[ "$tls" == "1" ]]; then
        env_prefix+=("TLS_CERT=$TLS_CERT" "TLS_KEY=$TLS_KEY")
    fi
    "${env_prefix[@]}" python3 "$SCRIPT_DIR/mock-backend.py" &
    BACKEND_PIDS+=("$!")
}
start_backend "$PORT_BACKEND_HTTP" backend-http "$BACKEND_HTTP_LOG" 0
start_backend "$PORT_BACKEND_TLS"  backend-tls  "$BACKEND_TLS_LOG"  1

# ─── start mock proxies (forward mode with RESOLVE for RFC-5737 targets) ─────
echo "[e2e] starting mock proxies..."
# RESOLVE: every test hostname/IP combination redirected to a real backend.
# Forward-mode proxies will then tunnel CONNECT or re-issue HTTP to these.
RESOLVE_MAP="plain.test:80=127.0.0.1:$PORT_BACKEND_HTTP"
RESOLVE_MAP+=",a-site.test:443=127.0.0.1:$PORT_BACKEND_TLS"
RESOLVE_MAP+=",b-site.test:443=127.0.0.1:$PORT_BACKEND_TLS"
RESOLVE_MAP+=",other.test:443=127.0.0.1:$PORT_BACKEND_TLS"
RESOLVE_MAP+=",other.test:8443=127.0.0.1:$PORT_BACKEND_TLS"
RESOLVE_MAP+=",fail-over.test:443=127.0.0.1:$PORT_BACKEND_TLS"
RESOLVE_MAP+=",socks-only.test:443=127.0.0.1:$PORT_BACKEND_TLS"
RESOLVE_MAP+=",192.0.2.10:80=127.0.0.1:$PORT_BACKEND_HTTP"
RESOLVE_MAP+=",192.0.2.14:80=127.0.0.1:$PORT_BACKEND_HTTP"

start_proxy() {
    local port="$1" id="$2" logfile="$3"
    env PORT="$port" PROXY_ID="$id" LOGFILE="$logfile" \
        MODE=forward RESOLVE="$RESOLVE_MAP" \
        python3 "$SCRIPT_DIR/mock-proxy.py" &
    PROXY_PIDS+=("$!")
}
start_proxy "$PORT_PROXY_DEFAULT" proxy-default "$PROXY_DEFAULT_LOG"
start_proxy "$PORT_PROXY_A"       proxy-a       "$PROXY_A_LOG"
start_proxy "$PORT_PROXY_B"       proxy-b       "$PROXY_B_LOG"

env PORT="$PORT_SOCKS" PROXY_ID=socks5-mock LOGFILE="$SOCKS_LOG" \
    RESOLVE="$RESOLVE_MAP" \
    python3 "$SCRIPT_DIR/mock-socks5.py" &
PROXY_PIDS+=("$!")

# Wait briefly for listeners to bind, then verify each one is up. A silent
# bind failure here (e.g. port already held by a stale process) produces
# very confusing downstream errors — fail fast with a clear message.
sleep 0.5
for port in "$PORT_PROXY_DEFAULT" "$PORT_PROXY_A" "$PORT_PROXY_B" \
            "$PORT_SOCKS" "$PORT_BACKEND_HTTP" "$PORT_BACKEND_TLS"; do
    if ! ss -tlnH "sport = :$port" | grep -q "$port"; then
        echo "[e2e] listener on :$port failed to bind" >&2
        exit 1
    fi
done

# ─── generate totan config ────────────────────────────────────────────────────
src_cfg="$TOOLKIT_DIR/totan.${MODE}-ci.toml"
sed "s|__PAC_PATH__|$PAC_PATH|" "$src_cfg" > "$TOTAN_CFG"
echo "[e2e] using config $TOTAN_CFG (pac=$PAC_PATH)"

# ─── mode-specific interception setup ────────────────────────────────────────
if [[ "$MODE" == "netfilter" ]]; then
    echo "[e2e] netfilter: creating test uid $TEST_UID ($TEST_USER)..."
    if ! id -u "$TEST_USER" >/dev/null 2>&1; then
        useradd -u "$TEST_UID" -M -s /bin/bash "$TEST_USER" 2>/dev/null \
            || useradd -u "$TEST_UID" -M "$TEST_USER"
    fi

    echo "[e2e] netfilter: installing nftables redirect for uid $TEST_UID..."
    nft add table ip totan_e2e
    nft add chain ip totan_e2e output '{ type nat hook output priority -100; policy accept; }'
    nft add rule ip totan_e2e output "meta skuid $TEST_UID tcp dport { 80, 443 } redirect to :3129"

    CURL_PREFIX=(sudo -u "$TEST_USER" --preserve-env=PATH)

else  # ebpf
    echo "[e2e] ebpf: checking kernel version..."
    KVER=$(uname -r)
    echo "[e2e] kernel $KVER (need ≥ 6.6 for tcx)"

    echo "[e2e] ebpf: setting up pod netns..."
    sysctl -qw net.ipv4.conf.all.rp_filter=0

    ip netns add "$POD_NS"
    ip link add veth-host type veth peer name veth-pod
    ip link set veth-pod netns "$POD_NS"
    ip link set veth-host up
    ip addr add 10.100.0.1/24 dev veth-host
    sysctl -qw net.ipv4.conf.veth-host.rp_filter=0 2>/dev/null || true

    ip netns exec "$POD_NS" ip link set lo up
    ip netns exec "$POD_NS" ip link set veth-pod up
    ip netns exec "$POD_NS" ip addr add 10.100.0.2/24 dev veth-pod
    ip netns exec "$POD_NS" ip route add default via 10.100.0.1

    CURL_PREFIX=(ip netns exec "$POD_NS")
fi

# ─── start totan ──────────────────────────────────────────────────────────────
echo "[e2e] starting totan ($MODE mode)..."
"$TOTAN_BIN" --config "$TOTAN_CFG" >"$TOTAN_LOG" 2>&1 &
TOTAN_PID=$!

echo "[e2e] waiting for totan listener..."
for i in $(seq 1 30); do
    if ss -tlnH "sport = :3129" | grep -q "3129"; then
        echo "[e2e] totan ready after $((i*5)) × 100ms"
        break
    fi
    sleep 0.1
    if [[ $i -eq 30 ]]; then
        echo "[e2e] totan failed to bind :3129 — see $TOTAN_LOG" >&2
        exit 1
    fi
done

[[ "$MODE" == "ebpf" ]] && sleep 0.5

# ─── scenarios ────────────────────────────────────────────────────────────────
pass=0
fail=0

assert_log_contains() {
    local logfile="$1" pattern="$2" scenario="$3"
    if grep -qF "$pattern" "$logfile"; then
        echo "  ✓ $scenario: found '$pattern' in $(basename "$logfile")"
        pass=$((pass + 1))
    else
        echo "  ✗ $scenario: '$pattern' NOT in $(basename "$logfile")" >&2
        echo "    $(basename "$logfile") contents:" >&2
        sed 's/^/      /' "$logfile" >&2 || true
        fail=$((fail + 1))
    fi
}

assert_log_empty() {
    local logfile="$1" scenario="$2"
    if [[ ! -s "$logfile" ]]; then
        echo "  ✓ $scenario: $(basename "$logfile") is empty (as expected)"
        pass=$((pass + 1))
    else
        echo "  ✗ $scenario: unexpected entries in $(basename "$logfile")" >&2
        sed 's/^/      /' "$logfile" >&2
        fail=$((fail + 1))
    fi
}

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  ✓ $label: got expected value"
        pass=$((pass + 1))
    else
        echo "  ✗ $label: expected $(printf %q "$expected"), got $(printf %q "$actual")" >&2
        fail=$((fail + 1))
    fi
}

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "  ✓ $label: output contains '$needle'"
        pass=$((pass + 1))
    else
        echo "  ✗ $label: expected output to contain '$needle'" >&2
        echo "    got: $(printf %q "$haystack")" >&2
        fail=$((fail + 1))
    fi
}

# --cacert points at our self-signed cert so TLS validation is real: if the
# cert didn't round-trip correctly (eg. SNI got dropped and the server
# returned a default cert), curl would fail — which is exactly what we want.
CURL_BASE=(curl --silent --show-error --max-time 10 --noproxy '*' --cacert "$TLS_CERT")

run_curl() {
    # Deliberately swallow non-zero exit codes: when an assertion fails we
    # want the *captured body* (or curl's error text) reported by the
    # assertion, not an abrupt `set -e` abort that hides the real cause.
    "${CURL_PREFIX[@]}" "${CURL_BASE[@]}" "$@" 2>&1 || true
}

echo
echo "── scenario 1: plain HTTP → proxy-default → backend-http ───────────────"
# Fully end-to-end: absolute-form request to proxy (RFC 7230 §5.3.2) and real
# round-trip through the backend, whose "/" endpoint returns "backend:<id>".
body=$(run_curl --resolve "plain.test:80:192.0.2.10" 'http://plain.test/')
assert_log_contains "$PROXY_DEFAULT_LOG" "GET http://plain.test/" "plain-http: absolute-form URI to proxy"
assert_log_contains "$BACKEND_HTTP_LOG"  "GET / host=plain.test"  "plain-http: backend saw right Host"
assert_eq           "plain-http: body round-trip"                   "backend:backend-http" "$body"

echo
echo "── scenario 2: plain HTTP IP-only routing → proxy-a ────────────────────"
# No SNI, no Host hostname — PAC must route by the literal IP "192.0.2.14".
body=$(run_curl "http://192.0.2.14/")
assert_log_contains "$PROXY_A_LOG" "GET http://192.0.2.14/" "ip-route: proxy-a got the request"
assert_log_empty    "$PROXY_B_LOG"                           "ip-route: proxy-b untouched"
assert_eq           "ip-route: body round-trip"              "backend:backend-http" "$body"

echo
echo "── scenario 3: HTTP POST /echo through proxy-default ───────────────────"
# Exercise request bodies through the forward proxy — the previous suite had
# no coverage of request-body handling.
payload=$(printf 'the quick brown fox jumps over the lazy dog')
body=$(run_curl --resolve 'plain.test:80:192.0.2.10' \
       -X POST -H 'Content-Type: text/plain' --data-binary "$payload" \
       'http://plain.test/echo')
assert_log_contains "$PROXY_DEFAULT_LOG" "POST http://plain.test/echo" "post: proxy logged POST"
assert_log_contains "$BACKEND_HTTP_LOG"  "POST /echo host=plain.test"  "post: backend logged POST"
assert_eq           "post: body echoed unchanged" "$payload" "$body"

echo
echo "── scenario 4: HTTPS a-site.test → PAC routes to proxy-a → TLS backend ─"
# The proxy MUST actually tunnel the CONNECT so the client's TLS handshake
# completes against our real backend — the earlier stub-mode suite never
# tested this beyond "did the CONNECT line show up in the log?".
body=$(run_curl --resolve 'a-site.test:443:192.0.2.11' 'https://a-site.test/')
assert_log_contains "$PROXY_A_LOG"       "CONNECT a-site.test:443" "https-a: proxy-a saw CONNECT"
assert_log_empty    "$PROXY_B_LOG"                                 "https-a: proxy-b untouched"
assert_log_contains "$BACKEND_TLS_LOG"   "GET / host=a-site.test"  "https-a: backend saw decrypted request"
assert_eq           "https-a: body round-trip" "backend:backend-tls" "$body"

echo
echo "── scenario 5: HTTPS b-site.test → PAC routes to proxy-b → TLS backend ─"
body=$(run_curl --resolve 'b-site.test:443:192.0.2.12' 'https://b-site.test/')
assert_log_contains "$PROXY_B_LOG"     "CONNECT b-site.test:443" "https-b: proxy-b saw CONNECT"
assert_log_contains "$BACKEND_TLS_LOG" "GET / host=b-site.test"  "https-b: backend saw decrypted request"
assert_eq           "https-b: body round-trip" "backend:backend-tls" "$body"

echo
echo "── scenario 6: HTTPS default PAC → proxy-default → TLS backend ─────────"
body=$(run_curl --resolve 'other.test:443:192.0.2.13' 'https://other.test/')
assert_log_contains "$PROXY_DEFAULT_LOG" "CONNECT other.test:443" "https-default: proxy-default saw CONNECT"
assert_eq           "https-default: body round-trip" "backend:backend-tls" "$body"

echo
echo "── scenario 7: HTTPS large body (1 MiB) through the CONNECT tunnel ─────"
# Validates bidirectional streaming doesn't truncate or corrupt bulk transfers.
# Hashing sidesteps printing 1 MiB to stdout on assertion failure.
expected_hash=$(python3 -c "import hashlib, sys; sys.stdout.write(hashlib.sha256(b'A'*1048576).hexdigest())")
actual_hash=$(run_curl --resolve 'a-site.test:443:192.0.2.11' \
              'https://a-site.test/bytes/1048576' | sha256sum | awk '{print $1}')
assert_eq "large-body: 1 MiB sha256 matches" "$expected_hash" "$actual_hash"

echo
echo "── scenario 8: HTTPS PAC failover — first proxy dead, second works ─────"
# PAC returns "PROXY 127.0.0.1:1; PROXY 127.0.0.1:8880": :1 always refuses,
# so totan must walk to the second entry and deliver through it.
body=$(run_curl --resolve 'fail-over.test:443:192.0.2.15' 'https://fail-over.test/')
assert_log_contains "$PROXY_DEFAULT_LOG" "CONNECT fail-over.test:443" "failover: recovered via proxy-default"
assert_eq           "failover: body round-trip" "backend:backend-tls" "$body"

echo
echo "── scenario 9: HTTPS via SOCKS5 mock proxy ─────────────────────────────"
# PAC returns SOCKS5 127.0.0.1:1080 — validates totan's SOCKS5 client.
body=$(run_curl --resolve 'socks-only.test:443:192.0.2.17' 'https://socks-only.test/')
assert_log_contains "$SOCKS_LOG"       "CONNECT socks-only.test:443" "socks5: mock handshake succeeded"
assert_log_contains "$BACKEND_TLS_LOG" "GET / host=socks-only.test"  "socks5: backend saw decrypted request"
assert_eq           "socks5: body round-trip" "backend:backend-tls" "$body"

echo
echo "── scenario 10: 20 concurrent HTTPS requests ──────────────────────────"
# Catches concurrency regressions (connection-manager races, SNI buffer
# reuse, PAC cache contention) that single-request tests miss by design.
# We fan out N requests with xargs -P and count how many returned the
# expected body. The pipeline tolerates per-request failures (we *want* the
# count, not a hard exit) and the chmod 644 on the conc_script ensures the
# unprivileged netfilter test uid can exec it.
conc_n=20
conc_expected="backend:backend-tls"
conc_script="$LOG_DIR/conc.sh"
cat > "$conc_script" <<CONCEOF
#!/usr/bin/env bash
out=\$(curl --silent --show-error --max-time 15 --noproxy '*' \\
           --cacert "$TLS_CERT" \\
           --resolve 'other.test:443:192.0.2.13' \\
           'https://other.test/' 2>&1)
[[ "\$out" == "$conc_expected" ]] && echo OK || echo "FAIL: \$out"
CONCEOF
chmod 755 "$conc_script"
conc_out=$("${CURL_PREFIX[@]}" bash -c \
    "seq 1 $conc_n | xargs -I{} -P $conc_n $conc_script" 2>&1 || true)
oks=$(printf '%s\n' "$conc_out" | grep -c '^OK$' || true)
if [[ "$oks" != "$conc_n" ]]; then
    echo "    sample failures:" >&2
    printf '%s\n' "$conc_out" | grep -v '^OK$' | head -3 | sed 's/^/      /' >&2
fi
assert_eq "concurrent: ${conc_n}/${conc_n} requests succeeded" "$conc_n" "$oks"

# ─── verdict ──────────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════════════"
echo "  mode: $MODE    passed: $pass    failed: $fail"
echo "═══════════════════════════════════════════════════════════════════════"

if [[ "$fail" -gt 0 ]]; then
    exit 1
fi

_E2E_PASS=1
echo "[e2e] PASS"
