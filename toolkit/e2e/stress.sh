#!/usr/bin/env bash
# Deterministic connection-churn test for totan's eBPF interception path.
#
# Every request uses a fresh HTTP/1.1 TCP connection. The test validates the
# status and body of every response for IPv4, IPv6, and mixed-family traffic.
# Observed throughput is printed for diagnostics only; shared-runner speed is
# deliberately not a pass/fail criterion.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLKIT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TOOLKIT_DIR/.." && pwd)"
TOTAN_BIN="${TOTAN_BIN:-$REPO_ROOT/target/release/totan}"
CHURN_CLIENT="$SCRIPT_DIR/churn-client.py"

LOG_DIR="$(mktemp -d -t totan-churn.XXXXXX)"
TOTAN_CFG="$LOG_DIR/totan.toml"
TOTAN_LOG="$LOG_DIR/totan.log"
PROXY_LOG="$LOG_DIR/proxy.log"

POD_NS="totan-churn-pod"
PREEXISTING_V4_LOCAL_ROUTE="$(ip route show table 100 type local 0.0.0.0/0 2>/dev/null || true)"
PREEXISTING_V6_LOCAL_ROUTE="$(ip -6 route show table 100 type local ::/0 2>/dev/null || true)"
ORIGINAL_RP_FILTER="$(sysctl -n net.ipv4.conf.all.rp_filter)"
ORIGINAL_TCP_TW_REUSE="$(sysctl -n net.ipv4.tcp_tw_reuse)"

PROXY_PID=""
TOTAN_PID=""
pass=0
fail=0

cleanup() {
    set +e
    echo "[churn] cleanup..."
    if [[ "${_CHURN_PASS:-0}" != "1" ]]; then
        echo "──── totan log (last 100 lines) ────"
        tail -n 100 "$TOTAN_LOG" 2>/dev/null || true
        echo "──── proxy log ────"
        cat "$PROXY_LOG" 2>/dev/null || true
        echo "──── network state ────"
        ip rule show 2>/dev/null || true
        ip -6 rule show 2>/dev/null || true
        ip route show table 100 2>/dev/null || true
        ip -6 route show table 100 2>/dev/null || true
        ss -s 2>/dev/null || true
    fi

    [[ -n "$TOTAN_PID" ]] && kill "$TOTAN_PID" 2>/dev/null
    [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null
    wait 2>/dev/null

    [[ -z "$PREEXISTING_V4_LOCAL_ROUTE" ]] && \
        ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
    [[ -z "$PREEXISTING_V6_LOCAL_ROUTE" ]] && \
        ip -6 route del local ::/0 dev lo table 100 2>/dev/null
    ip netns del "$POD_NS" 2>/dev/null
    ip link del veth-ch-host 2>/dev/null
    sysctl -qw "net.ipv4.conf.all.rp_filter=$ORIGINAL_RP_FILTER"
    sysctl -qw "net.ipv4.tcp_tw_reuse=$ORIGINAL_TCP_TW_REUSE"

    if [[ "${_CHURN_PASS:-0}" == "1" ]]; then
        rm -rf "$LOG_DIR"
    else
        echo "[churn] logs preserved at $LOG_DIR"
    fi
}
trap cleanup EXIT

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root (use sudo)" >&2; exit 1; }
[[ -x "$TOTAN_BIN" ]] || { echo "totan binary missing: $TOTAN_BIN" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

echo "[churn] starting mock proxy on :8880..."
PORT=8880 PROXY_ID=stress-proxy LOGFILE="$PROXY_LOG" \
    python3 "$SCRIPT_DIR/mock-proxy.py" &
PROXY_PID=$!
sleep 0.3
ss -tlnH "sport = :8880" | grep -q "8880" \
    || { echo "[churn] proxy failed to bind :8880" >&2; exit 1; }

cat > "$TOTAN_CFG" <<TOML
listen_port = 3129
default_proxy = "http://127.0.0.1:8880"

[logging]
level = "info"
format = "text"

[timeouts]
upstream_connect_ms = 5000
client_idle_secs = 30

[ebpf]
ingress_interfaces = ["veth-ch-host"]
tproxy_port = 3129
fwmark = 0x7474
TOML

echo "[churn] setting up pod netns..."
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.tcp_tw_reuse=1

ip netns add "$POD_NS"
ip link add veth-ch-host type veth peer name veth-ch-pod
ip link set veth-ch-pod netns "$POD_NS"
ip link set veth-ch-host up
ip addr add 10.101.0.1/24 dev veth-ch-host
ip -6 addr add fd00:101::1/64 dev veth-ch-host nodad
sysctl -qw net.ipv4.conf.veth-ch-host.rp_filter=0 2>/dev/null || true

ip netns exec "$POD_NS" ip link set lo up
ip netns exec "$POD_NS" ip link set veth-ch-pod up
ip netns exec "$POD_NS" ip addr add 10.101.0.2/24 dev veth-ch-pod
ip netns exec "$POD_NS" ip route add default via 10.101.0.1
ip netns exec "$POD_NS" ip -6 addr add fd00:101::2/64 dev veth-ch-pod nodad
ip netns exec "$POD_NS" ip -6 route add default via fd00:101::1
ip netns exec "$POD_NS" sysctl -qw net.ipv4.tcp_tw_reuse=1
ip netns exec "$POD_NS" sysctl -qw net.ipv4.tcp_fin_timeout=5
ip netns exec "$POD_NS" sysctl -qw net.ipv4.ip_local_port_range="1024 65535"

echo "[churn] starting totan..."
"$TOTAN_BIN" --config "$TOTAN_CFG" >"$TOTAN_LOG" 2>&1 &
TOTAN_PID=$!
for i in $(seq 1 30); do
    ss -tlnH "sport = :3129" | grep -q "3129" && break
    sleep 0.1
    [[ $i -eq 30 ]] && { echo "[churn] totan failed to start" >&2; exit 1; }
done
sleep 0.5

run_phase() {
    local label="$1" requests="$2" concurrency="$3"
    shift 3
    echo
    echo "── $label: requests=$requests concurrency=$concurrency targets=$* ──"
    if ip netns exec "$POD_NS" python3 "$CHURN_CLIENT" \
        --requests "$requests" --concurrency "$concurrency" "$@"; then
        pass=$((pass + 1))
        echo "  ✓ $label"
    else
        fail=$((fail + 1))
        echo "  ✗ $label" >&2
    fi
}

run_phase "warmup" 20 4 ipv4 ipv6
run_phase "ipv4-churn" 200 10 ipv4
run_phase "ipv6-churn" 200 10 ipv6
run_phase "mixed-sustained" 400 20 ipv4 ipv6
run_phase "mixed-burst" 200 40 ipv4 ipv6

echo
echo "═══════════════════════════════════════════════════════════════════════"
echo "  connection churn    passed: $pass    failed: $fail"
echo "═══════════════════════════════════════════════════════════════════════"

[[ "$fail" -gt 0 ]] && exit 1

_CHURN_PASS=1
echo "[churn] PASS"
