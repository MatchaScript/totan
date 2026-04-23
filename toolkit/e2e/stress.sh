#!/usr/bin/env bash
# Stress and performance test for totan using Apache Bench.
#
# Usage: stress.sh <netfilter|ebpf>
#
# Sends ab traffic through totan's transparent interception and validates:
#   - Failed request rate ≤ MAX_FAIL_PCT (default 1%)
#   - Requests per second ≥ MIN_RPS     (default 20 req/s)
#
# Uses a single mock proxy (no PAC) to keep the focus on totan's raw
# connection-handling throughput rather than PAC evaluation overhead.
#
# Interception setup mirrors toolkit/e2e/run.sh:
#   netfilter: nftables OUTPUT redirect scoped to uid $TEST_UID; ab runs as
#              that uid so its TCP traffic to RFC-5737 IPs is intercepted.
#   ebpf:      veth pair + pod netns; ab runs inside the pod netns.
#
# The target IP (192.0.2.10) is RFC 5737 documentation space — permanently
# unreachable — so any successful ab response proves totan proxied the flow.

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

LOG_DIR="$(mktemp -d -t totan-stress.XXXXXX)"
TOTAN_CFG="$LOG_DIR/totan.toml"
TOTAN_LOG="$LOG_DIR/totan.log"
PROXY_LOG="$LOG_DIR/proxy.log"

# Separate uid/user from run.sh (9999) so the two can coexist on the same host.
TEST_UID=9998
TEST_USER="totan-stress-client"
POD_NS="totan-stress-pod"

PROXY_PID=""
TOTAN_PID=""

# ── thresholds ────────────────────────────────────────────────────────────────
MIN_RPS="${TOTAN_STRESS_MIN_RPS:-20}"        # req/s — conservative for shared CI
MAX_FAIL_PCT="${TOTAN_STRESS_MAX_FAIL_PCT:-1}" # % of requests that may fail

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    set +e
    echo "[stress] cleanup..."
    [[ -n "$TOTAN_PID" ]] && kill "$TOTAN_PID" 2>/dev/null
    [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null
    wait 2>/dev/null

    if [[ "$MODE" == "netfilter" ]]; then
        nft delete table ip totan_stress 2>/dev/null
    else
        ip rule del fwmark 0x7474 lookup 100 2>/dev/null
        ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
        ip netns del "$POD_NS" 2>/dev/null
        ip link del veth-stress-host 2>/dev/null
    fi

    if [[ "${_STRESS_PASS:-0}" == "1" ]]; then
        rm -rf "$LOG_DIR"
    else
        echo "[stress] logs preserved at $LOG_DIR"
        [[ -f "$TOTAN_LOG" ]] && {
            echo "──── totan log (last 50 lines) ────"
            tail -n 50 "$TOTAN_LOG"
        }
    fi
}
trap cleanup EXIT

# ── prerequisites ─────────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || { echo "must run as root (use sudo)" >&2; exit 1; }
[[ -x "$TOTAN_BIN" ]] || { echo "totan binary missing: $TOTAN_BIN" >&2; exit 1; }
command -v ab      >/dev/null || { echo "ab (apache2-utils) required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

# ── mock proxy ────────────────────────────────────────────────────────────────
echo "[stress] starting mock proxy on :8880..."
PORT=8880 PROXY_ID=stress-proxy LOGFILE="$PROXY_LOG" \
    python3 "$SCRIPT_DIR/mock-proxy.py" &
PROXY_PID=$!
sleep 0.3
ss -tlnH "sport = :8880" | grep -q "8880" \
    || { echo "[stress] proxy failed to bind :8880" >&2; exit 1; }

# ── totan config (no PAC; all traffic → mock proxy) ───────────────────────────
cat > "$TOTAN_CFG" <<TOML
listen_port       = 3129
default_proxy     = "http://127.0.0.1:8880"
interception_mode = "$MODE"

[logging]
level  = "warn"
format = "text"

[timeouts]
upstream_connect_ms = 5000
client_idle_secs    = 30
TOML

if [[ "$MODE" == "ebpf" ]]; then
    printf '[ebpf]\ningress_interface = "veth-stress-host"\n' >> "$TOTAN_CFG"
fi

# ── interception setup ────────────────────────────────────────────────────────
if [[ "$MODE" == "netfilter" ]]; then
    echo "[stress] netfilter: creating test uid $TEST_UID ($TEST_USER)..."
    if ! id -u "$TEST_USER" >/dev/null 2>&1; then
        useradd -u "$TEST_UID" -M -s /bin/bash "$TEST_USER" 2>/dev/null \
            || useradd -u "$TEST_UID" -M "$TEST_USER"
    fi
    nft add table ip totan_stress
    nft add chain ip totan_stress output '{ type nat hook output priority -100; policy accept; }'
    nft add rule ip totan_stress output "meta skuid $TEST_UID tcp dport { 80 } redirect to :3129"
    AB_PREFIX=(sudo -u "$TEST_USER" --preserve-env=PATH)

else  # ebpf
    echo "[stress] ebpf: setting up pod netns..."
    sysctl -qw net.ipv4.conf.all.rp_filter=0

    ip netns add "$POD_NS"
    ip link add veth-stress-host type veth peer name veth-stress-pod
    ip link set veth-stress-pod netns "$POD_NS"
    ip link set veth-stress-host up
    ip addr add 10.101.0.1/24 dev veth-stress-host
    sysctl -qw net.ipv4.conf.veth-stress-host.rp_filter=0 2>/dev/null || true

    ip netns exec "$POD_NS" ip link set lo up
    ip netns exec "$POD_NS" ip link set veth-stress-pod up
    ip netns exec "$POD_NS" ip addr add 10.101.0.2/24 dev veth-stress-pod
    ip netns exec "$POD_NS" ip route add default via 10.101.0.1

    AB_PREFIX=(ip netns exec "$POD_NS")
fi

# ── start totan ───────────────────────────────────────────────────────────────
echo "[stress] starting totan ($MODE)..."
"$TOTAN_BIN" --config "$TOTAN_CFG" >"$TOTAN_LOG" 2>&1 &
TOTAN_PID=$!
for i in $(seq 1 30); do
    ss -tlnH "sport = :3129" | grep -q "3129" && break
    sleep 0.1
    [[ $i -eq 30 ]] && { echo "[stress] totan failed to start" >&2; exit 1; }
done
[[ "$MODE" == "ebpf" ]] && sleep 0.5

TARGET="http://192.0.2.10/"   # RFC 5737: unreachable without totan interception
pass=0
fail=0

# ── warm-up ───────────────────────────────────────────────────────────────────
echo "[stress] warming up..."
"${AB_PREFIX[@]}" ab -n 30 -c 3 -s 10 "$TARGET" >/dev/null 2>&1 || true
sleep 0.2

# ── benchmark runner ──────────────────────────────────────────────────────────
run_bench() {
    local label="$1" n="$2" c="$3"
    local out="$LOG_DIR/ab-${label}.txt"

    echo
    echo "── $label: $n requests, concurrency=$c ─────────────────────────────"

    # ab exits non-zero on failures; capture output regardless.
    "${AB_PREFIX[@]}" ab -n "$n" -c "$c" -s 10 "$TARGET" >"$out" 2>&1 || true

    # Print the summary block (from "Server Software:" onward).
    awk '/^Server Software:/,0' "$out" || cat "$out"
    echo

    local failed complete rps rps_int fail_pct
    failed=$(awk  '/^Failed requests:/{print $3}'     "$out" 2>/dev/null || echo "?")
    complete=$(awk '/^Complete requests:/{print $3}'  "$out" 2>/dev/null || echo "0")
    rps=$(awk     '/^Requests per second:/{print $4}' "$out" 2>/dev/null || echo "0")
    rps_int="${rps%%.*}"

    # ── failure-rate assertion ────────────────────────────────────────────────
    fail_pct=0
    if [[ "$failed" =~ ^[0-9]+$ && "$complete" =~ ^[0-9]+$ && "$complete" -gt 0 ]]; then
        fail_pct=$(( failed * 100 / complete ))
    fi

    if [[ "$fail_pct" -le "$MAX_FAIL_PCT" ]]; then
        echo "  ✓ $label: failed=$failed (${fail_pct}%) ≤ ${MAX_FAIL_PCT}% threshold"
        pass=$((pass + 1))
    else
        echo "  ✗ $label: failed=$failed (${fail_pct}%) > ${MAX_FAIL_PCT}% threshold" >&2
        fail=$((fail + 1))
    fi

    # ── throughput assertion ──────────────────────────────────────────────────
    if [[ "$rps_int" =~ ^[0-9]+$ && "$rps_int" -ge "$MIN_RPS" ]]; then
        echo "  ✓ $label: rps=${rps} ≥ ${MIN_RPS} req/s threshold"
        pass=$((pass + 1))
    else
        echo "  ✗ $label: rps=${rps} < ${MIN_RPS} req/s threshold" >&2
        fail=$((fail + 1))
    fi
}

# ── benchmarks ────────────────────────────────────────────────────────────────
run_bench "moderate"   500  10   # baseline throughput
run_bench "burst"     1000  50   # high concurrency spike
run_bench "sustained" 2000  20   # sustained mixed load

# ── verdict ───────────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════════════"
echo "  mode: $MODE    passed: $pass    failed: $fail"
echo "═══════════════════════════════════════════════════════════════════════"

[[ "$fail" -gt 0 ]] && exit 1

_STRESS_PASS=1
echo "[stress] PASS"
