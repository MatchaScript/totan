#!/usr/bin/env bash
# Unified e2e runner for totan.
#
# Usage: run.sh <netfilter|ebpf>
#
# Both modes share:
#   - Three mock proxies on 127.0.0.1:8880 / :8881 / :8882
#   - A PAC file routing "a-*" → 8881, "b-*" → 8882, else → 8880
#   - Scenario assertions that inspect each proxy's request log
#
# Modes differ in how they intercept the client's traffic:
#
#   netfilter: iptables OUTPUT REDIRECT scoped to a dedicated uid. The client
#              (curl) runs as that uid on the host netns; totan listens on
#              127.0.0.1:3129 and reads SO_ORIGINAL_DST on accept.
#
#   ebpf:      pod netns with veth pair. totan attaches a tcx ingress program
#              on the host-side veth (the first tc hook pod-originated packets
#              hit on the host), sets up fwmark policy routing, and binds an
#              IP_TRANSPARENT listener that recovers the original dst via
#              getsockname(). `bpf_sk_assign` is tc-ingress-only at the kernel
#              level, which is why we hook veth-host ingress rather than an
#              uplink egress.
#
# Scenario layout (host→target mapping via curl --resolve, all in TEST-NET):
#   plain.test       → 192.0.2.10  port 80  (plain HTTP, default proxy)
#   a-site.test      → 192.0.2.11  port 443 (HTTPS, PAC routes to proxy-a)
#   b-site.test      → 192.0.2.12  port 443 (HTTPS, PAC routes to proxy-b)
#   other.test       → 192.0.2.13  port 443 (HTTPS, PAC default → proxy-default)
#
# TEST-NET (192.0.2.0/24) is RFC 5737 documentation space: unreachable, so a
# successful response proves totan actually proxied the flow.

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

# netfilter-mode client uid
TEST_UID=9999
TEST_USER="totan-e2e-client"

# ebpf-mode isolation primitives
POD_NS="totan-e2e-pod"

PROXY_PIDS=()
TOTAN_PID=""

# ─── cleanup ─────────────────────────────────────────────────────────────────
cleanup() {
    set +e
    echo "[e2e] cleanup..."

    [[ -n "$TOTAN_PID" ]] && kill "$TOTAN_PID" 2>/dev/null
    for pid in "${PROXY_PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null

    if [[ "$MODE" == "netfilter" ]]; then
        nft delete table ip totan_e2e 2>/dev/null
    else
        ip rule del fwmark 0x7474 lookup 100 2>/dev/null
        ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
        ip netns del "$POD_NS" 2>/dev/null
        # Deleting one end of the pair removes both.
        ip link del veth-host 2>/dev/null
    fi

    # Preserve log directory on failure; remove on success.
    if [[ "${_E2E_PASS:-0}" == "1" ]]; then
        rm -rf "$LOG_DIR"
    else
        echo "[e2e] logs preserved at $LOG_DIR"
        [[ -f "$TOTAN_LOG" ]] && {
            echo "──── totan log (last 100 lines) ────"
            tail -n 100 "$TOTAN_LOG"
        }
        for f in "$PROXY_DEFAULT_LOG" "$PROXY_A_LOG" "$PROXY_B_LOG"; do
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
command -v curl >/dev/null || { echo "curl required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

# ─── start mock proxies ───────────────────────────────────────────────────────
echo "[e2e] starting mock proxies..."
start_proxy() {
    local port="$1" id="$2" logfile="$3"
    PORT="$port" PROXY_ID="$id" LOGFILE="$logfile" \
        python3 "$SCRIPT_DIR/mock-proxy.py" &
    PROXY_PIDS+=("$!")
}
start_proxy 8880 proxy-default "$PROXY_DEFAULT_LOG"
start_proxy 8881 proxy-a       "$PROXY_A_LOG"
start_proxy 8882 proxy-b       "$PROXY_B_LOG"
sleep 0.5

for port in 8880 8881 8882; do
    if ! ss -tlnH "sport = :$port" | grep -q "$port"; then
        echo "[e2e] mock proxy on :$port failed to bind" >&2
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

    # Run curl inside the host netns but as the scoped uid.
    CURL_PREFIX=(sudo -u "$TEST_USER" --preserve-env=PATH)

else  # ebpf
    echo "[e2e] ebpf: checking kernel version..."
    KVER=$(uname -r)
    echo "[e2e] kernel $KVER (need ≥ 6.6 for tcx)"

    echo "[e2e] ebpf: setting up pod netns..."
    # The fwmark-tagged packet enters local delivery via dev lo even though it
    # arrived on veth-host, so rp_filter could reject the src=10.100.0.2
    # reverse-path check. Loosen on all + the specific ingress device.
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

    # totan installs `ip rule fwmark 0x7474 lookup 100` + the local-delivery
    # route in table 100 automatically on startup; no manual routing needed.

    CURL_PREFIX=(ip netns exec "$POD_NS")
fi

# ─── start totan ──────────────────────────────────────────────────────────────
echo "[e2e] starting totan ($MODE mode)..."
"$TOTAN_BIN" --config "$TOTAN_CFG" >"$TOTAN_LOG" 2>&1 &
TOTAN_PID=$!

# Wait for totan's listener to be up. For netfilter, totan binds 0.0.0.0:3129;
# for ebpf, 127.0.0.1:3129 with IP_TRANSPARENT.
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

# Give aya a moment to finish attaching the tcx program.
[[ "$MODE" == "ebpf" ]] && sleep 0.5

# ─── scenarios ────────────────────────────────────────────────────────────────
# Each scenario sends one curl and asserts which proxy received it, based on
# the log file contents. Plain-HTTP responses also check the response body
# contains the proxy's identifier.
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

run_curl() {
    # curl may fail (HTTPS has no real TLS backend); we only care that the
    # request reached the proxy, which we verify via the log file.
    "${CURL_PREFIX[@]}" curl \
        --silent --show-error --max-time 5 --noproxy '*' \
        "$@" 2>&1 || true
}

echo
echo "── scenario 1: plain HTTP → default proxy ──────────────────────────────"
# PAC resolution uses the original dst IP (no SNI / Host inspection at that
# stage), so the IP falls through to the PAC default → proxy-default (8880).
# When forwarding upstream, totan rewrites the request-URI from the Host
# header per RFC 7230, so the proxy sees the hostname form.
body=$(run_curl --resolve 'plain.test:80:192.0.2.10' 'http://plain.test/')
echo "  body: $body"
assert_log_contains "$PROXY_DEFAULT_LOG" "GET http://plain.test/" "plain-http"
if [[ "$body" == *"proxy-default:"* ]]; then
    echo "  ✓ plain-http: response body contains proxy-default identifier"
    pass=$((pass + 1))
else
    echo "  ✗ plain-http: response body missing 'proxy-default:' — got: $body" >&2
    fail=$((fail + 1))
fi

echo
echo "── scenario 2: HTTPS a-site.test → PAC routes to proxy-a ───────────────"
# For HTTPS, totan extracts SNI "a-site.test" → PAC matches "a-*" → proxy-a.
run_curl --resolve 'a-site.test:443:192.0.2.11' -k 'https://a-site.test/' >/dev/null
assert_log_contains "$PROXY_A_LOG"       "CONNECT a-site.test:443" "pac-route-a"
assert_log_empty    "$PROXY_B_LOG"                                 "pac-route-a (b-proxy untouched)"

echo
echo "── scenario 3: HTTPS b-site.test → PAC routes to proxy-b ───────────────"
run_curl --resolve 'b-site.test:443:192.0.2.12' -k 'https://b-site.test/' >/dev/null
assert_log_contains "$PROXY_B_LOG" "CONNECT b-site.test:443" "pac-route-b"

echo
echo "── scenario 4: HTTPS other.test → PAC default → proxy-default ─────────"
run_curl --resolve 'other.test:443:192.0.2.13' -k 'https://other.test/' >/dev/null
assert_log_contains "$PROXY_DEFAULT_LOG" "CONNECT other.test:443" "pac-default-https"

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
