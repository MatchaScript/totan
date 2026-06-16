#!/usr/bin/env bash
# Proves the Cilium-style self-exclusion end-to-end:
#   1. host-hooks-only mode (empty `ingress_interfaces`) starts and intercepts.
#   2. totan running *inside* a hooked cgroup slice does NOT self-loop on its
#      own upstream connects — connect4 skips sockets carrying DEFAULT_SELF_MARK.
#
# The discriminator is a DIRECT upstream to :80 with totan inside the slice:
#   client(in slice) → connect4 → totan(in slice) → DIRECT connect to :80
# Without the self-skip, totan's own :80 connect would be rewritten back into
# its own listener and loop forever (curl would time out). With it, the request
# reaches the backend.
#
# Run as root: sudo ./toolkit/e2e/selfskip.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TOTAN_BIN="${TOTAN_BIN:-$REPO_ROOT/target/release/totan}"
SLICE=/sys/fs/cgroup/totan-selftest.slice
WORK="$(mktemp -d -t totan-selfskip.XXXXXX)"
CFG="$WORK/totan.toml"
PAC="$WORK/direct.pac"
TOTAN_LOG="$WORK/totan.log"
BACKEND_PY="$WORK/backend.py"
BACKEND_PID=""
TOTAN_PID=""

cleanup() {
    [[ -n "$TOTAN_PID" ]] && kill "$TOTAN_PID" 2>/dev/null
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null
    sleep 0.3
    rmdir "$SLICE" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || { echo "must run as root (sudo)"; exit 1; }
[[ -x "$TOTAN_BIN" ]] || { echo "build first: cargo build -p totan --features ebpf --release"; exit 1; }

# ── backend on 127.0.0.2:80 (DIRECT target) ──────────────────────────────────
cat > "$BACKEND_PY" <<'PY'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(b"selfskip-backend-ok")
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True  # tolerate TIME_WAIT across runs
socketserver.TCPServer(("127.0.0.2", 80), H).serve_forever()
PY
python3 "$BACKEND_PY" &
BACKEND_PID=$!
sleep 0.5

# ── host-hooks-only config, DIRECT upstream (PAC always returns DIRECT) ───────
echo 'function FindProxyForURL(url, host) { return "DIRECT"; }' > "$PAC"
cat > "$CFG" <<EOF
listen_port = 3129
interception_mode = "ebpf"
pac_file = "$PAC"

[logging]
level = "debug"
format = "text"

[ebpf]
ingress_interfaces = []

[ebpf.host_hooks]
redirect_port = 3130
slices = ["$SLICE"]
EOF

mkdir -p "$SLICE"

# Start totan ALREADY inside the hooked slice (mirrors a systemd unit placed in
# the slice via `Slice=`). connect4 fires on totan's own upstream connects, so
# self_mark must make it skip them; the guard should warn (not bail).
bash -c 'echo $$ > "'"$SLICE"'/cgroup.procs"; exec "$1" --config "$2"' \
    _ "$TOTAN_BIN" "$CFG" >"$TOTAN_LOG" 2>&1 &
TOTAN_PID=$!

# host-hooks-only binds only the redirect listener (3130), never the tproxy one.
for i in $(seq 1 50); do
    ss -tlnH 'sport = :3130' | grep -q 3130 && break
    sleep 0.1
    [[ $i -eq 50 ]] && { echo "FAIL: totan did not bind :3130"; echo "--- log ---"; cat "$TOTAN_LOG"; exit 1; }
done
echo "✓ host-hooks-only mode started in-slice (bound :3130, no interfaces configured)"
grep -qx "$TOTAN_PID" "$SLICE/cgroup.procs" || { echo "FAIL: totan not in slice"; exit 1; }
echo "✓ totan running inside $SLICE"

# ── client curl inside the slice → DIRECT upstream through totan ──────────────
body=$(bash -c 'echo $$ > "'"$SLICE"'/cgroup.procs"; exec curl --silent --max-time 5 --noproxy "*" http://127.0.0.2/' 2>&1)

echo "--- totan log (tail) ---"; tail -6 "$TOTAN_LOG"
echo "--- result: '$body' ---"

rc=0
if [[ "$body" == "selfskip-backend-ok" ]]; then
    echo "✓ PASS: totan-in-slice DIRECT upstream to :80 succeeded — no self-loop"
else
    echo "✗ FAIL: expected 'selfskip-backend-ok', got '$body' (self-loop?)"; rc=1
fi
if grep -q "relying on self_mark" "$TOTAN_LOG"; then
    echo "✓ PASS: self-exclusion warning emitted (guard relaxed, not fatal)"
else
    echo "✗ FAIL: expected self_mark co-residence warning in log"; rc=1
fi
exit $rc
