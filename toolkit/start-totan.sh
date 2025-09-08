#!/usr/bin/env bash
set -euo pipefail

# Configure nftables for transparent proxying inside the container
PORT=${PORT:-3129}
USER_NAME=${USER_NAME:-totan}
TEST_UID=${TEST_UID:-999}

echo "[start-totan] Using nftables redirection to port ${PORT} (scope: skuid=${TEST_UID})"

echo "[start-totan] Using nftables to redirect only uid ${TEST_UID} TCP dport 80,443 to ${PORT}"

# Ensure nft table/chain exists and is clean
nft list table ip nat >/dev/null 2>&1 || nft add table ip nat

# Create chains (idempotent)
if ! nft list chain ip nat OUTPUT >/dev/null 2>&1; then
  nft add chain ip nat OUTPUT '{ type nat hook output priority 100; policy accept; }'
fi

# Delete our rules if they exist (idempotent cleanup)
nft --handle list chain ip nat OUTPUT | awk '/ skuid / {print $NF}' | sed 's/;//' | while read -r h; do nft delete rule ip nat OUTPUT handle "$h" || true; done 2>/dev/null || true

# Add user-scoped redirect rules
nft add rule ip nat OUTPUT meta skuid ${TEST_UID} tcp dport {80, 443} redirect to ${PORT}

# Optional: avoid redirecting to squid itself if tester calls squid:3128 directly (no-op here since different dport)

echo "[start-totan] Starting totan..."

# Try to drop privileges to the totan user to avoid redirecting our own traffic
if command -v runuser >/dev/null 2>&1 && getent passwd "${USER_NAME}" >/dev/null 2>&1; then
  exec runuser -u "${USER_NAME}" -- /opt/totan/totan --config /etc/totan/totan.toml "$@"
elif command -v su >/dev/null 2>&1 && getent passwd "${USER_NAME}" >/dev/null 2>&1; then
  exec su -s /bin/sh -c "/opt/totan/totan --config /etc/totan/totan.toml \"$@\"" "${USER_NAME}"
else
  echo "[start-totan] Warning: cannot drop privileges; running as root"
  # Nothing special needed with nft since rule only targets TEST_UID
  exec /opt/totan/totan --config /etc/totan/totan.toml "$@"
fi
