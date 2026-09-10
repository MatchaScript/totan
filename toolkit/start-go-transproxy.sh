#!/usr/bin/env bash
set -euo pipefail

# Configure from env
HTTP_PROXY_UPSTREAM=${HTTP_PROXY_UPSTREAM:-http://squid:3128}
HTTPS_PROXY_UPSTREAM=${HTTPS_PROXY_UPSTREAM:-http://squid:3128}
NO_PROXY_LIST=${NO_PROXY_LIST:-localhost,127.0.0.1,nginx}
PUBLIC_DNS=${PUBLIC_DNS:-}
PRIVATE_DNS=${PRIVATE_DNS:-}
DNS_OVER_HTTPS=${DNS_OVER_HTTPS:-false}
DNS_OVER_TCP_DISABLED=${DNS_OVER_TCP_DISABLED:-false}
TEST_UID=${TEST_UID:-999}
ENABLE_DNS_REDIRECT=${ENABLE_DNS_REDIRECT:-true}
PORT_HTTP=${PORT_HTTP:-3129}
PORT_HTTPS=${PORT_HTTPS:-3130}
PORT_DNS=${PORT_DNS:-3131}

export http_proxy="${HTTP_PROXY_UPSTREAM}"
export https_proxy="${HTTPS_PROXY_UPSTREAM}"
export no_proxy="${NO_PROXY_LIST}"

args=(
  -loglevel info
  -tcp-proxy-listen :3128
  -http-proxy-listen :${PORT_HTTP}
  -https-proxy-listen :${PORT_HTTPS}
  -dns-proxy-listen :${PORT_DNS}
  -disable-iptables
)

if [[ -n "${PUBLIC_DNS}" ]]; then
  args+=( -public-dns "${PUBLIC_DNS}" )
fi
if [[ -n "${PRIVATE_DNS}" ]]; then
  args+=( -private-dns "${PRIVATE_DNS}" )
fi
if [[ "${DNS_OVER_HTTPS}" == "true" ]]; then
  args+=( -dns-over-https-enabled )
fi
if [[ "${DNS_OVER_TCP_DISABLED}" == "true" ]]; then
  args+=( -dns-over-tcp-disabled )
fi

# Configure nftables to transparently redirect only TEST_UID traffic
echo "[go-transproxy] Using nftables redirection for uid ${TEST_UID}: HTTP->${PORT_HTTP}, HTTPS->${PORT_HTTPS}, DNS->${PORT_DNS} (dns_redirect=${ENABLE_DNS_REDIRECT})"

# Ensure nft table/chain exists and is clean
nft list table ip nat >/dev/null 2>&1 || nft add table ip nat

if ! nft list chain ip nat OUTPUT >/dev/null 2>&1; then
  nft add chain ip nat OUTPUT '{ type nat hook output priority 100; policy accept; }'
fi

# Delete our rules if they exist (idempotent cleanup)
nft --handle list chain ip nat OUTPUT | awk '/ skuid / {print $NF}' | sed 's/;//' | while read -r h; do nft delete rule ip nat OUTPUT handle "$h" || true; done 2>/dev/null || true

# Add user-scoped redirect rules for HTTP/HTTPS
nft add rule ip nat OUTPUT meta skuid ${TEST_UID} tcp dport 80  redirect to ${PORT_HTTP}
nft add rule ip nat OUTPUT meta skuid ${TEST_UID} tcp dport 443 redirect to ${PORT_HTTPS}

# Optional: DNS redirection (TCP/UDP 53)
if [[ "${ENABLE_DNS_REDIRECT}" == "true" ]]; then
  nft add rule ip nat OUTPUT meta skuid ${TEST_UID} tcp dport 53  redirect to ${PORT_DNS}
  nft add rule ip nat OUTPUT meta skuid ${TEST_UID} udp dport 53  redirect to ${PORT_DNS}
fi

echo "[go-transproxy] starting with: transproxy ${args[*]}"
exec /usr/local/bin/transproxy "${args[@]}"
