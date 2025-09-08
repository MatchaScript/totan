FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    jq \
    iputils-ping \
    iproute2 \
    tcpdump \
    dnsutils \
    iptables \
    nftables \
    tshark \
    bpftrace \
    netcat-openbsd \
    w3m \
    gnupg \
    tini \
    apache2-utils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN set -x \
    # create totan user/group first, to be consistent throughout docker variants
    && groupadd --system --gid 105 totan \
    && useradd --system --gid totan --no-create-home --home /nonexistent --comment "totan user" --shell /bin/false --uid 105 totan \
    # create a general test user with fixed UID/GID 999
    && (getent group 999 >/dev/null || groupadd --gid 999 tester) \
    && (id -u 999 >/dev/null 2>&1 || useradd --uid 999 --gid 999 --create-home --home /home/tester --comment "test user" --shell /bin/sh tester) \
    && mkdir -p /etc/totan /opt/totan \
    && chown -R root:root /etc/totan /opt/totan \
    && chmod 0755 /etc/totan /opt/totan

# Copy entrypoint script
COPY toolkit/start-totan.sh /usr/local/bin/start-totan.sh
RUN chmod +x /usr/local/bin/start-totan.sh
# Expose default listen port
EXPOSE 3129

# By default just idle; compose will override with start script
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/start-totan.sh"]

