// PAC script used by the e2e test suite.
//
// Routing rules — each prefix triggers a different upstream so the test can
// verify PAC-based routing end-to-end by reading the matching proxy's log
// AND by checking the response body delivered through the chain:
//
//   "a-*"      → PROXY 127.0.0.1:8881            (proxy-a, forward mode)
//   "b-*"      → PROXY 127.0.0.1:8882            (proxy-b, forward mode)
//   "fail-*"   → PROXY 127.0.0.1:1; PROXY 8880   (first dead → failover)
//   "socks-*"  → SOCKS5 127.0.0.1:1080           (SOCKS5 path)
//   192.0.2.14 → PROXY 127.0.0.1:8881            (IP-only routing for plain HTTP)
//   default    → PROXY 127.0.0.1:8880            (proxy-default)
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "a-*")) {
        return "PROXY 127.0.0.1:8881";
    }
    if (shExpMatch(host, "b-*")) {
        return "PROXY 127.0.0.1:8882";
    }
    if (shExpMatch(host, "fail-*")) {
        // First entry is intentionally dead so the upstream connector must
        // walk the failover list and recover via the second entry.
        return "PROXY 127.0.0.1:1; PROXY 127.0.0.1:8880";
    }
    if (shExpMatch(host, "socks-*")) {
        return "SOCKS5 127.0.0.1:1080";
    }
    // For plain HTTP totan passes the raw destination IP as host (no SNI).
    // Route 192.0.2.14 to proxy-a to exercise the IP-based HTTP routing path.
    if (host === "192.0.2.14") {
        return "PROXY 127.0.0.1:8881";
    }
    return "PROXY 127.0.0.1:8880";
}
