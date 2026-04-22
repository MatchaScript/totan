// PAC script used by the e2e test suite.
//
// Routing rules:
//   host starts with "a-"  → PROXY 127.0.0.1:8881 (proxy-a)
//   host starts with "b-"  → PROXY 127.0.0.1:8882 (proxy-b)
//   everything else         → PROXY 127.0.0.1:8880 (proxy-default)
//
// The test runner curls specific hostnames (mapped via --resolve) and then
// asserts that the matching proxy's log file contains the request line —
// proving PAC evaluation picks the intended upstream.
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "a-*")) {
        return "PROXY 127.0.0.1:8881";
    }
    if (shExpMatch(host, "b-*")) {
        return "PROXY 127.0.0.1:8882";
    }
    return "PROXY 127.0.0.1:8880";
}
