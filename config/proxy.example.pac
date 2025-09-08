// Example PAC file for totan
// This function is called by the proxy to determine the appropriate proxy for a given URL

function FindProxyForURL(url, host) {
  var ip = dnsResolve(host);
    // Direct connection for localhost and local network
    if (isPlainHostName(host) || 
        isInNet(host, "127.0.0.0", "255.0.0.0") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return "DIRECT";
    }
    
    // Corporate domains that should go direct
    if (dnsDomainIs(host, ".internal.company.com") ||
        dnsDomainIs(host, ".corp.example.com")) {
        return "DIRECT";
    }
    
    // High-priority external services via fast proxy
    if (dnsDomainIs(host, ".github.com") ||
        dnsDomainIs(host, ".gitlab.com") ||
        dnsDomainIs(host, ".stackoverflow.com")) {
        return "PROXY fastproxy.example.com:8080; PROXY proxy.example.com:8080";
    }
    
    // Default: use the corporate proxy
    return "PROXY proxy.example.com:8080; DIRECT";
}
