function FindProxyForURL(url, host) {
  // Everything else goes DIRECT
  return "PROXY squid:3128";
}
