package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientIPFromPeer accepts forwarding headers only when the TCP peer is a
// configured trusted proxy. The first X-Forwarded-For address is the original
// client under the documented nginx/Caddy single-proxy configuration.
func (s *Server) clientIPFromPeer(peer, forwardedFor string) string {
	peerAddr, err := netip.ParseAddr(strings.TrimSpace(peer))
	if err != nil || s == nil || s.cfg == nil || !s.cfg.isTrustedProxy(peerAddr) {
		return peer
	}
	for _, value := range strings.Split(forwardedFor, ",") {
		candidate := strings.TrimSpace(value)
		if addr, err := netip.ParseAddr(candidate); err == nil {
			return addr.String()
		}
	}
	return peerAddr.String()
}

func (s *Server) remotePeerIsTrusted(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && s != nil && s.cfg != nil && s.cfg.isTrustedProxy(addr)
}
