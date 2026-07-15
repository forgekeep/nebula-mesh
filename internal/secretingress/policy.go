// Package secretingress defines the request-level transport policy for
// endpoints that receive private key material.
package secretingress

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Policy allows direct TLS, literal-loopback plaintext, and an explicitly
// trusted local TLS-terminating proxy. It ignores broader server
// plaintext opt-outs because private-key ingress needs a stricter boundary.
type Policy struct {
	listenerLoopback bool
	trustedProxy     bool
}

// NewPolicy constructs a request policy for the configured server listener.
func NewPolicy(listen string, trustedProxy bool) Policy {
	return Policy{
		listenerLoopback: listenerIsLoopback(listen),
		trustedProxy:     trustedProxy,
	}
}

// Allows reports whether request transport metadata proves a protected path.
func (p Policy) Allows(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	peerLoopback := remoteIsLoopback(r.RemoteAddr)
	if peerLoopback && hostIsLiteralLoopback(r.Host) {
		return true
	}
	if !p.trustedProxy || !p.listenerLoopback || !peerLoopback {
		return false
	}
	forwardedProto := r.Header.Values("X-Forwarded-Proto")
	if len(forwardedProto) != 1 || !strings.EqualFold(strings.TrimSpace(forwardedProto[0]), "https") {
		return false
	}
	return hostIsPublic(r.Host)
}

func listenerIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

func remoteIsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

func hostIsLiteralLoopback(hostport string) bool {
	host, ok := requestHostname(hostport)
	if !ok {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

func hostIsPublic(hostport string) bool {
	host, ok := requestHostname(hostport)
	if !ok || host == "" || strings.EqualFold(host, "localhost") {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return true
	}
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsLoopback() && !addr.IsPrivate() &&
		!addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() && !addr.IsUnspecified()
}

func requestHostname(hostport string) (string, bool) {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host, true
	}
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"), true
	}
	if strings.Contains(hostport, ":") {
		return "", false
	}
	return hostport, true
}
