// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Client addresses behind a load balancer (M1-L1). Every request's peer is the
// connection's remote address; behind a load balancer or reverse proxy that is
// the proxy, for every client. X-Forwarded-For names the clients, but anyone
// can send it, so it is read only from a peer inside the operator's
// server.trusted_proxies CIDRs, and then from its right end: each trusted proxy
// appends the address it received from, so the right-most address that is not
// itself a trusted proxy is the one the operator's own infrastructure vouches
// for. Anything to its left is what the client claimed.

// maxForwardedHops bounds the X-Forwarded-For entries read for one request.
const maxForwardedHops = 32

// TrustedProxies is the set of proxy networks whose X-Forwarded-For is read.
// The zero value trusts no proxy: every request's client is its peer.
type TrustedProxies struct {
	prefixes []netip.Prefix
}

// ParseTrustedProxies parses CIDRs (a bare address is its own /32 or /128).
// A prefix that matches every address is refused: it would let any client
// name its own address.
func ParseTrustedProxies(cidrs []string) (TrustedProxies, error) {
	var out TrustedProxies
	for _, raw := range cidrs {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		var prefix netip.Prefix
		var err error
		if strings.Contains(value, "/") {
			prefix, err = netip.ParsePrefix(value)
		} else {
			var addr netip.Addr
			addr, err = netip.ParseAddr(value)
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if err != nil {
			return TrustedProxies{}, fmt.Errorf("trusted proxy %q is not an address or CIDR", value)
		}
		if prefix.Bits() == 0 {
			return TrustedProxies{}, fmt.Errorf("trusted proxy %q matches every address; name the proxies' networks", value)
		}
		out.prefixes = append(out.prefixes, prefix.Masked())
	}
	return out, nil
}

func (t TrustedProxies) trusts(addr netip.Addr) bool {
	for _, p := range t.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePeer(remoteAddr string) (netip.Addr, bool) {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

var errForwardedFor = errors.New("netsec: unusable X-Forwarded-For")

// forwardedFor reads a request's X-Forwarded-For entries, left to right,
// across every header line.
func forwardedFor(r *http.Request) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			addr, ok := parsePeer(part)
			if !ok {
				return nil, errForwardedFor
			}
			out = append(out, addr)
			if len(out) > maxForwardedHops {
				return nil, errForwardedFor
			}
		}
	}
	return out, nil
}

// ClientAddr resolves the client behind r: its peer, unless the peer is a
// trusted proxy, in which case the right-most X-Forwarded-For address that is
// not a trusted proxy (the left-most when every one is). An X-Forwarded-For
// that cannot be read whole is not used.
func (t TrustedProxies) ClientAddr(r *http.Request) (netip.Addr, bool) {
	peer, ok := parsePeer(r.RemoteAddr)
	if !ok || !t.trusts(peer) {
		return peer, ok
	}
	hops, err := forwardedFor(r)
	if err != nil || len(hops) == 0 {
		return peer, true
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !t.trusts(hops[i]) {
			return hops[i], true
		}
	}
	return hops[0], true
}

type clientAddrKey struct{}

// Middleware resolves each request's client once and keeps it on the request,
// where ClientIP reads it.
func (t TrustedProxies) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if addr, ok := t.ClientAddr(r); ok {
			r = r.WithContext(context.WithValue(r.Context(), clientAddrKey{}, addr))
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP is the request's client address as Middleware resolved it, or the
// connection's peer address when it did not run. Callers that key a limit or
// a usage record on the client use this, never a forwarded-for header.
func ClientIP(r *http.Request) string {
	if addr, ok := r.Context().Value(clientAddrKey{}).(netip.Addr); ok && addr.IsValid() {
		return addr.String()
	}
	if addr, ok := parsePeer(r.RemoteAddr); ok {
		return addr.String()
	}
	return r.RemoteAddr
}
