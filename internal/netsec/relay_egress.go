// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"
)

// ErrRelayEgressBlocked is a job connection the agent's egress policy refused.
var ErrRelayEgressBlocked = errors.New("relay egress policy refused the destination")

// Cloud instance-metadata addresses outside the link-local range.
var relayMetadataAddrs = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6 IMDS
}

// RelayEgress is the egress policy for the connections an agent opens to run
// jobs. A network relay exists to reach private devices in its own segment, so
// it cannot run the control plane's SSRF guard, which refuses exactly those.
// Instead it always refuses the addresses no device job needs and an attacker
// most wants (link-local, cloud instance metadata among them, unspecified and
// multicast), and, when the operator lists destinations, refuses everything
// outside the list. A nil policy is the always-on part alone.
type RelayEgress struct {
	prefixes []netip.Prefix
	exact    []netip.AddrPort
}

// ParseRelayEgress parses an operator allowlist: CIDRs (10.20.0.0/16),
// addresses (10.20.0.5, fd00::5) and address:port pairs (10.20.0.5:8443,
// [fd00::5]:8443). Host names are refused: a dial sees only the address a name
// resolved to, so a name cannot be enforced here. An empty list allows every
// destination outside the always-refused ranges.
func ParseRelayEgress(entries []string) (*RelayEgress, error) {
	p := &RelayEgress{}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := ParseEgressAllowPrefix(entry)
			if err != nil {
				return nil, err
			}
			p.prefixes = append(p.prefixes, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			addr = addr.Unmap()
			p.prefixes = append(p.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		if ap, err := netip.ParseAddrPort(entry); err == nil && ap.Port() != 0 {
			p.exact = append(p.exact, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
			continue
		}
		return nil, fmt.Errorf("relay egress entry %q is not a CIDR, an IP address or an address:port; list addresses, since a host name resolves at connect time and cannot be pinned", entry)
	}
	return p, nil
}

// Allowlisted reports whether the operator listed destinations.
func (p *RelayEgress) Allowlisted() bool {
	return p != nil && (len(p.prefixes) > 0 || len(p.exact) > 0)
}

// relayAlwaysRefused is the part of the policy no allowlist can lift.
func relayAlwaysRefused(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, metadata := range relayMetadataAddrs {
		if addr == metadata {
			return true
		}
	}
	return false
}

// Allow reports whether a job may connect to the resolved destination.
func (p *RelayEgress) Allow(dest netip.AddrPort) error {
	addr := dest.Addr().Unmap()
	if relayAlwaysRefused(addr) {
		return fmt.Errorf("%w: %s is link-local, cloud metadata, unspecified or multicast, which no job may reach", ErrRelayEgressBlocked, addr)
	}
	if !p.Allowlisted() {
		return nil
	}
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return nil
		}
	}
	for _, exact := range p.exact {
		if exact.Addr() == addr && exact.Port() == dest.Port() {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not on this agent's egress allowlist", ErrRelayEgressBlocked, netip.AddrPortFrom(addr, dest.Port()))
}

// Control is a net.Dialer Control callback: it checks the resolved address of
// every connection attempt, so a name that resolves somewhere refused is still
// caught on the address actually dialed.
func (p *RelayEgress) Control(_ string, address string, _ syscall.RawConn) error {
	dest, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRelayEgressBlocked, err)
	}
	return p.Allow(dest)
}

// Guard chains base, which may be nil, before the policy's Control.
func (p *RelayEgress) Guard(base func(string, string, syscall.RawConn) error) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if base != nil {
			if err := base(network, address, c); err != nil {
				return err
			}
		}
		return p.Control(network, address, c)
	}
}

// CheckHostPort resolves host:port and checks every address it resolves to,
// for a connection the agent does not dial itself (an external tool) or one
// a proxy carries.
func (p *RelayEgress) CheckHostPort(ctx context.Context, hostport string) error {
	host, portText, err := net.SplitHostPort(hostport)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRelayEgressBlocked, err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("%w: port %q", ErrRelayEgressBlocked, portText)
	}
	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{addr}
	} else if addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host); err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, addr := range addrs {
		if err := p.Allow(netip.AddrPortFrom(addr, uint16(port))); err != nil { // #nosec G115 -- LookupPort returned 0-65535, checked above (CWE-190)
			return err
		}
	}
	return nil
}

// GuardTransport makes t's dialer enforce the policy.
func (p *RelayEgress) GuardTransport(t *http.Transport) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: p.Control}
	t.DialContext = dialer.DialContext
}

// RoundTripper checks each request's destination before next sends it. The
// dial check alone cannot see the destination of a request a proxy carries,
// since that dial reaches the proxy.
func (p *RelayEgress) RoundTripper(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return relayEgressRoundTripper{policy: p, next: next}
}

type relayEgressRoundTripper struct {
	policy *RelayEgress
	next   http.RoundTripper
}

func (rt relayEgressRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rt.policy.CheckRequest(req); err != nil {
		return nil, err
	}
	return rt.next.RoundTrip(req)
}

// CheckRequest checks the destination a request names, wherever it is sent.
func (p *RelayEgress) CheckRequest(req *http.Request) error {
	port := req.URL.Port()
	if port == "" {
		port = "443"
		if req.URL.Scheme == "http" {
			port = "80"
		}
	}
	return p.CheckHostPort(req.Context(), net.JoinHostPort(req.URL.Hostname(), port))
}

// CloseIdleConnections passes through to the wrapped transport.
func (rt relayEgressRoundTripper) CloseIdleConnections() {
	if closer, ok := rt.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// String describes the policy for logs and the executor census.
func (p *RelayEgress) String() string {
	if !p.Allowlisted() {
		return "link-local, cloud metadata, unspecified and multicast refused; no allowlist"
	}
	entries := make([]string, 0, len(p.prefixes)+len(p.exact))
	for _, prefix := range p.prefixes {
		if prefix.IsSingleIP() {
			entries = append(entries, prefix.Addr().String())
		} else {
			entries = append(entries, prefix.String())
		}
	}
	for _, exact := range p.exact {
		entries = append(entries, exact.String())
	}
	sort.Strings(entries)
	return "link-local, cloud metadata, unspecified and multicast refused; allowlist " + strings.Join(entries, ", ")
}
