// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/trust"
)

// cloudMetadataAddrs are the link-local addresses AWS serves a workload's own
// credentials on: the EC2 instance metadata service and its IPv6 alias, the
// ECS container credentials endpoint, and the EKS Pod Identity agent (IPv4
// and IPv6).
var cloudMetadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("169.254.170.2"),
	netip.MustParseAddr("169.254.170.23"),
	netip.MustParseAddr("fd00:ec2::23"),
}

// CloudMetadataClient returns the client a process reads its own cloud
// credentials with from a metadata endpoint (A200-L1). Those endpoints are
// plain HTTP on link-local addresses the SSRF guard refuses everywhere else,
// so this is the narrowest client netsec builds: the endpoint must be an http
// URL naming one of AWS's metadata addresses, or a loopback address (a local
// credentials agent, which the AWS SDKs accept as well); every socket is
// dialed to exactly that address and port; no proxy is consulted; and
// redirects are refused. A zero timeout means five seconds.
func CloudMetadataClient(endpoint string, timeout time.Duration) (*http.Client, error) {
	pinned, err := cloudMetadataAddrPort(endpoint)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := trust.HardenTransport(&http.Transport{
		// No proxy: a credentials request must reach the metadata address
		// itself, never an HTTP(S)_PROXY from the environment.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if !sameAddrPort(address, pinned) {
				return nil, fmt.Errorf("%w: the metadata client dials only %s, not %s", ErrSSRFBlocked, pinned, address)
			}
			return dialer.DialContext(ctx, network, pinned.String())
		},
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          1,
		IdleConnTimeout:       timeout,
	})
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("%w: the metadata client refuses redirects", ErrSSRFBlocked)
		},
	}, nil
}

// cloudMetadataAddrPort checks a metadata endpoint and returns the address
// and port every socket for it is pinned to.
func cloudMetadataAddrPort(endpoint string) (netip.AddrPort, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return netip.AddrPort{}, fmt.Errorf("%w: metadata endpoint must be an absolute URL", ErrSSRFBlocked)
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return netip.AddrPort{}, fmt.Errorf("%w: metadata endpoint must be http on a metadata or loopback address", ErrSSRFBlocked)
	}
	if u.User != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: metadata endpoint must not carry user information", ErrSSRFBlocked)
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: metadata endpoint must name an address, not the host name %q", ErrSSRFBlocked, u.Hostname())
	}
	addr = addr.Unmap()
	if addr.Zone() != "" || (!addr.IsLoopback() && !slices.Contains(cloudMetadataAddrs, addr)) {
		return netip.AddrPort{}, fmt.Errorf("%w: metadata endpoint %s is not a cloud metadata or loopback address", ErrSSRFBlocked, addr)
	}
	port := uint16(80)
	if raw := u.Port(); raw != "" {
		parsed, err := netip.ParseAddrPort(net.JoinHostPort(addr.String(), raw))
		if err != nil || parsed.Port() == 0 {
			return netip.AddrPort{}, fmt.Errorf("%w: metadata endpoint has an invalid port", ErrSSRFBlocked)
		}
		port = parsed.Port()
	}
	return netip.AddrPortFrom(addr, port), nil
}

// sameAddrPort reports whether a dial address names exactly the pinned one.
func sameAddrPort(address string, pinned netip.AddrPort) bool {
	got, err := netip.ParseAddrPort(address)
	if err != nil {
		return false
	}
	return got.Addr().Unmap() == pinned.Addr() && got.Port() == pinned.Port()
}
