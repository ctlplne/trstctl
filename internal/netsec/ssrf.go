// Package netsec holds shared network-security primitives. Its centerpiece is the
// SSRF guard (SEC-006/SEC-008): a dialer Control callback and HTTP client that
// refuse to connect to non-public addresses, so any outbound request whose target
// is operator- or tenant-influenced (an ACME challenge URL, a webhook endpoint, a
// connector target) cannot be coerced into reaching internal/metadata services.
//
// The guard validates the RESOLVED address at dial time (Control runs after DNS,
// immediately before connect, for every attempt including each redirect hop), so it
// defeats DNS rebinding: a public name that resolves to a private IP is still
// caught on the IP that is actually dialed. This is the single implementation the
// ACME validator (SEC-006) and the notification/connector channels (SEC-008) share,
// so the denylist cannot drift between call sites.
package netsec

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrSSRFBlocked is returned when an outbound request is aimed at an address in a
// blocked range (loopback, link-local incl. the cloud metadata service,
// private/RFC-1918, unique-local, carrier-grade NAT, unspecified, or multicast).
var ErrSSRFBlocked = errors.New("netsec: refusing to connect to a non-public address (SSRF guard)")

// BlockedIP reports whether ip is in a range an outbound request must never reach.
// It evaluates the RESOLVED address, so DNS that points a public name at an
// internal IP is still caught. The denylist: loopback (127/8, ::1), link-local
// (169.254/16 incl. the 169.254.169.254 cloud-metadata service, and fe80::/10),
// the IPv6 metadata alias fd00:ec2::254, private RFC-1918 ranges, IPv6 unique-local
// (fc00::/7), carrier-grade NAT (100.64/10), the unspecified address, and
// multicast.
func BlockedIP(ip net.IP) bool {
	return BlockedIPWithOptions(ip, BlockedIPOptions{})
}

// BlockedIPOptions lets call sites intentionally relax one part of the reserved
// set while keeping loopback, metadata, link-local, multicast, unspecified, CGNAT,
// and IPv6 unique-local blocked.
type BlockedIPOptions struct {
	AllowRFC1918 bool
}

// SafeClientOptions configures the SSRF-safe HTTP client. By default every
// non-public resolved address is refused. AllowPrivateCIDRs is the narrow escape
// hatch for operator-owned private CA/service endpoints: only resolved addresses
// inside one of these prefixes are allowed. Link-local, metadata, multicast,
// unspecified, and CGNAT ranges stay blocked.
type SafeClientOptions struct {
	AllowPrivateCIDRs []netip.Prefix
}

// BlockedIPWithOptions is BlockedIP with an explicit RFC1918 toggle for scanners
// that operators point at their own private network ranges.
func BlockedIPWithOptions(ip net.IP, opts BlockedIPOptions) bool {
	if ip == nil {
		return true // unparseable → refuse
	}
	// Normalize to canonical form so v4-in-v6 (::ffff:a.b.c.d) is matched as v4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if ip.IsPrivate() && (!opts.AllowRFC1918 || !isRFC1918(ip)) {
		return true
	}
	// Carrier-grade NAT (RFC 6598) is not covered by IsPrivate; treat it as internal.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10
			return true
		}
	}
	// The IPv6 alias some clouds expose for the metadata service.
	if ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return true
	}
	return false
}

func isRFC1918(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 10 ||
		(v4[0] == 172 && v4[1]&0xf0 == 16) ||
		(v4[0] == 192 && v4[1] == 168)
}

// SafeDialControl is a net.Dialer.Control callback that rejects a connection whose
// resolved address is in a blocked range. Because Control runs AFTER name
// resolution and immediately BEFORE connect — on the actual IP the socket will use,
// for every attempt including each redirect hop — it defeats DNS rebinding.
func SafeDialControl(_ /*network*/ string, address string, _ syscall.RawConn) error {
	return safeDialControl(SafeClientOptions{}, address)
}

// SafeDialControlWithOptions returns a net.Dialer.Control callback with explicit
// private-CIDR allowances.
func SafeDialControlWithOptions(opts SafeClientOptions) func(string, string, syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		return safeDialControl(opts, address)
	}
}

func safeDialControl(opts SafeClientOptions, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSRFBlocked, err)
	}
	if blockedIPForClient(net.ParseIP(host), opts) {
		return fmt.Errorf("%w: %s", ErrSSRFBlocked, host)
	}
	return nil
}

// SafeTransport returns an *http.Transport whose dialer validates every resolved
// address against the SSRF denylist.
func SafeTransport() *http.Transport {
	return SafeTransportWithOptions(SafeClientOptions{})
}

// SafeTransportWithOptions is SafeTransport with explicit private-CIDR allowances.
func SafeTransportWithOptions(opts SafeClientOptions) *http.Transport {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: SafeDialControlWithOptions(opts)}
	return &http.Transport{
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		// Don't reuse a connection across hosts/redirects — each dial is re-validated.
		DisableKeepAlives: true,
	}
}

// ValidatePublicHTTPSURL checks the cheap parts of an operator/tenant-supplied
// outbound endpoint before net/http builds or logs a request: it must be HTTPS, must
// name a host, and must not use a literal non-public IP. DNS answers are still checked
// by SafeTransport at dial time, which is what catches rebinding.
func ValidatePublicHTTPSURL(raw string) error {
	return ValidatePublicHTTPSURLWithOptions(raw, SafeClientOptions{})
}

// ValidatePublicHTTPSURLWithOptions checks the cheap URL pieces while honoring
// the same explicit private-CIDR allowances used by SafeClientWithOptions.
func ValidatePublicHTTPSURLWithOptions(raw string, opts SafeClientOptions) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: malformed outbound endpoint", ErrSSRFBlocked)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: outbound endpoint must use https", ErrSSRFBlocked)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: outbound endpoint is missing a host", ErrSSRFBlocked)
	}
	if ip := net.ParseIP(host); ip != nil && blockedIPForClient(ip, opts) {
		return fmt.Errorf("%w: outbound endpoint host is not public", ErrSSRFBlocked)
	}
	return nil
}

// SafeClient returns an *http.Client safe to point at an attacker-influenced URL:
// its transport blocks non-public resolved addresses, and its redirect policy both
// bounds the chain and re-validates each hop's host (the dial Control catches the
// IP; this catches a literal-IP Location before the dial, and refuses a redirect to
// a non-http(s) scheme).
func SafeClient(timeout time.Duration) *http.Client {
	return SafeClientWithOptions(timeout, SafeClientOptions{})
}

// SafeClientWithOptions returns an SSRF-safe HTTP client with explicit
// private-CIDR allowances.
func SafeClientWithOptions(timeout time.Duration, opts SafeClientOptions) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: SafeTransportWithOptions(opts),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("netsec: too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("%w: redirect to scheme %q", ErrSSRFBlocked, req.URL.Scheme)
			}
			if ip := net.ParseIP(req.URL.Hostname()); ip != nil && blockedIPForClient(ip, opts) {
				return fmt.Errorf("%w: redirect to %s", ErrSSRFBlocked, req.URL.Hostname())
			}
			return nil
		},
	}
}

func blockedIPForClient(ip net.IP, opts SafeClientOptions) bool {
	if !BlockedIP(ip) {
		return false
	}
	return !allowedPrivateIP(ip, opts)
}

func allowedPrivateIP(ip net.IP, opts SafeClientOptions) bool {
	if ip == nil || len(opts.AllowPrivateCIDRs) == 0 {
		return false
	}
	if hardBlockedIP(ip) {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range opts.AllowPrivateCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func hardBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return true
		}
	}
	return ip.Equal(net.ParseIP("fd00:ec2::254"))
}
