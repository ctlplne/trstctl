// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

// ErrRepositoryEgressBlocked is deliberately uniform: neither a tenant nor a
// signed hook learns whether a private address, DNS answer, or port exists.
var ErrRepositoryEgressBlocked = errors.New("secretscan: repository clone target is outside allowed HTTPS egress")

// RepositoryCloneEgress is operator-owned network authority. A tenant request
// cannot populate it. Empty means public HTTPS only.
type RepositoryCloneEgress struct {
	allowPrivateCIDRs []netip.Prefix
}

// RepositoryCloneEgressFromCIDRs intersects a source's approved request with
// the operator's current ceiling. A removed ceiling revokes the stored source
// on its next run, including a scheduled retry.
func RepositoryCloneEgressFromCIDRs(requested, ceiling []string) (RepositoryCloneEgress, error) {
	if len(requested) == 0 || len(requested) > 64 || len(ceiling) == 0 {
		return RepositoryCloneEgress{}, ErrRepositoryEgressBlocked
	}
	allowed := make([]netip.Prefix, 0, len(ceiling))
	for _, raw := range ceiling {
		prefix, err := netsec.ParsePrivateEgressPrefix(raw)
		if err != nil {
			return RepositoryCloneEgress{}, ErrRepositoryEgressBlocked
		}
		allowed = append(allowed, prefix)
	}
	policy := RepositoryCloneEgress{allowPrivateCIDRs: make([]netip.Prefix, 0, len(requested))}
	for _, raw := range requested {
		prefix, err := netsec.ParsePrivateEgressPrefix(raw)
		if err != nil {
			return RepositoryCloneEgress{}, ErrRepositoryEgressBlocked
		}
		inside := false
		for _, ceilingPrefix := range allowed {
			if prefix.Addr().Is4() == ceilingPrefix.Addr().Is4() &&
				prefix.Bits() >= ceilingPrefix.Bits() && ceilingPrefix.Contains(prefix.Addr()) {
				inside = true
				break
			}
		}
		if !inside {
			return RepositoryCloneEgress{}, ErrRepositoryEgressBlocked
		}
		policy.allowPrivateCIDRs = append(policy.allowPrivateCIDRs, prefix)
	}
	return policy, nil
}

type repositoryHostResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// ValidateRepositoryCloneURL checks the parts that require no DNS lookup, so
// API ingress can refuse a non-HTTPS clone before storing a discovery source.
// The worker repeats this check and pins every resolved address before Git.
func ValidateRepositoryCloneURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.ContainsAny(raw, "\r\n\x00") {
		return ErrRepositoryEgressBlocked
	}
	host := u.Hostname()
	if !validRepositoryCloneHost(host) {
		return ErrRepositoryEgressBlocked
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ErrRepositoryEgressBlocked
		}
	}
	return nil
}

func validRepositoryCloneHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == ""
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			digit := c >= '0' && c <= '9'
			if !letter && !digit && c != '-' {
				return false // ASCII/punycode only; no curl-resolve separators
			}
		}
	}
	return true
}

func (policy RepositoryCloneEgress) gitConfig(ctx context.Context, raw string, resolver repositoryHostResolver) ([]string, error) {
	if err := ValidateRepositoryCloneURL(raw); err != nil {
		return nil, err
	}
	u, _ := url.Parse(raw) // validated above
	host := strings.ToLower(u.Hostname())
	curlHost := host
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		curlHost = "[" + host + "]"
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := resolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		return nil, ErrRepositoryEgressBlocked
	}
	seen := map[netip.Addr]struct{}{}
	var pinned []string
	for _, address := range addresses {
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok || address.Zone != "" {
			return nil, ErrRepositoryEgressBlocked
		}
		ip = ip.Unmap()
		if !policy.allows(ip) {
			return nil, ErrRepositoryEgressBlocked
		}
		if _, duplicate := seen[ip]; duplicate {
			continue
		}
		seen[ip] = struct{}{}
		pin := ip.String()
		if ip.Is6() {
			pin = "[" + pin + "]"
		}
		pinned = append(pinned, pin)
	}
	// Git hands http.curloptResolve to libcurl for every request in this
	// process. No '+' prefix: these checked answers cannot expire mid-clone.
	return []string{"http.followRedirects", "false", "http.proxy", "",
		"http.curloptResolve", curlHost + ":" + port + ":" + strings.Join(pinned, ",")}, nil
}

func (policy RepositoryCloneEgress) allows(ip netip.Addr) bool {
	if netsec.HardBlockedIP(net.IP(ip.AsSlice())) {
		return false
	}
	if !netsec.BlockedIP(net.IP(ip.AsSlice())) {
		return true
	}
	// The operator may deliberately grant a narrow private/loopback clone
	// network. netsec's unconditional deny set stays closed even under a grant.
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return false
	}
	for _, prefix := range policy.allowPrivateCIDRs {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
