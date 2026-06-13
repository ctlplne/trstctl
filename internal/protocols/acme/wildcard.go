package acme

import (
	"fmt"
	"strings"
)

// S8b.14 — automated wildcard issuance & renewal. Wildcards (`*.example.com`) are the
// one capability that is DNS-01-exclusive: no other validation method can satisfy a
// wildcard (RFC 8555 §7.1.1, §8.4). The DNS-01 record for a wildcard is published at the
// base name (DNS01RecordName already strips the `*.` label), so wildcard issuance and
// renewal ride the very same solver, lifecycle, drift, and audit machinery as any other
// certificate. The only wildcard-specific control is governance: wildcards are powerful,
// so a profile/policy must explicitly permit them (S8.1).

// IsWildcard reports whether an identifier is a wildcard request.
func IsWildcard(domain string) bool { return strings.HasPrefix(domain, "*.") }

// WildcardPolicy is the per-profile governance decision for wildcard requests.
type WildcardPolicy struct {
	// AllowWildcards permits `*.<domain>` issuance under the bound profile. Default false:
	// wildcards are refused unless a profile opts in.
	AllowWildcards bool
}

// CheckWildcard enforces wildcard governance for a requested identifier and validation
// method. A non-wildcard request always passes. A wildcard request is refused unless the
// bound profile allows it, and (because only DNS-01 can satisfy a wildcard) unless the
// method is dns-01.
func (p WildcardPolicy) CheckWildcard(domain, method string) error {
	if !IsWildcard(domain) {
		return nil
	}
	if !p.AllowWildcards {
		return fmt.Errorf("acme: wildcard issuance for %q is not permitted by the bound profile", domain)
	}
	if method != ChallengeDNS01 {
		return fmt.Errorf("acme: wildcard %q requires dns-01 validation, not %q", domain, method)
	}
	return nil
}
