package acme

import (
	"context"
	"fmt"
)

// Validators routes a challenge to the validator for its type. It is the
// production validator: each of the three DV methods is validated for real, and
// an unconfigured or unknown method fails closed — there is no
// accept-everything path.
type Validators struct {
	HTTP01    Validator
	DNS01     Validator
	TLSALPN01 Validator
}

// DefaultValidators wires the real validators for all three DV methods (HTTP-01,
// DNS-01, TLS-ALPN-01), each with its default network seam.
func DefaultValidators() Validators {
	return Validators{
		HTTP01:    HTTP01Validator{},
		DNS01:     DNS01Validator{},
		TLSALPN01: TLSALPN01Validator{},
	}
}

// Validate dispatches to the per-type validator. An unknown type, or a type
// whose validator is not configured, is an error (fail closed).
func (m Validators) Validate(ctx context.Context, challengeType, domain, token, keyAuth string) error {
	var v Validator
	switch challengeType {
	case ChallengeHTTP01:
		v = m.HTTP01
	case ChallengeDNS01:
		v = m.DNS01
	case ChallengeTLSALPN01:
		v = m.TLSALPN01
	default:
		return fmt.Errorf("acme: unknown challenge type %q", challengeType)
	}
	if v == nil {
		return fmt.Errorf("acme: %s validation is not configured (fail closed)", challengeType)
	}
	return v.Validate(ctx, challengeType, domain, token, keyAuth)
}

// MethodContext describes what is known about an identifier, so the right DV
// method can be selected automatically (S8b.13).
type MethodContext struct {
	Domain          string // the identifier, e.g. "example.com" or "*.example.com"
	Wildcard        bool   // a wildcard identifier (only DNS-01 can issue these)
	Port80Reachable bool   // can the CA reach :80 for HTTP-01?
	DNSManaged      bool   // can trstctl publish the DNS-01 TXT record?
	Override        string // explicit method from profile/policy; wins when set
}

// SelectMethod chooses the domain-validation method by context and returns the
// method plus a human-readable rationale to record in the audit trail (AN-2):
// DNS-01 for wildcards, TLS-ALPN-01 where port 80 is closed, HTTP-01 otherwise —
// overridable by profile/policy. It fails closed when no method can satisfy the
// request.
func SelectMethod(c MethodContext) (method, rationale string, err error) {
	if c.Override != "" {
		if !knownMethod(c.Override) {
			return "", "", fmt.Errorf("acme: unknown DV method override %q", c.Override)
		}
		return c.Override, "policy/profile override", nil
	}
	switch {
	case c.Wildcard:
		if !c.DNSManaged {
			return "", "", fmt.Errorf("acme: wildcard %q requires DNS-01, but the zone is not managed", c.Domain)
		}
		return ChallengeDNS01, "wildcard identifier — only DNS-01 can issue wildcards", nil
	case !c.Port80Reachable:
		if c.DNSManaged {
			return ChallengeDNS01, "port 80 unreachable and DNS managed — DNS-01", nil
		}
		return ChallengeTLSALPN01, "port 80 unreachable — TLS-ALPN-01 over :443", nil
	default:
		return ChallengeHTTP01, "publicly reachable host — HTTP-01", nil
	}
}

func knownMethod(m string) bool {
	switch m {
	case ChallengeHTTP01, ChallengeDNS01, ChallengeTLSALPN01:
		return true
	default:
		return false
	}
}
