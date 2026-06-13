package acme

import (
	"context"
	"fmt"
	"strings"
)

// S8b.4 — CAA awareness. A pre-issuance CAA check (RFC 8659) so issuance fails fast and
// clearly when the chosen CA is not authorized for the domain, rather than with a
// confusing downstream rejection. The check is the DNS record almost every automation
// forgets; it composes on top of profiles (S8.1).

// CAARecord is one CAA resource record.
type CAARecord struct {
	Flag  uint8
	Tag   string // "issue", "issuewild", or "iodef"
	Value string
}

// CAAResolver looks up the CAA record set at exactly one name (no tree walking). Go's
// stdlib net.Resolver has no LookupCAA, so production supplies a DNS-library-backed
// implementation; the checker logic is resolver-agnostic and fully testable.
type CAAResolver interface {
	LookupCAA(ctx context.Context, name string) ([]CAARecord, error)
}

// CAAChecker performs the pre-issuance CAA check: issuance is permitted only if the CAA
// policy for the domain authorizes the configured issuer. It walks from the FQDN up
// toward the apex and applies the first level that publishes a CAA set (RFC 8659 §3).
// No CAA anywhere means unrestricted. It fails closed on a lookup error.
type CAAChecker struct {
	Resolver     CAAResolver
	IssuerDomain string // the CA identifier matched against issue/issuewild values
}

// Check reports whether the configured issuer may issue for domain. For a wildcard
// request, issuewild (if present at the governing level) takes precedence over issue
// (RFC 8659 §4.3).
func (c CAAChecker) Check(ctx context.Context, domain string, wildcard bool) error {
	if c.Resolver == nil {
		return fmt.Errorf("acme: CAA check requires a resolver")
	}
	labels := strings.Split(strings.TrimSuffix(strings.TrimPrefix(domain, "*."), "."), ".")
	for i := 0; i < len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		records, err := c.Resolver.LookupCAA(ctx, name)
		if err != nil {
			return fmt.Errorf("acme: CAA lookup %s: %w", name, err)
		}
		if len(records) == 0 {
			continue // walk up to the parent
		}
		return c.evaluate(name, records, wildcard)
	}
	return nil // no CAA anywhere up the tree => unrestricted
}

func (c CAAChecker) evaluate(name string, records []CAARecord, wildcard bool) error {
	var issue, issuewild []CAARecord
	for _, r := range records {
		switch strings.ToLower(r.Tag) {
		case "issue":
			issue = append(issue, r)
		case "issuewild":
			issuewild = append(issuewild, r)
		}
	}
	relevant := issue
	if wildcard && len(issuewild) > 0 {
		relevant = issuewild
	}
	if len(relevant) == 0 {
		return fmt.Errorf("acme: CAA at %s authorizes no issuer for this request", name)
	}
	for _, r := range relevant {
		if c.authorizes(r.Value) {
			return nil
		}
	}
	return fmt.Errorf("acme: CAA at %s does not authorize issuer %q", name, c.IssuerDomain)
}

// authorizes parses a CAA issue/issuewild property value ("ca.example; account=1") and
// reports whether it names this issuer. A value of ";" (empty issuer) forbids all
// issuance (RFC 8659 §4.2).
func (c CAAChecker) authorizes(value string) bool {
	field := strings.TrimSpace(value)
	if i := strings.IndexByte(field, ';'); i >= 0 {
		field = strings.TrimSpace(field[:i])
	}
	if field == "" {
		return false
	}
	return strings.EqualFold(field, c.IssuerDomain)
}
