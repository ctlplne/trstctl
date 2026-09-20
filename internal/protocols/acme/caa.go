// SPDX-License-Identifier: BUSL-1.1

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

// CAAInspection is the operator-safe evidence behind one CAA decision. Records are
// public DNS policy, not credentials. GoverningName is empty only when the complete
// tree walk found no CAA record set; on lookup failure it identifies the exact name
// whose answer could not be trusted.
type CAAInspection struct {
	GoverningName  string
	Records        []CAARecord
	RelevantTag    string
	AllowedIssuers []string
	Unrestricted   bool
	Authorized     bool
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
	_, err := c.Inspect(ctx, domain, wildcard)
	return err
}

// Inspect applies the same fail-closed decision as Check and also returns the public
// DNS facts that explain it. A caller may safely display the returned evidence even
// when err is non-nil; Authorized remains false for both a policy denial and a lookup
// failure.
func (c CAAChecker) Inspect(ctx context.Context, domain string, wildcard bool) (CAAInspection, error) {
	inspection := CAAInspection{RelevantTag: "issue"}
	if wildcard {
		inspection.RelevantTag = "issuewild"
	}
	if c.Resolver == nil {
		return inspection, fmt.Errorf("acme: CAA check requires a resolver")
	}
	labels := strings.Split(strings.TrimSuffix(strings.TrimPrefix(domain, "*."), "."), ".")
	for i := 0; i < len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		inspection.GoverningName = name
		records, err := c.Resolver.LookupCAA(ctx, name)
		if err != nil {
			return inspection, fmt.Errorf("acme: CAA lookup %s: %w", name, err)
		}
		if len(records) == 0 {
			continue // walk up to the parent
		}
		inspection.Records = append([]CAARecord(nil), records...)
		return c.evaluateInspection(inspection, wildcard)
	}
	inspection.GoverningName = ""
	inspection.Unrestricted = true
	inspection.Authorized = true
	return inspection, nil // no CAA anywhere up the tree => unrestricted
}

func (c CAAChecker) evaluateInspection(inspection CAAInspection, wildcard bool) (CAAInspection, error) {
	var issue, issuewild []CAARecord
	for _, r := range inspection.Records {
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
		inspection.RelevantTag = "issuewild"
	} else {
		inspection.RelevantTag = "issue"
	}
	for _, r := range relevant {
		issuer := caaIssuer(r.Value)
		if issuer != "" {
			inspection.AllowedIssuers = appendUniqueFold(inspection.AllowedIssuers, issuer)
		}
	}
	if len(relevant) == 0 {
		return inspection, fmt.Errorf("acme: CAA at %s authorizes no issuer for this request", inspection.GoverningName)
	}
	for _, r := range relevant {
		if c.authorizes(r.Value) {
			inspection.Authorized = true
			return inspection, nil
		}
	}
	return inspection, fmt.Errorf("acme: CAA at %s does not authorize issuer %q", inspection.GoverningName, c.IssuerDomain)
}

// authorizes parses a CAA issue/issuewild property value ("ca.example; account=1") and
// reports whether it names this issuer. A value of ";" (empty issuer) forbids all
// issuance (RFC 8659 §4.2).
func (c CAAChecker) authorizes(value string) bool {
	field := caaIssuer(value)
	if field == "" {
		return false
	}
	return strings.EqualFold(field, c.IssuerDomain)
}

func caaIssuer(value string) string {
	field := strings.TrimSpace(value)
	if i := strings.IndexByte(field, ';'); i >= 0 {
		field = strings.TrimSpace(field[:i])
	}
	return field
}

func appendUniqueFold(values []string, candidate string) []string {
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return values
		}
	}
	return append(values, candidate)
}
