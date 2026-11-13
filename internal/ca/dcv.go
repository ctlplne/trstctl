// SPDX-License-Identifier: BUSL-1.1

package ca

import (
	"context"
	"strings"
	"time"
)

// DefaultDCVTimeout bounds how long a vendor's domain validation is waited
// for once its records are published (A165-L4).
const DefaultDCVTimeout = 10 * time.Minute

// maxDCVBackoff caps the spacing between a vendor's validation checks.
const maxDCVBackoff = 30 * time.Second

// DCVBackoff is the wait before a vendor's next validation check (A165-L4):
// it starts at first and doubles each check up to 30 seconds, so slow DNS
// propagation is waited out without asking the vendor in a tight loop.
func DCVBackoff(first time.Duration, attempt int) time.Duration {
	if first <= 0 {
		first = 500 * time.Millisecond
	}
	d := first
	for i := 0; i < attempt && d < maxDCVBackoff; i++ {
		d *= 2
	}
	if d > maxDCVBackoff {
		d = maxDCVBackoff
	}
	return d
}

// DCVBaseNames turns an order's names into the base names a vendor
// validates, in order and once each, and says which of them a wildcard asked
// for (A165-L3): "*.example.com" and "example.com" validate example.com once,
// as a wildcard.
func DCVBaseNames(dnsNames []string) ([]string, map[string]bool) {
	var bases []string
	wildcard := map[string]bool{}
	for _, name := range dnsNames {
		raw := strings.ToLower(strings.TrimSpace(name))
		base := strings.TrimPrefix(raw, "*.")
		if base == "" {
			continue
		}
		if _, ok := wildcard[base]; !ok {
			bases = append(bases, base)
			wildcard[base] = false
		}
		if raw != base {
			wildcard[base] = true
		}
	}
	return bases, wildcard
}

// TXTPublisher publishes one DNS TXT record for an authority's domain
// validation and returns its retraction (A165). Vendors whose validation is a
// TXT record of their own token at their own name (DigiCert's _dnsauth record,
// Sectigo's DCV host) use it the way ACME issuance uses its dns-01 solver; the
// server's implementation goes through the tenant's DNS-01 provider configs
// under the same consent and CAA checks as upstream ACME validation.
type TXTPublisher interface {
	PublishTXT(ctx context.Context, tenantID, identifier, recordName, value string) (retract func(context.Context) error, err error)
}

// DomainValidationMethodDNSTXT is a vendor validation proven by a TXT record
// the publisher placed.
const DomainValidationMethodDNSTXT = "dns-txt"

// DomainValidation is one identifier's validation outcome at a vendor
// authority (A165-L2), shaped like an upstream ACME authorization outcome.
type DomainValidation struct {
	Identifier string
	// Method is how it was proven; empty when Reused.
	Method string
	// Reused is true when the authority already held the identifier
	// validated and nothing was published.
	Reused bool
}

// DomainValidationObserver is implemented by a TXTPublisher that records each
// validation outcome (A165-L2), as upstream ACME issuance records its
// authorizations, so a validation the install earned and one it rode on show
// the same way at every authority.
type DomainValidationObserver interface {
	ObserveDomainValidation(ctx context.Context, tenantID string, out DomainValidation)
}

// ObserveDomainValidation reports out to p when p records outcomes.
func ObserveDomainValidation(ctx context.Context, p TXTPublisher, tenantID string, out DomainValidation) {
	if o, ok := p.(DomainValidationObserver); ok {
		o.ObserveDomainValidation(ctx, tenantID, out)
	}
}
