// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// ErrNoDNS01ProviderConfig is returned when an ACME order needs a DNS-01 record
// for a name that no tenant DNS-01 provider config covers. It is a sentinel so
// callers can classify the failure (a missing prerequisite an operator can add)
// without inspecting error text.
var ErrNoDNS01ProviderConfig = errors.New("acme: no served dns-01 provider config matches the requested name")

// DNS01ZoneCovers reports whether a provider config declared for zone (or its
// challenge delegation domain) is allowed to publish the _acme-challenge record
// for domain. It is the single matching rule shared by order-time automation,
// the endpoint-lifecycle preview, and preflight checks, so a prerequisite that
// the preview accepts cannot be rejected later at issuance time.
func DNS01ZoneCovers(zone, challengeDomain, domain string) bool {
	base := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*."), ".")
	if base == "" {
		return false
	}
	recordName := strings.TrimSuffix(strings.ToLower(DNS01RecordName(domain)), ".")
	for _, candidate := range []string{zone, challengeDomain} {
		candidate = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(candidate)), ".")
		if candidate == "" {
			continue
		}
		if base == candidate || strings.HasSuffix(base, "."+candidate) {
			return true
		}
		if recordName == candidate || strings.HasSuffix(recordName, "."+candidate) {
			return true
		}
	}
	return false
}

// Resolver looks up TXT records; *net.Resolver satisfies it. It is an injectable
// seam so the DNS-01 validator can be tested without real DNS.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DNS01Validator validates dns-01 challenges (RFC 8555 §8.4): the
// `_acme-challenge` TXT record for the identifier must contain the unpadded
// base64url SHA-256 digest of the key authorization. It fails closed — a missing
// record, a lookup error, or a mismatch is an error. Resolver defaults to the
// system resolver.
type DNS01Validator struct {
	Resolver Resolver
}

// Validate performs the dns-01 check.
func (v DNS01Validator) Validate(ctx context.Context, challengeType, domain, token, keyAuth string) error {
	if challengeType != ChallengeDNS01 {
		return fmt.Errorf("acme: DNS01Validator cannot validate %q", challengeType)
	}
	resolver := v.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	name := DNS01RecordName(domain)
	want := crypto.SHA256Base64URL([]byte(keyAuth))
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return fmt.Errorf("acme: dns-01 lookup %s: %w", name, err)
	}
	for _, r := range records {
		if strings.TrimSpace(r) == want {
			return nil
		}
	}
	return fmt.Errorf("acme: dns-01 TXT for %s did not contain the expected authorization", name)
}

// DNS01RecordName returns the validation record name for a domain
// (`_acme-challenge.<base>`), stripping a leading wildcard label so that
// `*.example.com` validates at `_acme-challenge.example.com` (RFC 8555 §8.4).
func DNS01RecordName(domain string) string {
	return "_acme-challenge." + strings.TrimPrefix(domain, "*.")
}

// DNS01RecordValue returns the TXT record value a dns-01 challenge expects for
// the given key authorization (the base64url SHA-256 digest). Solvers publish
// this; the validator checks it.
func DNS01RecordValue(keyAuth string) string {
	return crypto.SHA256Base64URL([]byte(keyAuth))
}
