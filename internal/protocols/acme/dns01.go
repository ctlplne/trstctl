package acme

import (
	"context"
	"fmt"
	"net"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

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
