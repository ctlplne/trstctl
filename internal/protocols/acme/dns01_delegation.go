package acme

import (
	"context"
	"fmt"
	"strings"
)

// S8b.3 — CNAME delegation (validation-zone isolation). This lets trustctl perform
// DNS-01 without ever holding a write credential for the customer's production DNS
// zone: a one-time `_acme-challenge.<domain>` CNAME points into an isolated validation
// zone that trustctl controls (the acme-dns pattern, F71). trustctl writes the TXT only
// to the delegated target; the production zone is never touched.

// CNAMEResolver resolves the target a name is CNAME'd to. A thin adapter over
// *net.Resolver.LookupCNAME satisfies it in production; it is injectable so delegation
// is testable without real DNS.
type CNAMEResolver interface {
	LookupCNAME(ctx context.Context, name string) (cname string, err error)
}

// DelegatingProvider wraps a base DNSProvider whose credential is scoped to an isolated
// validation zone, and publishes each TXT record at the delegated target found by
// following the `_acme-challenge` CNAME. It fails closed when a name is not delegated,
// so it can never silently fall back to writing a production-zone record.
type DelegatingProvider struct {
	Base     DNSProvider   // holds only the least-privilege validation-zone credential
	Resolver CNAMEResolver // follows the _acme-challenge CNAME to its delegated target
}

var _ DNSProvider = DelegatingProvider{}

// PresentTXT follows the CNAME for name and publishes value at the delegated target.
func (d DelegatingProvider) PresentTXT(ctx context.Context, name, value string) error {
	target, err := d.target(ctx, name)
	if err != nil {
		return err
	}
	return d.Base.PresentTXT(ctx, target, value)
}

// CleanupTXT follows the CNAME for name and retracts value at the delegated target.
func (d DelegatingProvider) CleanupTXT(ctx context.Context, name, value string) error {
	target, err := d.target(ctx, name)
	if err != nil {
		return err
	}
	return d.Base.CleanupTXT(ctx, target, value)
}

func (d DelegatingProvider) target(ctx context.Context, name string) (string, error) {
	if d.Resolver == nil {
		return "", fmt.Errorf("acme: delegation requires a CNAME resolver")
	}
	cname, err := d.Resolver.LookupCNAME(ctx, name)
	if err != nil {
		return "", fmt.Errorf("acme: delegation CNAME lookup %s: %w", name, err)
	}
	cname = strings.TrimSuffix(cname, ".")
	// net.LookupCNAME returns the queried name itself when there is no CNAME; treat
	// that (or an empty answer) as "not delegated" and fail closed.
	if cname == "" || strings.EqualFold(cname, strings.TrimSuffix(name, ".")) {
		return "", fmt.Errorf("acme: %s is not delegated (no _acme-challenge CNAME to a validation zone)", name)
	}
	return cname, nil
}

// VerifyDelegation is an onboarding pre-flight (pairs with PreflightDNS01): it confirms
// `_acme-challenge.<domain>` is CNAME'd to the expected validation-zone target, so a
// missing or wrong delegation surfaces before issuance rather than at a renewal.
func VerifyDelegation(ctx context.Context, resolver CNAMEResolver, domain, wantTarget string) error {
	if resolver == nil {
		return fmt.Errorf("acme: VerifyDelegation requires a CNAME resolver")
	}
	name := DNS01RecordName(domain)
	cname, err := resolver.LookupCNAME(ctx, name)
	if err != nil {
		return fmt.Errorf("acme: delegation check %s: %w", name, err)
	}
	if !strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(wantTarget, ".")) {
		return fmt.Errorf("acme: %s is CNAME'd to %q, want %q (fix the delegation)", name, cname, wantTarget)
	}
	return nil
}
