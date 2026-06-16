package acme_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/protocols/acme"
)

// TestWildcardSolvesAtBaseName proves a wildcard request is satisfied end-to-end via
// DNS-01 by publishing the TXT at the base name (the `*.` label is stripped), so the
// same validator that handles any domain validates the wildcard.
func TestWildcardSolvesAtBaseName(t *testing.T) {
	ctx := context.Background()
	const wildcard, keyAuth = "*.example.com", "tok.thumb"
	baseName := acme.DNS01RecordName(wildcard) // _acme-challenge.example.com
	if baseName != "_acme-challenge.example.com" {
		t.Fatalf("wildcard record name = %q, want _acme-challenge.example.com", baseName)
	}
	mem := &acme.MemoryDNSProvider{}
	solver := acme.DNS01Solver{Provider: mem, Resolver: mem}
	cleanup, err := solver.Present(ctx, wildcard, keyAuth)
	if err != nil {
		t.Fatalf("Present(%q): %v", wildcard, err)
	}
	v := acme.DNS01Validator{Resolver: mem}
	if err := v.Validate(ctx, acme.ChallengeDNS01, wildcard, "token", keyAuth); err != nil {
		t.Errorf("wildcard did not validate via DNS-01: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if err := v.Validate(ctx, acme.ChallengeDNS01, wildcard, "token", keyAuth); err == nil {
		t.Error("validation still succeeded after cleanup")
	}
}

func TestWildcardRefusedByProfile(t *testing.T) {
	if err := (acme.WildcardPolicy{AllowWildcards: false}).CheckWildcard("*.example.com", acme.ChallengeDNS01); err == nil {
		t.Error("wildcard must be refused when the profile forbids it")
	}
	if err := (acme.WildcardPolicy{AllowWildcards: true}).CheckWildcard("*.example.com", acme.ChallengeDNS01); err != nil {
		t.Errorf("wildcard should be allowed when the profile permits it: %v", err)
	}
}

func TestWildcardRequiresDNS01(t *testing.T) {
	if err := (acme.WildcardPolicy{AllowWildcards: true}).CheckWildcard("*.example.com", acme.ChallengeHTTP01); err == nil {
		t.Error("a wildcard must require dns-01 validation")
	}
}

func TestNonWildcardAlwaysAllowed(t *testing.T) {
	if err := (acme.WildcardPolicy{AllowWildcards: false}).CheckWildcard("example.com", acme.ChallengeHTTP01); err != nil {
		t.Errorf("a non-wildcard request must always pass the wildcard gate: %v", err)
	}
}
