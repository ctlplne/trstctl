package acme_test

import (
	"context"
	"errors"
	"testing"

	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// The reference MemoryDNSProvider must round-trip through the real validator:
// what the solver publishes is exactly what DNS01Validator reads back. This is
// the publish-side ⇄ verify-side agreement (B9/N3) — there is no separate place
// the two can drift.
func TestDNS01SolverRoundTripsThroughValidator(t *testing.T) {
	const domain, keyAuth = "shop.example", "tok.account-thumbprint"
	provider := &acmesrv.MemoryDNSProvider{}
	solver := acmesrv.DNS01Solver{Provider: provider, Resolver: provider}

	cleanup, err := solver.Present(context.Background(), domain, keyAuth)
	if err != nil {
		t.Fatalf("present: %v", err)
	}

	v := acmesrv.DNS01Validator{Resolver: provider}
	if err := v.Validate(context.Background(), acmesrv.ChallengeDNS01, domain, "tok", keyAuth); err != nil {
		t.Fatalf("validator rejected solver's record: %v", err)
	}

	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if err := v.Validate(context.Background(), acmesrv.ChallengeDNS01, domain, "tok", keyAuth); err == nil {
		t.Fatal("validation still passed after cleanup retracted the record")
	}
}

// The solver's optional self-check must fail closed if the record never becomes
// visible (a broken provider), and must NOT leave the record behind.
func TestDNS01SolverSelfCheckFailsClosed(t *testing.T) {
	const domain, keyAuth = "shop.example", "tok.thumb"
	// A provider that silently drops PresentTXT, paired with a resolver that
	// therefore never sees the record.
	dropping := droppingProvider{}
	solver := acmesrv.DNS01Solver{Provider: dropping, Resolver: emptyResolver{}}
	if _, err := solver.Present(context.Background(), domain, keyAuth); err == nil {
		t.Fatal("expected self-check to fail when the record is not visible")
	}
}

func TestDNS01SolverPresentError(t *testing.T) {
	solver := acmesrv.DNS01Solver{Provider: erroringProvider{}}
	if _, err := solver.Present(context.Background(), "x.example", "k.t"); err == nil {
		t.Fatal("expected present error to propagate")
	}
	// No provider at all is a fail-closed error, not a nil-cleanup success.
	if _, err := (acmesrv.DNS01Solver{}).Present(context.Background(), "x.example", "k.t"); err == nil {
		t.Fatal("expected error when solver has no provider")
	}
}

// The conformance harness is the self-validation a real provider plugin runs.
// The reference provider must pass it.
func TestConformDNSProviderPasses(t *testing.T) {
	provider := &acmesrv.MemoryDNSProvider{}
	if err := acmesrv.ConformDNSProvider(context.Background(), provider, provider); err != nil {
		t.Fatalf("reference provider failed conformance: %v", err)
	}
}

// A provider that publishes nothing must FAIL conformance — proving the harness
// actually checks the published record validates, rather than rubber-stamping.
func TestConformDNSProviderCatchesNoOpProvider(t *testing.T) {
	if err := acmesrv.ConformDNSProvider(context.Background(), droppingProvider{}, emptyResolver{}); err == nil {
		t.Fatal("conformance passed a provider that publishes nothing")
	}
}

// --- test doubles --------------------------------------------------------

// droppingProvider accepts calls but stores nothing.
type droppingProvider struct{}

func (droppingProvider) PresentTXT(context.Context, string, string) error { return nil }
func (droppingProvider) CleanupTXT(context.Context, string, string) error { return nil }

// erroringProvider fails on present.
type erroringProvider struct{}

func (erroringProvider) PresentTXT(context.Context, string, string) error {
	return errors.New("zone API down")
}
func (erroringProvider) CleanupTXT(context.Context, string, string) error { return nil }

// emptyResolver never returns any record.
type emptyResolver struct{}

func (emptyResolver) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
