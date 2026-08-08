// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"testing"
	"time"
)

// breakGlassService builds a licensed service with one seeded tenant and op-1
// delegated over it, ready to request and consent break-glass.
func breakGlassService(t *testing.T) *Service {
	t.Helper()
	store := NewMemStore()
	if _, err := store.CreateTenant(context.Background(),
		Tenant{ID: "tenant-x", Slug: "x", Name: "X", Status: TenantActive}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	audit := &captureAudit{}
	return NewService(Config{
		License:     providerLicense(t, 10),
		Store:       store,
		Audit:       audit,
		Telemetry:   &auditCheckingTelemetry{audit: audit},
		Clock:       fixedClock(),
		Delegations: fullyDelegated("op-1", "tenant-x"),
	})
}

func requestGrant(t *testing.T, svc *Service) BreakGlassGrant {
	t.Helper()
	grant, err := svc.RequestBreakGlass(context.Background(), providerOperator("op-1"),
		BreakGlassRequest{TenantID: "tenant-x", Reason: "incident 7", TTL: time.Hour})
	if err != nil {
		t.Fatalf("request break-glass: %v", err)
	}
	return grant
}

// Two-person control: a single approval leaves the grant awaiting a co-approver
// and opens nothing; a distinct second approval activates it.
func TestBreakGlassRequiresTwoDistinctApprovers(t *testing.T) {
	ctx := context.Background()
	svc := breakGlassService(t)
	op := providerOperator("op-1")
	grant := requestGrant(t, svc)

	g, err := svc.ConsentBreakGlass(ctx, "tenant-x", grant.ID, "approver-a", true)
	if err != nil {
		t.Fatalf("first consent: %v", err)
	}
	if st := g.State(fixedClock()()); st != GrantAwaitingCoConsent {
		t.Fatalf("state after one consent = %q, want awaiting_co_consent", st)
	}
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, ErrBreakGlassNotConsented) {
		t.Fatalf("access after one consent = %v, want refused", err)
	}

	g, err = svc.ConsentBreakGlass(ctx, "tenant-x", grant.ID, "approver-b", true)
	if err != nil {
		t.Fatalf("second consent: %v", err)
	}
	if st := g.State(fixedClock()()); st != GrantActive {
		t.Fatalf("state after two consents = %q, want active", st)
	}
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); err != nil {
		t.Fatalf("access after two consents: %v", err)
	}
}

// The requester cannot approve their own request — the person asking for
// emergency access is not one of the two independent approvers it requires.
func TestBreakGlassRequesterCannotApprove(t *testing.T) {
	ctx := context.Background()
	svc := breakGlassService(t)
	grant := requestGrant(t, svc) // requester is op-1

	if _, err := svc.ConsentBreakGlass(ctx, "tenant-x", grant.ID, "op-1", true); !errors.Is(err, ErrBreakGlassConsentByRequester) {
		t.Fatalf("requester self-approval = %v, want ErrBreakGlassConsentByRequester", err)
	}
}

// One operator cannot satisfy both consents. Removing the distinctness check
// would let a single approver activate a grant alone, which is the whole thing
// two-person control exists to prevent.
func TestBreakGlassCoConsentMustBeDistinct(t *testing.T) {
	ctx := context.Background()
	svc := breakGlassService(t)
	op := providerOperator("op-1")
	grant := requestGrant(t, svc)

	if _, err := svc.ConsentBreakGlass(ctx, "tenant-x", grant.ID, "approver-a", true); err != nil {
		t.Fatalf("first consent: %v", err)
	}
	if _, err := svc.ConsentBreakGlass(ctx, "tenant-x", grant.ID, "approver-a", true); !errors.Is(err, ErrBreakGlassConsentNotDistinct) {
		t.Fatalf("same approver twice = %v, want ErrBreakGlassConsentNotDistinct", err)
	}
	// The grant is still only singly-consented, so access stays refused.
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, ErrBreakGlassNotConsented) {
		t.Fatalf("access after a rejected double-consent = %v, want refused", err)
	}
}

// A denial by the second approver, after the first has consented, stops the
// grant — one refusal is enough even once another has approved.
func TestBreakGlassSecondApproverCanDeny(t *testing.T) {
	ctx := context.Background()
	svc := breakGlassService(t)
	op := providerOperator("op-1")
	grant := requestGrant(t, svc)

	if _, err := svc.ConsentBreakGlass(ctx, "tenant-x", grant.ID, "approver-a", true); err != nil {
		t.Fatalf("first consent: %v", err)
	}
	g, err := svc.ConsentBreakGlass(ctx, "tenant-x", grant.ID, "approver-b", false)
	if err != nil {
		t.Fatalf("second-approver denial: %v", err)
	}
	if st := g.State(fixedClock()()); st != GrantDenied {
		t.Fatalf("state after denial = %q, want denied", st)
	}
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); err == nil {
		t.Fatal("a denied grant still granted access")
	}
}
