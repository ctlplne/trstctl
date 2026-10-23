// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// A95: tenant-scoped break-glass with dual consent. When the customer's own
// policy requires its consent, two Provider approvals open nothing until the
// customer has recorded the configured number of distinct approvals for the
// grant and no denial; a denial closes it; a customer without such a policy
// keeps the two-custodian rule alone.
type fakeTenantConsent struct {
	require   bool
	approvals int
	decisions map[string][]TenantConsentDecision
}

func (f *fakeTenantConsent) TenantConsentPolicy(context.Context, string) (TenantConsentPolicy, error) {
	return TenantConsentPolicy{RequireTenantConsent: f.require, Approvals: f.approvals}, nil
}

func (f *fakeTenantConsent) TenantConsentDecisions(_ context.Context, _ string, grantID string) ([]TenantConsentDecision, error) {
	return f.decisions[grantID], nil
}

func TestBreakGlassResultsHonourTenantDualConsentA95(t *testing.T) {
	ctx := context.Background()
	consent := &fakeTenantConsent{require: true, approvals: 2, decisions: map[string][]TenantConsentDecision{}}
	svc := breakGlassService(t)
	svc.tenantConsent = consent
	op := providerOperator("op-1")
	grant := requestGrant(t, svc)
	for _, approver := range []string{"approver-a", "approver-b"} {
		if _, err := svc.ConsentBreakGlass(ctx, providerOperator(approver), "tenant-x", grant.ID, true); err != nil {
			t.Fatalf("provider consent %s: %v", approver, err)
		}
	}
	// Two Provider custodians approved; the customer has not.
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, ErrBreakGlassTenantConsentPending) {
		t.Fatalf("results before tenant consent = %v, want pending", err)
	}
	page, err := svc.ListBreakGlassGrants(ctx, op, "tenant-x", 10, "")
	if err != nil || len(page.Items) != 1 || !page.Items[0].TenantConsentRequired || page.Items[0].TenantApprovals != 0 {
		t.Fatalf("queue view = %+v %v, want tenant consent required with 0 approvals", page, err)
	}
	consent.decisions[grant.ID] = []TenantConsentDecision{{Subject: "alice@customer.test", Approve: true, DecidedAt: time.Now()}}
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, ErrBreakGlassTenantConsentPending) {
		t.Fatalf("results after one tenant approval = %v, want pending", err)
	}
	consent.decisions[grant.ID] = append(consent.decisions[grant.ID], TenantConsentDecision{Subject: "alice@customer.test", Approve: true, DecidedAt: time.Now()})
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, ErrBreakGlassTenantConsentPending) {
		t.Fatalf("results with the same subject twice = %v, want pending (distinct subjects count)", err)
	}
	consent.decisions[grant.ID] = append(consent.decisions[grant.ID], TenantConsentDecision{Subject: "bob@customer.test", Approve: true, DecidedAt: time.Now()})
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); err != nil {
		t.Fatalf("results after two distinct tenant approvals: %v", err)
	}
	page, _ = svc.ListBreakGlassGrants(ctx, op, "tenant-x", 10, "")
	if len(page.Items) != 1 || page.Items[0].TenantApprovals != 2 || page.Items[0].TenantDenied {
		t.Fatalf("queue view after approvals = %+v", page.Items)
	}
	consent.decisions[grant.ID] = append(consent.decisions[grant.ID], TenantConsentDecision{Subject: "carol@customer.test", Approve: false, Reason: "no", DecidedAt: time.Now()})
	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, ErrBreakGlassTenantDenied) {
		t.Fatalf("results after a tenant denial = %v, want denied", err)
	}
	page, _ = svc.ListBreakGlassGrants(ctx, op, "tenant-x", 10, "")
	if len(page.Items) != 1 || !page.Items[0].TenantDenied {
		t.Fatalf("queue view after denial = %+v", page.Items)
	}

	// A customer without the policy keeps the two-custodian rule alone.
	consent.require = false
	second := requestGrant(t, svc)
	for _, approver := range []string{"approver-a", "approver-b"} {
		if _, err := svc.ConsentBreakGlass(ctx, providerOperator(approver), "tenant-x", second.ID, true); err != nil {
			t.Fatalf("provider consent %s: %v", approver, err)
		}
	}
	if _, err := svc.BreakGlassResults(ctx, op, second.ID); err != nil {
		t.Fatalf("results without a tenant policy: %v", err)
	}
}

// A95: the Provider's request event, folded by the authority projection,
// lands in the customer's own request table so the customer can decide on it;
// the rebuild writes it the same way.
func TestProviderRequestProjectsIntoTheCustomersRequestTableA95(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	mutations := NewEventMutationSink(log, NewAuthorityProjection(st))
	customer := CustomerID("consent-request-test")
	now := time.Date(2026, 10, 23, 7, 0, 0, 0, time.UTC)
	grant := BreakGlassGrant{ID: "consent-request-grant", TenantID: customer, OperatorID: "requester", OperatorEmail: "oncall@provider.example",
		Reason: "incident 9", RequestedAt: now, ExpiresAt: now.Add(time.Hour)}
	if _, err := mutations.Append(ctx, "request", AuditBreakGlassRequested, customer, AuthorityEvent{Grant: &grant,
		Audit: AuditEvent{Type: AuditBreakGlassRequested, TenantID: customer, OperatorID: "requester", GrantID: grant.ID, Reason: grant.Reason, At: now}}); err != nil {
		t.Fatal(err)
	}
	requests, err := st.ProviderAccessRequestsFor(ctx, customer, now.Add(time.Minute))
	if err != nil || len(requests) != 1 || requests[0].GrantID != grant.ID || requests[0].OperatorEmail != "oncall@provider.example" || requests[0].Reason != "incident 9" {
		t.Fatalf("customer request rows = %+v %v, want the Provider's request under the customer", requests, err)
	}
	if expired, err := st.ProviderAccessRequestsFor(ctx, customer, now.Add(2*time.Hour)); err != nil || len(expired) != 0 {
		t.Fatalf("expired request still listed = %+v %v", expired, err)
	}
}
