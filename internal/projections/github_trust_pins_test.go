// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"slices"
	"testing"
	"trstctl.com/trstctl/internal/eventstest"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/githubidentity"
	"trstctl.com/trstctl/internal/projections"
)

// CR-384: historical trust events, an ID-bearing tail and material rotation
// restore the same tenant policy as replay from the authoritative log.
func TestGitHubTrustPinsSurviveProtectedReplayAndRotation(t *testing.T) {
	ctx := t.Context()
	s := newStore(t)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	p := projections.New(s)
	appendPayload := func(tenant, kind string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{Type: kind, TenantID: tenant, Data: data})
	}
	const sourceA = "00000000-0000-4000-8000-000000038401"
	const sourceB = "00000000-0000-4000-8000-000000038402"
	const ownerID = "9007199254740993"
	legacy := projections.WorkloadAttesterTrustSourceUpserted{
		ID: sourceA, Name: "workflow", Method: "github_oidc", Audience: "trstctl",
		JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true, SelfAuthenticating: true, AllowedOwners: []string{"acme"},
	}
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Pin tenant")})
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantB, Data: tenantRegistered("Legacy tenant")})
	appendPayload(tenantA, projections.EventWorkloadAttesterTrustSourceUpserted, legacy)
	neighbor := legacy
	neighbor.ID = sourceB
	appendPayload(tenantB, projections.EventWorkloadAttesterTrustSourceUpserted, neighbor)
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if count, err := p.Snapshot(ctx); err != nil || count != 2 {
		t.Fatalf("snapshots = %d, error %v, want both tenants", count, err)
	}

	pinned := legacy
	pinned.AllowedOwnerIDs = []string{ownerID}
	pinned.AllowedRepositoryIDs = []string{"456"}
	data, err := json.Marshal(pinned)
	if err != nil {
		t.Fatal(err)
	}
	// Trust event history uses reject-only privacy treatment. A subject
	// collision must stop the rewrite rather than change an authorization pin.
	if _, _, err := events.PseudonymizeEventDataForSubject(data, tenantA, ownerID, projections.EventWorkloadAttesterTrustSourceUpserted, 1); err == nil {
		t.Fatal("privacy rewrite accepted a subject collision with an authorization pin")
	}
	appendPayload(tenantA, projections.EventWorkloadAttesterTrustSourceUpserted, pinned)
	appendPayload(tenantA, projections.EventWorkloadAttesterTrustSourceRotated, projections.WorkloadAttesterTrustSourceRotated{
		ID: sourceA, Issuer: githubidentity.DefaultIssuer, Audience: "trstctl", JWKS: legacy.JWKS, RotationVersion: 2,
	})
	check := func() {
		t.Helper()
		active, err := s.GetEffectiveWorkloadAttesterTrustSource(ctx, tenantA, sourceA)
		if err != nil {
			t.Fatal(err)
		}
		if active.RotationVersion != 2 || active.Issuer != githubidentity.DefaultIssuer || active.RequiresImmutableGitHubPin() ||
			!slices.Equal(active.AllowedOwnerIDs, pinned.AllowedOwnerIDs) || !slices.Equal(active.AllowedRepositoryIDs, pinned.AllowedRepositoryIDs) {
			t.Fatal("projected source lost its pins or rotated issuer")
		}
		old, err := s.GetEffectiveWorkloadAttesterTrustSource(ctx, tenantB, sourceB)
		if err != nil || !old.RequiresImmutableGitHubPin() {
			t.Fatalf("neighbor legacy source needs pin remediation, error %v", err)
		}
	}
	truncateReadModelAndCheckpoint(t, s)
	if restored, err := p.RestoreFromSnapshot(ctx, log); err != nil || !restored {
		t.Fatalf("restore and tail replay = %t, error %v", restored, err)
	}
	check()
	if err := s.DeleteAllSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	check()
}
