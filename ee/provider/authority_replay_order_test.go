// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

func authorityReplayFixture(t *testing.T, options ...events.OpenOption) (*corestore.Store, *events.Log, *EventMutationSink) {
	t.Helper()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true}, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return st, log, NewEventMutationSink(log, NewAuthorityProjection(st))
}

func TestProviderAuthorityReplayCannotUndoLaterDecisions(t *testing.T) {
	t.Run("revoked grant survives an identical retry through a restarted command", func(t *testing.T) {
		st, log, sink := authorityReplayFixture(t)
		customer := CustomerID("revoked-grant-replay")
		now := time.Now().UTC()
		grant := AuthorityEvent{Delegation: &DelegationMutation{
			OperatorID: "operator-1", CustomerID: customer, Operation: OpRead, GrantedBy: "admin",
		}, EffectiveAt: now}
		first, err := sink.Append(t.Context(), "grant-1", EventDelegationGranted, customer, grant)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sink.Append(t.Context(), "revoke-1", EventDelegationRevoked, customer, grant); err != nil {
			t.Fatal(err)
		}
		assertReplayAuthority(t, st, "operator-1", customer, false)
		restarted := NewEventMutationSink(log, NewAuthorityProjection(st))
		retry, err := restarted.Append(t.Context(), "grant-1", EventDelegationGranted, customer, grant)
		if err != nil {
			t.Fatal(err)
		}
		if retry.ID != first.ID || retry.Sequence != first.Sequence {
			t.Fatal("retry minted a different authority event")
		}
		assertReplayAuthority(t, st, "operator-1", customer, false)
	})
	t.Run("old revoke cannot remove a later explicitly regranted operation", func(t *testing.T) {
		st, _, sink := authorityReplayFixture(t)
		customer := CustomerID("regrant-replay")
		payload := AuthorityEvent{Delegation: &DelegationMutation{
			OperatorID: "operator-1", CustomerID: customer, Operation: OpRead,
		}, EffectiveAt: time.Now().UTC()}
		if _, err := sink.Append(t.Context(), "grant-1", EventDelegationGranted, customer, payload); err != nil {
			t.Fatal(err)
		}
		revoked, err := sink.Append(t.Context(), "revoke-1", EventDelegationRevoked, customer, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sink.Append(t.Context(), "grant-2", EventDelegationGranted, customer, payload); err != nil {
			t.Fatal(err)
		}
		assertReplayAuthority(t, st, "operator-1", customer, true)
		if err := NewAuthorityProjection(st).Apply(t.Context(), revoked); err != nil {
			t.Fatal(err)
		}
		assertReplayAuthority(t, st, "operator-1", customer, true)
	})
	t.Run("old identity projection cannot reactivate a leaver", func(t *testing.T) {
		st, _, sink := authorityReplayFixture(t)
		now := time.Now().UTC()
		identity := OperatorIdentity{ID: "operator-1", ExternalID: "subject-1", UserName: "worker",
			Role: OperatorAdmin, Active: true, Source: "scim:test", CreatedAt: now, UpdatedAt: now}
		active, err := sink.Append(t.Context(), "join-1", EventOperatorUpserted, providerAuthorityTenant,
			AuthorityEvent{Operator: &identity, EffectiveAt: now})
		if err != nil {
			t.Fatal(err)
		}
		identity.Active, identity.DeprovisionedAt = false, now
		if _, err := sink.Append(t.Context(), "leave-1", EventOperatorOffboarded, providerAuthorityTenant,
			AuthorityEvent{Operator: &identity, EffectiveAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := NewAuthorityProjection(st).Apply(t.Context(), active); err != nil {
			t.Fatal(err)
		}
		got, err := NewPGAccessStore(st).ResolveOperator(t.Context(), identity.ExternalID)
		if err != nil || got.Active || got.DeprovisionedAt.IsZero() {
			t.Fatalf("stale join changed the leaver: %+v, %v", got, err)
		}
	})
	t.Run("old customer projection cannot undo suspension", func(t *testing.T) {
		st, _, sink := authorityReplayFixture(t)
		now := time.Now().UTC()
		tenant := Tenant{ID: CustomerID("suspended-replay"), Slug: "suspended-replay", Name: "Suspended customer",
			Status: TenantActive, CreatedAt: now, UpdatedAt: now}
		active, err := sink.Append(t.Context(), "provision-1", AuditTenantProvisioned, tenant.ID,
			AuthorityEvent{Tenant: &tenant, EffectiveAt: now})
		if err != nil {
			t.Fatal(err)
		}
		tenant.Status = TenantSuspended
		if _, err := sink.Append(t.Context(), "suspend-1", AuditTenantSuspended, tenant.ID,
			AuthorityEvent{Tenant: &tenant, EffectiveAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := NewAuthorityProjection(st).Apply(t.Context(), active); err != nil {
			t.Fatal(err)
		}
		got, err := NewPGStore(st).Tenant(t.Context(), tenant.ID)
		if err != nil || got.Status != TenantSuspended {
			t.Fatalf("stale provision changed suspension: %+v, %v", got, err)
		}
	})
}

func assertReplayAuthority(t *testing.T, st *corestore.Store, operator, customer string, allowed bool) {
	t.Helper()
	set, err := NewPGDelegationSource(st).Delegations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Authorize(Operator{ID: operator}, customer, OpRead); (err == nil) != allowed {
		t.Fatalf("authority allowed=%v, want %v: %v", err == nil, allowed, err)
	}
}
