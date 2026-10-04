// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestProviderRegrantRetainsRevokedEpisodeThroughRebuild(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	operatorID, customerID := "history-operator", CustomerID("history-customer")
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	identity := OperatorIdentity{ID: operatorID, ExternalID: "history@example.test", UserName: "history@example.test",
		Email: "history@example.test", Role: OperatorAdmin, Active: true, Source: "scim:qa", CreatedAt: now, UpdatedAt: now}
	appendEvent := func(key, typ, tenant string, at time.Time, payload AuthorityEvent) {
		t.Helper()
		payload.EffectiveAt = at
		payload.Audit = AuditEvent{Type: typ, TenantID: tenant, OperatorID: "scim:qa", At: at}
		if _, err := runtime.Mutations.Append(ctx, key, typ, tenant, payload); err != nil {
			t.Fatalf("append %s: %v", typ, err)
		}
	}
	appendEvent("history-join", EventOperatorUpserted, providerAuthorityTenant, now, AuthorityEvent{Operator: &identity})
	delegation := DelegationMutation{OperatorID: operatorID, CustomerID: customerID, Operation: OpRead, GrantedBy: "admin", Source: "scim"}
	appendEvent("history-grant-1", EventDelegationGranted, customerID, now.Add(time.Minute), AuthorityEvent{Delegation: &delegation})
	identity.Active = false
	identity.UpdatedAt = now.Add(2 * time.Minute)
	identity.DeprovisionedAt = identity.UpdatedAt
	appendEvent("history-leaver", EventOperatorOffboarded, providerAuthorityTenant, identity.UpdatedAt, AuthorityEvent{Operator: &identity})
	identity.Active = true
	identity.UpdatedAt = now.Add(3 * time.Minute)
	identity.DeprovisionedAt = time.Time{}
	appendEvent("history-rejoin", EventOperatorUpserted, providerAuthorityTenant, identity.UpdatedAt, AuthorityEvent{Operator: &identity})
	appendEvent("history-grant-2", EventDelegationGranted, customerID, now.Add(4*time.Minute), AuthorityEvent{Delegation: &delegation})

	check := func(phase string) {
		t.Helper()
		operators, err := NewPGAccessStore(st).ListOperatorAccess(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(operators) != 1 || len(operators[0].Delegations) != 2 {
			t.Fatalf("%s: operator history = %+v, want two grant episodes", phase, operators)
		}
		first, second := operators[0].Delegations[0], operators[0].Delegations[1]
		if first.GrantEventID == "" || second.GrantEventID == "" || first.GrantEventID == second.GrantEventID ||
			first.RevokedAt.IsZero() || !second.RevokedAt.IsZero() || !first.GrantedAt.Before(second.GrantedAt) {
			t.Fatalf("%s: episode order or revocation lost: %+v / %+v", phase, first, second)
		}
	}
	check("live")
	if err := projections.New(st, projections.WithEventProjection(NewAuthorityProjection(st))).Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("replayed")
}

func TestProviderBootstrapDoesNotResurrectLegacyRevokedGrant(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	now := time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC)
	if _, err := st.SystemPool().Exec(ctx, `INSERT INTO provider_operator_delegations
		(tenant_id, operator_id, customer_tenant_id, operation, granted_by, granted_at, revoked_at, revoked_by)
		VALUES ($1, 'legacy-revoked', $2, 'read', 'bootstrap-admin', $3, $4, 'legacy-offboard')`,
		providerAuthorityTenant, CustomerID("legacy-revoked-customer"), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if err := NewAuthorityRuntime(st, log).Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	var revokedAt *time.Time
	if err := st.SystemPool().QueryRow(ctx, `SELECT revoked_at FROM provider_operator_delegations
		WHERE tenant_id=$1 AND operator_id='legacy-revoked'`, providerAuthorityTenant).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt == nil || !revokedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("bootstrap resurrected revoked legacy grant: revoked_at=%v", revokedAt)
	}
	var episodes int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM provider_operator_grant_episodes
		WHERE tenant_id=$1 AND operator_id='legacy-revoked' AND revoked_at IS NOT NULL`,
		providerAuthorityTenant).Scan(&episodes); err != nil || episodes != 1 {
		t.Fatalf("legacy revoked history episodes=%d, err=%v", episodes, err)
	}
}
