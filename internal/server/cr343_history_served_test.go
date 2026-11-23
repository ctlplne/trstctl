// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestCR343RetainedSecondRevokeDoesNotBlockCrossTenantCatchup(t *testing.T) {
	const (
		tenant = "11111111-1111-4111-8111-111111111344"
		other  = "22222222-2222-4222-8222-222222222344"
	)
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "cr343-issue", "sha256:cr343-issue")
	secret.Wipe(credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "cr343-first", "sha256:cr343-first"); err != nil {
		t.Fatal(err)
	}
	stop()
	record, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	operationID := dynamicSecretOperationID(tenant, "cr343-second")
	response, err := json.Marshal(dynamicSecretOperationResponseFromLease(dynamicLeaseFromStore(record), dynsecret.LeaseRevoked, record.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	appendEvent := func(id, eventType string, version int, tenantID string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{ID: id, Type: eventType, TenantID: tenantID, SchemaVersion: version, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent(dynamicSecretEventID(tenant, record.TenantEpoch, "operation-requested", operationID), projections.EventDynamicSecretOperationRequested,
		projections.DynamicSecretEventSchemaVersion, tenant, projections.DynamicSecretOperationRequested{
			TenantEpoch: record.TenantEpoch, OperationID: operationID, IdempotencyKey: "cr343-second", RequestBinding: "sha256:cr343-second",
			Action: "revoke", LeaseID: lease.ID, Response: response,
		})
	appendEvent(dynamicSecretEventID(tenant, record.TenantEpoch, "lease-revocation-requested", operationID), projections.EventDynamicSecretLeaseRevocationRequested,
		projections.DynamicSecretRevocationReferenceSchemaVersion, tenant, projections.DynamicSecretLeaseRevocationRequestedV3{
			TenantEpoch: record.TenantEpoch, OperationID: operationID, ID: lease.ID, Provider: provider.name,
		})
	appendEvent("cr343-other-tenant", projections.EventTenantRegistered, events.DefaultSchemaVersion, other, map[string]string{"name": "unrelated tenant"})
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("the second valid request wedged shared catch-up: %v", err)
	}
	if _, err := st.GetTenant(ctx, other); err != nil {
		t.Fatalf("unrelated tenant did not project: %v", err)
	}
	var intents int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		tenant, dynamicSecretRevokeDestination).Scan(&intents); err != nil || intents != 1 {
		t.Fatalf("provider revoke intents=%d err=%v, want exactly one", intents, err)
	}
}

func TestCR343RecoveryChoosesFirstRetainedRevokeIntent(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111345"
	ctx := context.Background()
	st, log, kek, outbox, provider, dispatcher := newDynamicSecretOutboxTestStack(t, tenant)
	srv, stop := startSecretIntegrationDispatcher(t, st, outbox, dispatcher)
	defer stop()
	lifecycle, err := newDurableDynamicSecretLifecycle(tenant, []dynsecret.Provider{provider}, st, log, kek, outbox, srv.wakeOutbox)
	if err != nil {
		t.Fatal(err)
	}
	lease, credential, err := lifecycle.IssueBound(ctx, provider.name, "reader", 20*time.Minute, "cr343-recovery-issue", "sha256:cr343-recovery-issue")
	secret.Wipe(credential)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	lifecycle.afterCanonicalAppend = func(event events.Event) error {
		if event.Type == projections.EventDynamicSecretLeaseRevocationRequested {
			return errors.New("injected: first revocation retained before projection")
		}
		return nil
	}
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "cr343-recovery-first", "sha256:cr343-recovery-first"); err == nil {
		t.Fatal("the preprojection fault was not reached")
	}
	lifecycle.afterCanonicalAppend = nil
	record, err := st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || record.State != "active" {
		t.Fatalf("first retained request unexpectedly projected: state=%s err=%v", record.State, err)
	}
	operationID := dynamicSecretOperationID(tenant, "cr343-recovery-second")
	response, err := json.Marshal(dynamicSecretOperationResponseFromLease(dynamicLeaseFromStore(record), dynsecret.LeaseRevoked, record.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	appendEvent := func(id, typ string, version int, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{ID: id, Type: typ, TenantID: tenant, SchemaVersion: version, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent(dynamicSecretEventID(tenant, record.TenantEpoch, "operation-requested", operationID), projections.EventDynamicSecretOperationRequested,
		projections.DynamicSecretEventSchemaVersion, projections.DynamicSecretOperationRequested{
			TenantEpoch: record.TenantEpoch, OperationID: operationID, IdempotencyKey: "cr343-recovery-second", RequestBinding: "sha256:cr343-recovery-second",
			Action: "revoke", LeaseID: lease.ID, Response: response,
		})
	appendEvent(dynamicSecretEventID(tenant, record.TenantEpoch, "lease-revocation-requested", operationID), projections.EventDynamicSecretLeaseRevocationRequested,
		projections.DynamicSecretRevocationReferenceSchemaVersion, projections.DynamicSecretLeaseRevocationRequestedV3{
			TenantEpoch: record.TenantEpoch, OperationID: operationID, ID: lease.ID, Provider: provider.name,
		})
	if _, err := lifecycle.RevokeBound(ctx, lease.ID, "cr343-recovery-third", "sha256:cr343-recovery-third"); err != nil {
		t.Fatalf("a later command could not recover the first valid intent: %v", err)
	}
	record, err = st.GetDynamicSecretLease(ctx, tenant, lease.ID)
	if err != nil || record.State != "revoked" {
		t.Fatalf("first valid intent was not projected: state=%s err=%v", record.State, err)
	}
	var intents int
	if err := st.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		tenant, dynamicSecretRevokeDestination).Scan(&intents); err != nil || intents != 1 {
		t.Fatalf("provider revoke intents=%d err=%v, want exactly one", intents, err)
	}
}
