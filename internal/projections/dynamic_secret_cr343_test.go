// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// CR-343: two valid revoke commands for one issued lease may already exist in
// an append-only log from an older writer. The first is the only provider
// intent; replay must skip the second and keep another tenant projectable.
func TestCR343DistinctKeyRevocationHistoryDoesNotWedgeOtherTenants(t *testing.T) {
	const (
		tenant = "11111111-1111-4111-8111-111111111343"
		other  = "22222222-2222-4222-8222-222222222343"
		epoch  = "33333333-3333-4333-8333-333333333343"
		lease  = "cr343-lease"
	)
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	event := func(sequence uint64, tenantID, typ, purpose, commandID string, version int, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		id := "tenant-registered-" + tenantID
		if purpose != "" {
			id = store.DynamicSecretEventID(tenantID, epoch, purpose, commandID)
		}
		return events.Event{ID: id, Type: typ, TenantID: tenantID, Sequence: sequence,
			SchemaVersion: version, Time: at, Data: data}
	}
	a := newDynamicSecretLifecycleAuthority()
	mustObserveDynamicSecretLifecycleTest(t, a, event(1, tenant, EventTenantRegistered, "", "", 1, map[string]string{"name": "A"}), false)
	mustObserveDynamicSecretLifecycleTest(t, a, event(2, tenant, EventDynamicSecretLeasePending, "issue-requested", lease, DynamicSecretEventSchemaVersion,
		DynamicSecretLeasePending{TenantEpoch: epoch, ID: lease, IdempotencyKey: "issue", RequestBinding: "sha256:issue", Provider: "postgres", Role: "reader",
			ExpiresAt: at.Add(time.Hour), HardExpiresAt: at.Add(2 * time.Hour)}), false)
	mustObserveDynamicSecretLifecycleTest(t, a, event(3, tenant, EventDynamicSecretLeaseIssued, "provider-issued", lease, DynamicSecretEventSchemaVersion,
		DynamicSecretLeaseIssued{TenantEpoch: epoch, ID: lease, IdempotencyKey: "issue", RequestBinding: "sha256:issue", Provider: "postgres", Role: "reader",
			BackendRef: "native-lease", SealedCredential: []byte("sealed-fixture"), ExpiresAt: at.Add(time.Hour), HardExpiresAt: at.Add(2 * time.Hour)}), false)
	for i, operation := range []string{"operation-a", "operation-b"} {
		mustObserveDynamicSecretLifecycleTest(t, a, event(uint64(4+i), tenant, EventDynamicSecretOperationRequested, "operation-requested", operation, DynamicSecretEventSchemaVersion,
			DynamicSecretOperationRequested{TenantEpoch: epoch, OperationID: operation, IdempotencyKey: operation, RequestBinding: "sha256:" + operation,
				Action: "revoke", LeaseID: lease, Response: json.RawMessage(`{"lease_id":"cr343-lease"}`)}), false)
	}
	first := event(6, tenant, EventDynamicSecretLeaseRevocationRequested, "lease-revocation-requested", "operation-a", DynamicSecretRevocationReferenceSchemaVersion,
		DynamicSecretLeaseRevocationRequestedV3{TenantEpoch: epoch, OperationID: "operation-a", ID: lease, Provider: "postgres"})
	second := event(7, tenant, EventDynamicSecretLeaseRevocationRequested, "lease-revocation-requested", "operation-b", DynamicSecretRevocationReferenceSchemaVersion,
		DynamicSecretLeaseRevocationRequestedV3{TenantEpoch: epoch, OperationID: "operation-b", ID: lease, Provider: "postgres"})
	mustObserveDynamicSecretLifecycleTest(t, a, first, false)
	mustObserveDynamicSecretLifecycleTest(t, a, second, true)
	if got := a.lifecycles[tenant].leases[lease].revocationRequested; got == nil || got.ID != first.ID {
		t.Fatal("the first revoke command lost its provider authority")
	}
	if _, skipped := a.skipSequences[second.Sequence]; !skipped {
		t.Fatal("the second revoke command would still reach the provider projector")
	}
	mustObserveDynamicSecretLifecycleTest(t, a, event(8, other, EventTenantRegistered, "", "", 1, map[string]string{"name": "B"}), false)
	forged := event(9, tenant, EventDynamicSecretLeaseRevocationRequested, "lease-revocation-requested", "missing-operation", DynamicSecretRevocationReferenceSchemaVersion,
		DynamicSecretLeaseRevocationRequestedV3{TenantEpoch: epoch, OperationID: "missing-operation", ID: lease, Provider: "postgres"})
	if _, err := a.observe(forged); err == nil {
		t.Fatal("a later revoke with no bound operation was silently accepted")
	}
}
