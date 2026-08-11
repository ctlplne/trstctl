// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestDynamicSecretLegacyOutcomesFromErasedRegistrationAreInertAUD108(t *testing.T) {
	const (
		tenantID = "11111111-1111-4111-8111-111111111208"
		leaseID  = "same-public-lease"
		newEpoch = "11111111-1111-4111-8111-111111111202"
	)
	base := time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC)
	oldPending := DynamicSecretLeasePending{
		ID: leaseID, IdempotencyKey: "same-command", RequestBinding: "sha256:same",
		Provider: "postgres", Role: "reader", ExpiresAt: base.Add(time.Hour),
		HardExpiresAt: base.Add(2 * time.Hour),
	}
	newPending := oldPending
	newPending.TenantEpoch = newEpoch

	makeEvent := func(sequence uint64, id, eventType string, schema int, at time.Time, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{
			ID: id, Type: eventType, TenantID: tenantID, Sequence: sequence,
			SchemaVersion: schema, Time: at, Data: data,
		}
	}
	registered := func(sequence uint64, suffix string) events.Event {
		return makeEvent(sequence, "tenant-registered-"+suffix, EventTenantRegistered,
			events.DefaultSchemaVersion, base, map[string]string{"name": suffix})
	}
	offboarded := func(sequence uint64) events.Event {
		return makeEvent(sequence, "tenant-offboarded", EventTenantOffboarded,
			events.DefaultSchemaVersion, base.Add(time.Minute), map[string]int{"rows_deleted": 1})
	}
	oldPendingEvent := func(sequence uint64) events.Event {
		return makeEvent(sequence, "old-pending", EventDynamicSecretLeasePending,
			events.DefaultSchemaVersion, base.Add(time.Second), oldPending)
	}
	newPendingEvent := func(sequence uint64) events.Event {
		return makeEvent(sequence,
			store.DynamicSecretEventID(tenantID, newEpoch, "issue-requested", leaseID),
			EventDynamicSecretLeasePending, DynamicSecretEventSchemaVersion,
			base.Add(2*time.Minute), newPending)
	}

	tests := []struct {
		name      string
		oldPrefix []events.Event
		stale     events.Event
		newPrefix []events.Event
	}{
		{
			name: "prepared",
			stale: makeEvent(3, "old-prepared", EventDynamicSecretLeasePrepared, 1,
				base.Add(2*time.Second), DynamicSecretLeasePrepared{
					ID: leaseID, Provider: "postgres", SealedPreparation: []byte("sealed-preparation"),
				}),
		},
		{
			name: "issued",
			stale: makeEvent(3, "old-issued", EventDynamicSecretLeaseIssued, 1,
				base.Add(2*time.Second), DynamicSecretLeaseIssued{
					ID: leaseID, IdempotencyKey: "same-command", RequestBinding: "sha256:same",
					Provider: "postgres", Role: "reader", BackendRef: "backend-old",
					SealedCredential: []byte("sealed-old"), ExpiresAt: base.Add(time.Hour),
					HardExpiresAt: base.Add(2 * time.Hour),
				}),
		},
		{
			name: "renewed",
			oldPrefix: []events.Event{makeEvent(3, "old-issued", EventDynamicSecretLeaseIssued, 1,
				base.Add(2*time.Second), DynamicSecretLeaseIssued{
					ID: leaseID, IdempotencyKey: "same-command", RequestBinding: "sha256:same",
					Provider: "postgres", Role: "reader", BackendRef: "backend-old",
					SealedCredential: []byte("sealed-old"), ExpiresAt: base.Add(time.Hour),
					HardExpiresAt: base.Add(2 * time.Hour),
				})},
			stale: makeEvent(4, "old-renewed", EventDynamicSecretLeaseRenewed, 1,
				base.Add(3*time.Second), DynamicSecretLeaseRenewed{
					ID: leaseID, ExpiresAt: base.Add(90 * time.Minute),
				}),
		},
		{
			name: "revocation completed",
			oldPrefix: dynamicSecretLegacyRevocationPrefixForTest(
				t, makeEvent, base, leaseID),
			stale: makeEvent(5, "old-revoke-completed", EventDynamicSecretLeaseRevocationCompleted, 1,
				base.Add(4*time.Second), DynamicSecretLeaseRevocationCompleted{ID: leaseID}),
		},
		{
			name: "revocation failed",
			oldPrefix: dynamicSecretLegacyRevocationPrefixForTest(
				t, makeEvent, base, leaseID),
			stale: makeEvent(5, "old-revoke-failed", EventDynamicSecretLeaseRevocationFailed, 1,
				base.Add(4*time.Second), DynamicSecretLeaseFailure{ID: leaseID, Error: "old failure"}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := newDynamicSecretLifecycleAuthority()
			sequence := uint64(1)
			mustObserveDynamicSecretLifecycleTest(t, authority, registered(sequence, "old"), false)
			sequence++
			mustObserveDynamicSecretLifecycleTest(t, authority, oldPendingEvent(sequence), false)
			for _, event := range test.oldPrefix {
				sequence++
				event.Sequence = sequence
				mustObserveDynamicSecretLifecycleTest(t, authority, event, false)
			}
			sequence++
			stale := test.stale
			stale.Sequence = sequence
			mustObserveDynamicSecretLifecycleTest(t, authority, stale, false)
			sequence++
			mustObserveDynamicSecretLifecycleTest(t, authority, offboarded(sequence), false)
			sequence++
			mustObserveDynamicSecretLifecycleTest(t, authority, registered(sequence, "new"), false)
			sequence++
			mustObserveDynamicSecretLifecycleTest(t, authority, newPendingEvent(sequence), false)

			// A physically new post-registration v1 envelope carries the exact old
			// transition bytes. Sequence-only fencing would accept it; erased-ID
			// classification must make it inert even though the public ID/command is reused.
			sequence++
			stale.Sequence = sequence
			stale.ID += "-late-duplicate"
			mustObserveDynamicSecretLifecycleTest(t, authority, stale, true)
		})
	}

	t.Run("operation terminal", func(t *testing.T) {
		const operationID = "same-operation"
		authority := newDynamicSecretLifecycleAuthority()
		mustObserveDynamicSecretLifecycleTest(t, authority, registered(1, "old"), false)
		mustObserveDynamicSecretLifecycleTest(t, authority, oldPendingEvent(2), false)
		oldRequest := makeEvent(3, "old-operation-requested", EventDynamicSecretOperationRequested, 1,
			base.Add(2*time.Second), DynamicSecretOperationRequested{
				OperationID: operationID, IdempotencyKey: "same-operation-key",
				RequestBinding: "sha256:same-operation", Action: "renew", LeaseID: leaseID,
				Response: json.RawMessage(`{"lease_id":"same-public-lease"}`),
			})
		mustObserveDynamicSecretLifecycleTest(t, authority, oldRequest, false)
		oldCompleted := makeEvent(4, "old-operation-completed", EventDynamicSecretOperationCompleted, 1,
			base.Add(3*time.Second), DynamicSecretOperationCompleted{
				OperationID: operationID, RequestBinding: "sha256:same-operation",
				Action: "renew", LeaseID: leaseID,
			})
		mustObserveDynamicSecretLifecycleTest(t, authority, oldCompleted, false)
		mustObserveDynamicSecretLifecycleTest(t, authority, offboarded(5), false)
		mustObserveDynamicSecretLifecycleTest(t, authority, registered(6, "new"), false)
		mustObserveDynamicSecretLifecycleTest(t, authority, newPendingEvent(7), false)
		newRequest := DynamicSecretOperationRequested{
			TenantEpoch: newEpoch, OperationID: operationID, IdempotencyKey: "same-operation-key",
			RequestBinding: "sha256:same-operation", Action: "renew", LeaseID: leaseID,
			Response: json.RawMessage(`{"lease_id":"same-public-lease"}`),
		}
		mustObserveDynamicSecretLifecycleTest(t, authority, makeEvent(8,
			store.DynamicSecretEventID(tenantID, newEpoch, "operation-requested", operationID),
			EventDynamicSecretOperationRequested, DynamicSecretEventSchemaVersion,
			base.Add(2*time.Minute), newRequest), false)
		oldCompleted.Sequence = 9
		oldCompleted.ID = "old-operation-completed-late-duplicate"
		mustObserveDynamicSecretLifecycleTest(t, authority, oldCompleted, true)
	})

}

func dynamicSecretLegacyRevocationPrefixForTest(
	t *testing.T,
	makeEvent func(uint64, string, string, int, time.Time, any) events.Event,
	base time.Time,
	leaseID string,
) []events.Event {
	t.Helper()
	return []events.Event{
		makeEvent(3, "old-issued", EventDynamicSecretLeaseIssued, 1,
			base.Add(2*time.Second), DynamicSecretLeaseIssued{
				ID: leaseID, IdempotencyKey: "same-command", RequestBinding: "sha256:same",
				Provider: "postgres", Role: "reader", BackendRef: "backend-old",
				SealedCredential: []byte("sealed-old"), ExpiresAt: base.Add(time.Hour),
				HardExpiresAt: base.Add(2 * time.Hour),
			}),
		makeEvent(4, "old-revoke-requested", EventDynamicSecretLeaseRevocationRequested, 1,
			base.Add(3*time.Second), DynamicSecretLeaseRevocationRequested{
				ID: leaseID, Provider: "postgres", BackendRef: "backend-old",
			}),
	}
}

func mustObserveDynamicSecretLifecycleTest(
	t *testing.T,
	authority *dynamicSecretLifecycleAuthority,
	event events.Event,
	wantSkip bool,
) {
	t.Helper()
	skip, err := authority.observe(event)
	if err != nil {
		t.Fatalf("observe %s@%d: %v", event.Type, event.Sequence, err)
	}
	if skip != wantSkip {
		t.Fatalf("observe %s@%d skip=%t, want %t", event.Type, event.Sequence, skip, wantSkip)
	}
}

func TestDynamicSecretLifecycleRejectsZeroCanonicalTimeForEveryTransitionAUD108(t *testing.T) {
	for _, eventType := range []string{
		EventDynamicSecretLeasePending,
		EventDynamicSecretLeasePrepared,
		EventDynamicSecretLeaseIssued,
		EventDynamicSecretLeaseIssuanceFailed,
		EventDynamicSecretLeaseRenewed,
		EventDynamicSecretLeaseRevocationRequested,
		EventDynamicSecretLeaseRevocationCompleted,
		EventDynamicSecretLeaseRevocationFailed,
		EventDynamicSecretOperationRequested,
		EventDynamicSecretOperationCompleted,
	} {
		t.Run(eventType, func(t *testing.T) {
			_, err := newDynamicSecretLifecycleAuthority().observe(events.Event{
				ID: "malformed-zero-time", Type: eventType,
				TenantID: "11111111-1111-4111-8111-111111111208",
				Sequence: 1, SchemaVersion: DynamicSecretEventSchemaVersion,
				Data: []byte(`{}`),
			})
			if err == nil {
				t.Fatal("zero canonical event time was accepted")
			}
		})
	}
}

func TestDynamicSecretLegacyResultABConflictFailsClosedAUD108(t *testing.T) {
	const (
		tenantID = "11111111-1111-4111-8111-111111111208"
		leaseID  = "legacy-result-ab"
	)
	base := time.Date(2026, 8, 11, 14, 0, 0, 0, time.UTC)
	makeEvent := func(sequence uint64, id, eventType string, at time.Time, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{
			ID: id, Type: eventType, TenantID: tenantID, Sequence: sequence,
			SchemaVersion: 1, Time: at, Data: data,
		}
	}
	registered := makeEvent(1, "tenant-registered", EventTenantRegistered, base,
		map[string]string{"name": "legacy"})
	pending := makeEvent(2, "pending", EventDynamicSecretLeasePending, base.Add(time.Second),
		DynamicSecretLeasePending{
			ID: leaseID, IdempotencyKey: "legacy-command", RequestBinding: "sha256:legacy",
			Provider: "postgres", Role: "reader", ExpiresAt: base.Add(time.Hour),
			HardExpiresAt: base.Add(2 * time.Hour),
		})
	issued := func(sequence uint64, id, backend string, sealed []byte) events.Event {
		return makeEvent(sequence, id, EventDynamicSecretLeaseIssued, base.Add(2*time.Second),
			DynamicSecretLeaseIssued{
				ID: leaseID, IdempotencyKey: "legacy-command", RequestBinding: "sha256:legacy",
				Provider: "postgres", Role: "reader", BackendRef: backend,
				SealedCredential: sealed, ExpiresAt: base.Add(time.Hour),
				HardExpiresAt: base.Add(2 * time.Hour),
			})
	}
	revocationRequested := makeEvent(4, "revoke-requested", EventDynamicSecretLeaseRevocationRequested,
		base.Add(3*time.Second), DynamicSecretLeaseRevocationRequested{
			ID: leaseID, Provider: "postgres", BackendRef: "backend-a",
		})

	tests := []struct {
		name     string
		prefix   []events.Event
		first    events.Event
		conflict events.Event
	}{
		{
			name:   "prepared ciphertext",
			prefix: []events.Event{registered, pending},
			first: makeEvent(3, "prepared-a", EventDynamicSecretLeasePrepared, base.Add(2*time.Second),
				DynamicSecretLeasePrepared{ID: leaseID, Provider: "postgres", SealedPreparation: []byte("sealed-a")}),
			conflict: makeEvent(4, "prepared-b", EventDynamicSecretLeasePrepared, base.Add(2*time.Second),
				DynamicSecretLeasePrepared{ID: leaseID, Provider: "postgres", SealedPreparation: []byte("sealed-b")}),
		},
		{
			name:     "issued provider result",
			prefix:   []events.Event{registered, pending},
			first:    issued(3, "issued-a", "backend-a", []byte("credential-a")),
			conflict: issued(4, "issued-b", "backend-b", []byte("credential-b")),
		},
		{
			name:   "revocation completion",
			prefix: []events.Event{registered, pending, issued(3, "issued-a", "backend-a", []byte("credential-a")), revocationRequested},
			first: makeEvent(5, "completed-a", EventDynamicSecretLeaseRevocationCompleted, base.Add(4*time.Second),
				DynamicSecretLeaseRevocationCompleted{ID: leaseID}),
			conflict: makeEvent(6, "completed-b", EventDynamicSecretLeaseRevocationCompleted, base.Add(5*time.Second),
				DynamicSecretLeaseRevocationCompleted{ID: leaseID}),
		},
		{
			name:   "revocation failure",
			prefix: []events.Event{registered, pending, issued(3, "issued-a", "backend-a", []byte("credential-a")), revocationRequested},
			first: makeEvent(5, "failed-a", EventDynamicSecretLeaseRevocationFailed, base.Add(4*time.Second),
				DynamicSecretLeaseFailure{ID: leaseID, Error: "failure-a"}),
			conflict: makeEvent(6, "failed-b", EventDynamicSecretLeaseRevocationFailed, base.Add(4*time.Second),
				DynamicSecretLeaseFailure{ID: leaseID, Error: "failure-b"}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := newDynamicSecretLifecycleAuthority()
			for _, event := range test.prefix {
				mustObserveDynamicSecretLifecycleTest(t, authority, event, false)
			}
			mustObserveDynamicSecretLifecycleTest(t, authority, test.first, false)
			if _, err := authority.observe(test.conflict); !errors.Is(err, store.ErrIdempotencyConflict) {
				t.Fatalf("conflicting legacy result error = %v, want idempotency conflict", err)
			}
		})
	}
}
