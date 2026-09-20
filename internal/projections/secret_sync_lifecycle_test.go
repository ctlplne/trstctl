// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestSecretSyncLifecycleAuthorityKeepsDuplicateRegistrationAndErasesWholeLifecycleAUD109(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111109"
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	authority := newSecretSyncLifecycleAuthority()
	event := func(sequence uint64, id, eventType string, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return events.Event{
			Sequence: sequence, ID: id, Type: eventType, TenantID: tenantID,
			SchemaVersion: events.DefaultSchemaVersion, Time: now.Add(time.Duration(sequence) * time.Second), Data: data, // #nosec G115 -- fixture sequences are single-digit seconds (CWE-190).
		}
	}
	observe := func(candidate events.Event, wantSkip bool) {
		t.Helper()
		skip, err := authority.observe(candidate)
		if err != nil || skip != wantSkip {
			t.Fatalf("observe %s seq %d = (skip:%t, %v), want skip:%t", candidate.Type, candidate.Sequence, skip, err, wantSkip)
		}
	}

	observe(event(1, "tenant-register-1", EventTenantRegistered, map[string]string{"name": "Acme"}), false)
	queue := func(sequence uint64, jobID string) events.Event {
		return event(sequence, store.SecretSyncQueuedEventID(tenantID, jobID), EventSecretSyncQueued, SecretSyncQueued{
			ID: jobID, SecretName: "production/database", SecretVersion: 1,
			Target: "ci", RemoteKey: "TOKEN", ValueDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			IdempotencyKey: store.SecretSyncOutboxIdempotencyKey("ci", jobID), Sealed: []byte("sealed"),
		})
	}
	observe(queue(2, "sync-before-duplicate-registration"), false)
	// This is an idempotent registration refresh, not a new lifecycle.
	observe(event(3, "tenant-register-duplicate", EventTenantRegistered, map[string]string{"name": "Acme renamed"}), false)
	observe(event(4, store.SecretSyncDeliveredEventID(tenantID, "sync-before-duplicate-registration"), EventSecretSyncDelivered,
		SecretSyncDelivered{ID: "sync-before-duplicate-registration", Attempts: 1}), false)
	if _, ok := authority.activeTerminal[secretSyncLifecycleJobKey(tenantID, "sync-before-duplicate-registration")]; !ok {
		t.Fatal("duplicate registration forgot the queued job before its terminal outcome")
	}

	observe(queue(5, "sync-late-after-offboard"), false)
	observe(event(6, "tenant-offboard", EventTenantOffboarded, map[string]int{"rows_deleted": 2}), false)
	if len(authority.activeTerminal) != 0 {
		t.Fatalf("offboard left active terminal requirements: %+v", authority.activeTerminal)
	}
	for _, sequence := range []uint64{2, 4, 5} {
		if _, erased := authority.skipSequences[sequence]; !erased {
			t.Fatalf("offboard did not erase lifecycle sequence %d", sequence)
		}
	}

	observe(event(7, "tenant-register-2", EventTenantRegistered, map[string]string{"name": "Acme new lifecycle"}), false)
	// Legacy v1 carries no epoch. Its erased job identity still makes it inert
	// after re-registration instead of letting append position choose a lifecycle.
	observe(event(8, store.SecretSyncFailedEventID(tenantID, "sync-late-after-offboard"), EventSecretSyncFailed,
		SecretSyncFailed{ID: "sync-late-after-offboard", Attempts: 2, Error: "closed failure"}), true)
}
