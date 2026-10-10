// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestBreakglassApprovalEvidenceIndexedColdRecoveryAndConflict(t *testing.T) {
	ctx := context.Background()
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")}
	const duplicateWindow = 100 * time.Millisecond
	log, err := events.Open(ctx, cfg, events.WithDuplicateWindowForTesting(duplicateWindow))
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "d0d00000-0000-4000-8000-000000000931"
	const ceremony = "d0d00000-0000-4000-8000-000000000932"
	runtime := &configuredBreakglassRuntime{
		tenantID: tenant, threshold: 2, operators: []string{"alice", "bob", "carol"}, log: log,
	}
	appendApproval := func(id, custodian, actor string, count int) events.Event {
		t.Helper()
		data, err := json.Marshal(projections.CACeremonyApproved{
			CeremonyID: ceremony, Custodian: custodian, Approvals: count,
		})
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(events.ContextWithActor(ctx, events.Actor{Subject: actor}), events.Event{
			ID: id, TenantID: tenant, Type: projections.EventCACeremonyApproved, Data: data,
		})
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	if _, err := log.Append(ctx, events.Event{ID: "unrelated-before", TenantID: tenant, Type: "test.unrelated", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	alice := appendApproval("approval-alice", "alice", "alice", 1)
	if _, err := log.Append(ctx, events.Event{ID: "unrelated-between", TenantID: tenant, Type: "test.unrelated", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	bob := appendApproval("approval-bob", "bob", "bob", 2)
	evidence := []store.KeyCeremonyApprovalEvidence{
		{Custodian: "alice", EventID: alice.ID, EventSequence: alice.Sequence},
		{Custodian: "bob", EventID: bob.ID, EventSequence: bob.Sequence},
	}
	verify := func() {
		t.Helper()
		approvers, err := runtime.verifyApprovalEvidence(ctx, ceremony, evidence)
		if err != nil || !reflect.DeepEqual(approvers, []string{"alice", "bob"}) {
			t.Fatalf("verified approvers = %v, %v", approvers, err)
		}
	}
	verify()
	tampered := append([]store.KeyCeremonyApprovalEvidence(nil), evidence...)
	tampered[0].EventSequence = bob.Sequence
	if _, err := runtime.verifyApprovalEvidence(ctx, ceremony, tampered); err == nil {
		t.Fatal("approval row with another event's sequence was accepted")
	}
	wrongActor := appendApproval("approval-carol-wrong-actor", "carol", "alice", 3)
	wrong := []store.KeyCeremonyApprovalEvidence{
		evidence[0], {Custodian: "carol", EventID: wrongActor.ID, EventSequence: wrongActor.Sequence},
	}
	if _, err := runtime.verifyApprovalEvidence(ctx, ceremony, wrong); err == nil {
		t.Fatal("approval row with a different authenticated actor was accepted")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, cfg, events.WithDuplicateWindowForTesting(duplicateWindow))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime.log = log
	verify()
	// A later envelope with the same identity but changed contents must not
	// let the first matching row authorize an emergency signature.
	time.Sleep(4 * duplicateWindow)
	appendApproval(alice.ID, "alice", "alice", 9)
	if _, err := runtime.verifyApprovalEvidence(ctx, ceremony, evidence); !errors.Is(err, events.ErrConflictingEventIdentity) {
		t.Fatalf("conflicting immutable approval identity = %v, want refusal", err)
	}
}
