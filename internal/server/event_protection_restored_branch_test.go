// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Requires the existing full-restore helper to return target, restored store,
// info and original claims verified against the source signer's public JWKS.
// The exact completed restore has no retired offboard in its old prefix.
func TestEventProtectionFullRestoreContinuesBeyondOriginalOffboardPosition(t *testing.T) {
	target, restored, info, claims := eventProtectionErasedSQLRestore(t, false)
	signer, key, err := openAuditSigningRuntime(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	log, runtime, err := openConfiguredEventSource(t.Context(), target, restored, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runtime.Close(); _ = log.Close() }()
	oldHead, err := log.LastSequence(t.Context())
	if err != nil || oldHead >= claims.Request.OffboardSequence {
		t.Fatalf("fixture is not a pre-offboard cut: %d %v", oldHead, err)
	}
	var ids []string
	head := oldHead
	for head <= claims.Request.OffboardSequence {
		id := uuid.NewString()
		wire, err := json.Marshal(projections.OwnerCreated{ID: id, Kind: "team", Name: "Restored neighbor", Email: "restored-branch@example.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(t.Context(), events.Event{Type: projections.EventOwnerCreated, TenantID: info.Neighbor, Data: wire})
		if err != nil {
			t.Fatal(err)
		}
		head = event.Sequence
		ids = append(ids, id)
	}
	if err := projections.New(restored, runtime.projectionOptions()...).ProjectCatchUp(t.Context(), log); err != nil {
		t.Fatalf("actual restored branch cannot project beyond original offboard ordinal: %v", err)
	}
	if err := projections.New(restored, runtime.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatalf("actual restored branch cannot rebuild: %v", err)
	}
	for _, id := range ids {
		got, err := restored.GetOwner(t.Context(), info.Neighbor, id)
		if err != nil || got.Email != "restored-branch@example.invalid" {
			t.Fatalf("neighbor was lost: %v", err)
		}
	}
	checkpoint, err := restored.ProjectionCheckpoint(t.Context())
	if err != nil || checkpoint != head {
		t.Fatalf("branch checkpoint %d want %d: %v", checkpoint, head, err)
	}
	worker := projections.NewTailWorker(log, projections.New(restored, runtime.projectionOptions()...), nil, time.Second)
	tailCtx, cancel := context.WithCancel(t.Context())
	workerErr := make(chan error, 1)
	go func() { workerErr <- worker.Run(tailCtx) }()
	defer func() {
		cancel()
		select {
		case <-workerErr:
		case <-time.After(5 * time.Second):
			t.Error("restored branch tail did not stop within 5s")
		}
	}()
	id := uuid.NewString()
	wire, err := json.Marshal(projections.OwnerCreated{ID: id, Kind: "team", Name: "Restored tail", Email: "restored-tail@example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	late, err := log.Append(t.Context(), events.Event{Type: projections.EventOwnerCreated, TenantID: info.Neighbor, Data: wire})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	observed := false
	for !observed {
		select {
		case err := <-workerErr:
			t.Fatalf("restored branch tail stopped: %v", err)
		case <-deadline.C:
			t.Fatal("restored branch tail did not project neighbor within 12s")
		case <-ticker.C:
			got, err := restored.GetOwner(t.Context(), info.Neighbor, id)
			checkpoint, checkpointErr := restored.ProjectionCheckpoint(t.Context())
			observed = err == nil && checkpointErr == nil && got.Email == "restored-tail@example.invalid" && checkpoint == late.Sequence && worker.Applied() >= late.Sequence
		}
	}
	if err := runtime.reader.VerifyCurrentCustody(t.Context()); err != nil {
		t.Fatalf("configured current-custody readiness became unhealthy: %v", err)
	}
	eventKeyAssertNoTenantSQLResidue(t, restored, info.Tenant)
	receipt, erased, err := runtime.custody.DestructionReceipt(t.Context(), claims.Request.Ref)
	if err != nil || !erased || receipt == "" {
		t.Fatalf("current signed key absence lost: %v", err)
	}
}
