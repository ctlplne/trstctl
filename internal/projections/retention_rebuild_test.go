// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestAuditRetentionPreservesProjectionRebuild pins the event-sourcing durability
// wall: retention may hide old events from audit queries, but it may not delete
// the event envelopes needed to rebuild a still-live owner.
func TestAuditRetentionPreservesProjectionRebuild(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)

	old := time.Now().Add(-48 * time.Hour)
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Time: old, Data: tenantRegistered("Acme"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		Time: old.Add(time.Second),
		Data: ownerCreated("00000000-0000-0000-0000-0000000000d1", "durable-owner"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := projector.Project(ctx, log); err != nil {
		t.Fatalf("initial projection: %v", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf("owners before retention = %d, want 1", got)
	}

	key, err := audit.LoadOrCreateSigningKey(
		filepath.Join(t.TempDir(), "audit-signing-key.pem"), "audit-export",
	)
	if err != nil {
		t.Fatal(err)
	}
	service := audit.NewService(log, key, audit.WithCheckpoints(st))
	worker := audit.NewRetentionWorker(
		service, log, audit.DirArchiver{Dir: t.TempDir()}, st, time.Hour,
	)
	summary, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if summary.RecordsArchived != 2 || summary.RecordsSourceRetained != 2 ||
		summary.RecordsPruned != 0 {
		t.Fatalf("retention summary = %+v, want two archived/source-retained and zero pruned", summary)
	}

	// Simulate an event-only recovery target. The replayable archive event must
	// reconstruct the logical query floor along with the domain projection.
	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE audit_checkpoints`); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild after retention: %v", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf("owners after retention rebuild = %d, want 1", got)
	}
	checkpoint, ok, err := st.LatestAuditCheckpoint(ctx, tenantA)
	if err != nil || !ok {
		t.Fatalf("rebuilt audit checkpoint: ok=%v err=%v", ok, err)
	}
	if checkpoint.RecordCount != 2 || checkpoint.BoundarySeq != 2 ||
		checkpoint.BoundaryHash == "" || checkpoint.ArchiveURI == "" {
		t.Fatalf("rebuilt audit checkpoint = %+v, want exact hidden prefix", checkpoint)
	}
}

func TestAuditRetentionRebuildRejectsLostSourceBeforeReadModelMutation(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)
	old := time.Now().Add(-48 * time.Hour)
	for _, event := range []events.Event{
		{Type: projections.EventTenantRegistered, TenantID: tenantA, Time: old, Data: tenantRegistered("Acme")},
		{Type: projections.EventOwnerCreated, TenantID: tenantA, Time: old.Add(time.Second), Data: ownerCreated("00000000-0000-0000-0000-0000000000d2", "preserve-on-failure")},
	} {
		if _, err := log.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := projector.Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	key, err := audit.LoadOrCreateSigningKey(
		filepath.Join(t.TempDir(), "audit-signing-key.pem"), "audit-export",
	)
	if err != nil {
		t.Fatal(err)
	}
	service := audit.NewService(log, key, audit.WithCheckpoints(st))
	worker := audit.NewRetentionWorker(
		service, log, audit.DirArchiver{Dir: t.TempDir()}, st, time.Hour,
	)
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE audit_checkpoints`); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{1, 2} {
		if err := log.Delete(ctx, seq); err != nil {
			t.Fatalf("simulate legacy source loss at %d: %v", seq, err)
		}
	}

	err = projector.Rebuild(ctx, log)
	if err == nil || !strings.Contains(err.Error(), "refuse lossy rebuild") {
		t.Fatalf("Rebuild error = %v, want retained-source rejection", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf("failed rebuild mutated prior owner state: owners=%d, want 1", got)
	}
}

func TestAuditArchivedCheckpointProjectionIsTenantIsolated(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	for tenantID, name := range map[string]string{tenantA: "A", tenantB: "B"} {
		if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := json.Marshal(audit.ArchivedEvent{
		Count: 1, BoundarySeq: 7, BoundaryHash: "tenant-a-chain-head",
		ArchiveURI: "s3://audit/tenant-a/segment.jws", SourceHistoryRetained: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).Apply(ctx, events.Event{
		Type: audit.EventTypeArchived, TenantID: tenantA,
		SchemaVersion: audit.ArchivedEventSchemaVersion, Data: payload,
	}); err != nil {
		t.Fatal(err)
	}
	if checkpoint, ok, err := st.LatestAuditCheckpoint(ctx, tenantA); err != nil || !ok ||
		checkpoint.BoundarySeq != 7 {
		t.Fatalf("tenant A checkpoint = %+v ok=%v err=%v", checkpoint, ok, err)
	}
	if checkpoint, ok, err := st.LatestAuditCheckpoint(ctx, tenantB); err != nil || ok {
		t.Fatalf("tenant B observed tenant A checkpoint: %+v ok=%v err=%v", checkpoint, ok, err)
	}
}
