// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestAuditRetentionPreservesProjectionRebuild pins the event-sourcing durability
// wall: audit retention may move old events out of the served audit view only
// when the advertised from-log rebuild still reproduces the exact served read model.
// Ordinary domain events are audit records too, so deleting an owner.created
// envelope without a durable projection-compaction baseline would make the next
// rebuild erase a still-live owner.
func TestAuditRetentionPreservesProjectionRebuild(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	projector := projections.New(st)

	old := time.Now().Add(-48 * time.Hour)
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventTenantRegistered,
		TenantID: tenantA,
		Time:     old,
		Data:     tenantRegistered("Acme"),
	}); err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type:     projections.EventOwnerCreated,
		TenantID: tenantA,
		Time:     old.Add(time.Second),
		Data:     ownerCreated("00000000-0000-0000-0000-0000000000d1", "durable-owner"),
	}); err != nil {
		t.Fatalf("append owner: %v", err)
	}
	if err := projector.Project(ctx, log); err != nil {
		t.Fatalf("initial projection: %v", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf("owners before retention = %d, want 1", got)
	}

	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatalf("audit signing key: %v", err)
	}
	service := audit.NewService(log, key, audit.WithCheckpoints(st))
	worker := audit.NewRetentionWorker(
		service,
		log,
		audit.DirArchiver{Dir: t.TempDir()},
		st,
		time.Hour,
	)
	summary, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if summary.RecordsArchived != 2 || summary.RecordsSourceRetained != 2 ||
		summary.RecordsPruned != 0 {
		t.Fatalf("retention summary = %+v, want two archived and source-retained with zero pruned", summary)
	}

	// Simulate an event-only recovery target: PostgreSQL lost the logical
	// checkpoint as well as the served read model. The immutable audit.archived
	// event must rebuild that receiver, or archived history would reappear.
	if _, err := st.SystemPool().Exec(ctx, `TRUNCATE audit_checkpoints`); err != nil {
		t.Fatalf("clear audit checkpoints: %v", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild after retention: %v", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf(
			"owners after retention rebuild = %d, want 1; retention deleted the authoritative owner.created event without a durable rebuild baseline",
			got,
		)
	}
	checkpoint, ok, err := st.LatestAuditCheckpoint(ctx, tenantA)
	if err != nil || !ok {
		t.Fatalf("rebuilt audit checkpoint: ok=%v err=%v", ok, err)
	}
	if checkpoint.RecordCount != 2 || checkpoint.BoundarySeq != 2 ||
		checkpoint.BoundaryHash == "" || checkpoint.ArchiveURI == "" {
		t.Fatalf("rebuilt audit checkpoint = %+v, want exact retired prefix", checkpoint)
	}
}

func TestAuditRetentionRebuildRejectsLostSourceBeforeReadModelMutation(t *testing.T) {
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
		Data: ownerCreated("00000000-0000-0000-0000-0000000000d2", "preserve-on-failure"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := projector.Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
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
	//nolint:staticcheck // Deliberately reproduces legacy source loss so rebuild must fail closed.
	if err := log.PruneTenantThroughCheckpoint(ctx, tenantA, 2, nil); err != nil {
		t.Fatalf("simulate legacy source loss: %v", err)
	}

	err = projector.Rebuild(ctx, log)
	if err == nil || !strings.Contains(err.Error(), "refuse lossy rebuild") {
		t.Fatalf("Rebuild error = %v, want retained-source rejection", err)
	}
	if got := ownerCount(t, st, tenantA); got != 1 {
		t.Fatalf("failed rebuild mutated prior owner state: owners=%d, want 1", got)
	}
}
