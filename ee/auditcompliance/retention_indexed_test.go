// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestArchivedEventRecoveryUsesExactIdentityAcrossColdRestart(t *testing.T) {
	ctx := context.Background()
	const dedupe = 100 * time.Millisecond
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(ctx, cfg, events.WithDuplicateWindowForTesting(dedupe))
	if err != nil {
		t.Fatal(err)
	}
	const tenant = "11111111-1111-1111-1111-111111111111"
	if _, err := log.Append(ctx, events.Event{ID: "retained-record", TenantID: tenant, Type: "test.retained"}); err != nil {
		t.Fatal(err)
	}
	checkpoint := audit.Checkpoint{
		TenantID: tenant, BoundarySeq: 1, BoundaryHash: "checkpoint-head",
		RecordCount: 1, ArchiveURI: "local://signed-segment",
	}
	worker := &RetentionWorker{log: log}
	if err := worker.ensureArchivedEvent(ctx, checkpoint); err != nil {
		t.Fatal(err)
	}
	var archived events.Event
	if err := log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.Type == audit.EventTypeArchived {
			archived = ev
		}
		return nil
	}); err != nil || archived.ID == "" {
		t.Fatalf("find archived fixture: %+v, %v", archived, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(ctx, cfg, events.WithDuplicateWindowForTesting(dedupe))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	worker.log = reopened
	if err := worker.ensureArchivedEvent(ctx, checkpoint); err != nil {
		t.Fatalf("cold recovery appended duplicate: %v", err)
	}
	if head, err := reopened.LastSequence(ctx); err != nil || head != archived.Sequence {
		t.Fatalf("cold recovery head = %d, %v; want %d", head, err, archived.Sequence)
	}
	time.Sleep(4 * dedupe)
	conflicting := audit.ArchivedEvent{
		Count: checkpoint.RecordCount, BoundarySeq: checkpoint.BoundarySeq,
		BoundaryHash: checkpoint.BoundaryHash, ArchiveURI: "local://different-segment",
		SourceHistoryRetained: true,
	}
	data, err := json.Marshal(conflicting)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Append(ctx, events.Event{
		ID: archived.ID, Type: audit.EventTypeArchived, TenantID: tenant,
		SchemaVersion: audit.ArchivedEventSchemaVersion, Data: data,
	}); err != nil {
		t.Fatal(err)
	}
	if err := worker.ensureArchivedEvent(ctx, checkpoint); !errors.Is(err, events.ErrConflictingEventIdentity) {
		t.Fatalf("conflicting retained archive identity was accepted: %v", err)
	}
}
