// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestProgressReadsExactStartAcrossColdRestart(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "nats")
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "unrelated.event", TenantID: "tenant-b", Data: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(projections.LicensedCryptoMigrationStarted{RunID: "run-a"})
	if err != nil {
		t.Fatal(err)
	}
	start, err := log.Append(ctx, events.Event{ID: migrationStartEventID("tenant-a", "run-a"),
		Type: projections.EventLicensedCryptoMigrationStarted, TenantID: "tenant-a", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	projection := NewProgressProjection(nil)
	service := &pqcMigrationService{log: log, progress: projection}
	result, err := service.Progress(ctx, "tenant-a", "run-a")
	if err != nil || result.RunID != "run-a" || projection.RunStartSequence("tenant-a", "run-a") != start.Sequence {
		t.Fatalf("indexed progress before tail: result=%+v sequence=%d error=%v", result,
			projection.RunStartSequence("tenant-a", "run-a"), err)
	}
	if _, err := service.Progress(ctx, "tenant-b", "run-a"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-tenant start lookup: %v, want not found", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	// A replacement process starts with no in-memory projection. The durable
	// event-ID index and exact canonical envelope recover the start directly.
	cold := &pqcMigrationService{log: reopened, progress: NewProgressProjection(nil)}
	result, err = cold.Progress(ctx, "tenant-a", "run-a")
	if err != nil || result.RunID != "run-a" || cold.progress.RunStartSequence("tenant-a", "run-a") != start.Sequence {
		t.Fatalf("cold indexed progress: result=%+v sequence=%d error=%v", result,
			cold.progress.RunStartSequence("tenant-a", "run-a"), err)
	}
	// A pre-upgrade random-ID start is still reachable through the exact
	// sequence retained by the boot-rebuilt projection.
	legacyData, err := json.Marshal(projections.LicensedCryptoMigrationStarted{RunID: "legacy-run"})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := reopened.Append(ctx, events.Event{Type: projections.EventLicensedCryptoMigrationStarted,
		TenantID: "tenant-a", Data: legacyData})
	if err != nil {
		t.Fatal(err)
	}
	if err := cold.progress.Apply(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	result, err = cold.Progress(ctx, "tenant-a", "legacy-run")
	if err != nil || result.RunID != "legacy-run" {
		t.Fatalf("legacy sequence progress: result=%+v error=%v", result, err)
	}
}

func TestProgressRejectsConflictingStartIdentity(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	data, err := json.Marshal(projections.LicensedCryptoMigrationStarted{RunID: "another-run"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{ID: migrationStartEventID("tenant-a", "run-a"),
		Type: projections.EventLicensedCryptoMigrationStarted, TenantID: "tenant-a", Data: data}); err != nil {
		t.Fatal(err)
	}
	service := &pqcMigrationService{log: log, progress: NewProgressProjection(nil)}
	if _, err := service.Progress(ctx, "tenant-a", "run-a"); err == nil {
		t.Fatal("conflicting run identity was accepted")
	}
}

func TestProgressRejectsProjectionThatDiffersFromRetainedStart(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	valid, err := json.Marshal(projections.LicensedCryptoMigrationStarted{RunID: "run-a"})
	if err != nil {
		t.Fatal(err)
	}
	start, err := log.Append(ctx, events.Event{ID: migrationStartEventID("tenant-a", "run-a"),
		Type: projections.EventLicensedCryptoMigrationStarted, TenantID: "tenant-a", Data: valid})
	if err != nil {
		t.Fatal(err)
	}
	projection := NewProgressProjection(nil)
	stale := start
	stale.Data = []byte(`{"run_id":"run-a","queued":99}`)
	if err := projection.Apply(ctx, stale); err != nil {
		t.Fatal(err)
	}
	service := &pqcMigrationService{log: log, progress: projection}
	if _, err := service.Progress(ctx, "tenant-a", "run-a"); err == nil {
		t.Fatal("mismatched projected start was accepted as source evidence")
	}
}
