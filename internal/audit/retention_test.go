// SPDX-License-Identifier: MPL-2.0

package audit_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// memCheckpoints is an in-memory audit.CheckpointSource + audit.CheckpointSink for
// the worker unit test (the store implements the real one).
type memCheckpoints struct {
	mu sync.Mutex
	m  map[string]audit.Checkpoint
}

type failOnceCheckpoints struct {
	*memCheckpoints
	failed bool
}

func (c *failOnceCheckpoints) SaveAuditCheckpoint(ctx context.Context, cp audit.Checkpoint) error {
	if !c.failed {
		c.failed = true
		return errors.New("injected checkpoint write failure")
	}
	return c.memCheckpoints.SaveAuditCheckpoint(ctx, cp)
}

func (c *memCheckpoints) LatestAuditCheckpoint(_ context.Context, tenantID string) (audit.Checkpoint, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.m[tenantID]
	return cp, ok, nil
}

func (c *memCheckpoints) SaveAuditCheckpoint(_ context.Context, cp audit.Checkpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]audit.Checkpoint{}
	}
	if cur, ok := c.m[cp.TenantID]; !ok || cp.BoundarySeq >= cur.BoundarySeq {
		c.m[cp.TenantID] = cp
	}
	return nil
}

func openTestLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

// TestRetentionWorkerArchivesRetiresViewAndRetainsRebuildSource is R4.4's core
// acceptance: due records leave the served audit view behind a verified archive
// checkpoint, while their exact AN-2 envelopes remain available to rebuild.
func TestRetentionWorkerArchivesRetiresViewAndRetainsRebuildSource(t *testing.T) {
	ctx := context.Background()
	log := openTestLog(t)
	keyPath := filepath.Join(t.TempDir(), "audit-key.pem")
	key, err := audit.LoadOrCreateSigningKey(keyPath, "audit-export")
	if err != nil {
		t.Fatal(err)
	}
	cp := &memCheckpoints{}
	archiveDir := t.TempDir()
	svc := audit.NewService(log, key, audit.WithCheckpoints(cp))
	worker := audit.NewRetentionWorker(svc, log, audit.DirArchiver{Dir: archiveDir}, cp, 24*time.Hour)

	const tenant = "11111111-1111-1111-1111-111111111111"
	now := time.Now()
	oldT := now.Add(-48 * time.Hour)
	recentT := now.Add(-1 * time.Minute)
	const nOld, nRecent = 3, 2
	for i := 0; i < nOld; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "thing.created", TenantID: tenant,
			Time: oldT.Add(time.Duration(i) * time.Second), Data: []byte(fmt.Sprintf(`{"old":%d}`, i))}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < nRecent; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "thing.created", TenantID: tenant,
			Time: recentT.Add(time.Duration(i) * time.Second), Data: []byte(fmt.Sprintf(`{"recent":%d}`, i))}); err != nil {
			t.Fatal(err)
		}
	}

	// Pre-run: full chain over all 5 records, capturing the survivors' hashes.
	full, err := svc.Search(ctx, audit.Query{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != nOld+nRecent {
		t.Fatalf("pre-run records = %d, want %d", len(full), nOld+nRecent)
	}
	wantSurvivorHashes := []string{full[nOld].Hash, full[nOld+1].Hash}

	// Run one retention pass.
	sum, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if sum.RecordsArchived != nOld || sum.RecordsSourceRetained != nOld ||
		sum.RecordsPruned != 0 || sum.TenantsProcessed != 1 {
		t.Fatalf("summary = %+v, want archived/source-retained=%d, pruned=0, tenants=1", sum, nOld)
	}

	// (a) Archived: the bundle on disk recovers and its chain verifies.
	matches, _ := filepath.Glob(filepath.Join(archiveDir, tenant, "*.jws"))
	if len(matches) != 1 {
		t.Fatalf("archive files = %v, want exactly 1", matches)
	}
	signed, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := audit.VerifyBundle(string(signed), svc.VerificationKeys())
	if err != nil {
		t.Fatalf("archived bundle failed verification: %v", err)
	}
	if bundle.Count != nOld || len(bundle.Records) != nOld {
		t.Fatalf("archived bundle has %d records, want %d", len(bundle.Records), nOld)
	}
	for _, r := range bundle.Records {
		if r.Time.After(recentT) {
			t.Errorf("archived a record newer than the cutoff: %v", r.Time)
		}
	}

	// (b) Retired from the served audit view but retained in the raw AN-2 source.
	live := map[string]int{}
	rawCount := 0
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		rawCount++
		live[e.Type]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := live["thing.created"]; got != nOld+nRecent {
		t.Errorf("raw thing.created = %d, want %d (source history must remain)", got, nOld+nRecent)
	}
	if got := live[audit.EventTypeArchived]; got != 1 {
		t.Errorf("audit.archived events = %d, want 1", got)
	}
	if rawCount != nOld+nRecent+1 {
		t.Errorf("raw event count = %d, want %d", rawCount, nOld+nRecent+1)
	}

	// (c) VerifyChain holds across the checkpoint, and the survivors keep their
	// original hashes.
	if _, err := svc.VerifyChain(ctx, tenant); err != nil {
		t.Fatalf("VerifyChain across checkpoint failed: %v", err)
	}
	post, err := svc.Search(ctx, audit.Query{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	// post = [recent1, recent2, audit.archived]
	if len(post) != nRecent+1 {
		t.Fatalf("post-run records = %d, want %d", len(post), nRecent+1)
	}
	for i, want := range wantSurvivorHashes {
		if post[i].Hash != want {
			t.Errorf("survivor %d hash changed across retention: got %s want %s", i, post[i].Hash, want)
		}
	}

	// (d) The checkpoint was sealed with the boundary the survivors anchor on.
	sealed, ok, err := cp.LatestAuditCheckpoint(ctx, tenant)
	if err != nil || !ok {
		t.Fatalf("checkpoint not sealed: ok=%v err=%v", ok, err)
	}
	if sealed.RecordCount != nOld || sealed.BoundaryHash != full[nOld-1].Hash || sealed.ArchiveURI == "" {
		t.Errorf("checkpoint = %+v, want count=%d boundaryHash=%s archive set", sealed, nOld, full[nOld-1].Hash)
	}
	if err := audit.VerifyCheckpointSourceRetained(ctx, log, sealed); err != nil {
		t.Fatalf("retained rebuild source: %v", err)
	}

	// (e) A second pass is a no-op: the survivors are still within the window.
	sum2, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum2.RecordsArchived != 0 {
		t.Errorf("second pass archived %d, want 0 (survivors not yet past the window)", sum2.RecordsArchived)
	}
}

// TestRetentionWorkerDoesNothingWithoutWindow confirms an unconfigured worker is a
// no-op (Retention=0): nothing is archived or retired from the served view.
func TestRetentionWorkerDoesNothingWithoutWindow(t *testing.T) {
	ctx := context.Background()
	log := openTestLog(t)
	key, err := audit.LoadOrCreateSigningKey(filepath.Join(t.TempDir(), "k.pem"), "audit-export")
	if err != nil {
		t.Fatal(err)
	}
	cp := &memCheckpoints{}
	svc := audit.NewService(log, key, audit.WithCheckpoints(cp))
	worker := audit.NewRetentionWorker(svc, log, audit.DirArchiver{Dir: t.TempDir()}, cp, 0)

	const tenant = "22222222-2222-2222-2222-222222222222"
	if _, err := log.Append(ctx, events.Event{Type: "thing.created", TenantID: tenant, Time: time.Now().Add(-1000 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	sum, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.RecordsArchived != 0 || sum.RecordsPruned != 0 {
		t.Errorf("no-op worker did work: %+v", sum)
	}
}

func TestRetentionWorkerRetryHealsCheckpointWithoutDuplicatingArchivedEvent(t *testing.T) {
	ctx := context.Background()
	log := openTestLog(t)
	key, err := audit.LoadOrCreateSigningKey(filepath.Join(t.TempDir(), "k.pem"), "audit-export")
	if err != nil {
		t.Fatal(err)
	}
	const tenantID = "33333333-3333-3333-3333-333333333333"
	if _, err := log.Append(ctx, events.Event{
		ID: "retention-crash-source", Type: "owner.created", TenantID: tenantID,
		Time: time.Now().Add(-48 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	base := &memCheckpoints{}
	checkpoints := &failOnceCheckpoints{memCheckpoints: base}
	svc := audit.NewService(log, key, audit.WithCheckpoints(checkpoints))
	worker := audit.NewRetentionWorker(
		svc, log, audit.DirArchiver{Dir: t.TempDir()}, checkpoints, time.Hour,
	)

	if _, err := worker.RunOnce(ctx); err == nil ||
		!strings.Contains(err.Error(), "injected checkpoint write failure") {
		t.Fatalf("first RunOnce error = %v, want injected checkpoint failure", err)
	}
	if _, ok, err := base.LatestAuditCheckpoint(ctx, tenantID); err != nil || ok {
		t.Fatalf("checkpoint survived injected failure: ok=%v err=%v", ok, err)
	}
	assertArchivedEventCount(t, log, tenantID, 1)

	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("retry RunOnce: %v", err)
	}
	checkpoint, ok, err := base.LatestAuditCheckpoint(ctx, tenantID)
	if err != nil || !ok {
		t.Fatalf("retry did not heal checkpoint: ok=%v err=%v", ok, err)
	}
	if err := audit.VerifyCheckpointSourceRetained(ctx, log, checkpoint); err != nil {
		t.Fatalf("healed checkpoint source: %v", err)
	}
	assertArchivedEventCount(t, log, tenantID, 1)
}

func TestRetentionWorkerRepairsMissingArchivedEventFromRetainedCheckpoint(t *testing.T) {
	ctx := context.Background()
	log := openTestLog(t)
	key, err := audit.LoadOrCreateSigningKey(filepath.Join(t.TempDir(), "k.pem"), "audit-export")
	if err != nil {
		t.Fatal(err)
	}
	const tenantID = "44444444-4444-4444-4444-444444444444"
	appended, err := log.Append(ctx, events.Event{
		ID: "retention-presealed-source", Type: "owner.created", TenantID: tenantID,
		Time: time.Now().Add(-48 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutCheckpoint := audit.NewService(log, key)
	records, err := withoutCheckpoint.Search(ctx, audit.Query{TenantID: tenantID})
	if err != nil || len(records) != 1 {
		t.Fatalf("read checkpoint boundary: records=%d err=%v", len(records), err)
	}
	checkpoints := &memCheckpoints{}
	if err := checkpoints.SaveAuditCheckpoint(ctx, audit.Checkpoint{
		TenantID: tenantID, BoundarySeq: appended.Sequence,
		BoundaryHash: records[0].Hash, RecordCount: 1,
		ArchiveURI: "memory://retention/presealed.jws",
	}); err != nil {
		t.Fatal(err)
	}
	svc := audit.NewService(log, key, audit.WithCheckpoints(checkpoints))
	worker := audit.NewRetentionWorker(
		svc, log, audit.DirArchiver{Dir: t.TempDir()}, checkpoints, time.Hour,
	)

	summary, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if summary.RecordsArchived != 0 {
		t.Fatalf("recovery re-archived %d records, want only event repair", summary.RecordsArchived)
	}
	assertArchivedEventCount(t, log, tenantID, 1)
}

func assertArchivedEventCount(t *testing.T, log *events.Log, tenantID string, want int) {
	t.Helper()
	got := 0
	if err := log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID == tenantID && event.Type == audit.EventTypeArchived {
			got++
			if event.SchemaVersion != audit.ArchivedEventSchemaVersion {
				t.Errorf("audit.archived schema version = %d, want %d", event.SchemaVersion, audit.ArchivedEventSchemaVersion)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("audit.archived event count = %d, want %d", got, want)
	}
}
