package audit_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

// TestRetentionWorkerArchivesPrunesAndKeepsChainVerifiable is R4.4's core
// acceptance: seed records past the retention window, run the worker, and assert
// the old records are archived (recoverable + chain-verifiable), pruned from the
// hot log, and that VerifyChain still holds across the sealed checkpoint with the
// surviving records' hashes unchanged.
func TestRetentionWorkerArchivesPrunesAndKeepsChainVerifiable(t *testing.T) {
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
	if sum.RecordsArchived != nOld || sum.RecordsPruned != nOld || sum.TenantsProcessed != 1 {
		t.Fatalf("summary = %+v, want archived/pruned=%d, tenants=1", sum, nOld)
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

	// (b) Pruned from hot storage: the old sequences are gone from the raw log.
	live := map[string]int{}
	rawCount := 0
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		rawCount++
		live[e.Type]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Survivors: 2 recent "thing.created" + 1 "audit.archived" the worker emitted.
	if got := live["thing.created"]; got != nRecent {
		t.Errorf("live thing.created = %d, want %d (3 old pruned)", got, nRecent)
	}
	if got := live[audit.EventTypeArchived]; got != 1 {
		t.Errorf("audit.archived events = %d, want 1", got)
	}

	// (c) VerifyChain holds across the checkpoint, and the survivors keep their
	// original hashes (the prune is hash-stable).
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
			t.Errorf("survivor %d hash changed across prune: got %s want %s", i, post[i].Hash, want)
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
// no-op (Retention=0): nothing is archived or pruned.
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
