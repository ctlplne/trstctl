// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/auditcompliance"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
)

// memCheckpoints is an in-memory audit.CheckpointSource + audit.CheckpointSink for
// the worker unit test (the store implements the real one).
type memCheckpoints struct {
	mu sync.Mutex
	m  map[string]audit.Checkpoint
}

type retentionHistoryReadKey struct{}

type retentionHistoryCoordinator struct {
	operation sync.Mutex
	barrier   sync.RWMutex
	readDepth atomic.Int64
}

func (c *retentionHistoryCoordinator) WithRewriteOperation(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	c.operation.Lock()
	defer c.operation.Unlock()
	return fn(ctx)
}

func (c *retentionHistoryCoordinator) WithCutover(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	c.barrier.Lock()
	defer c.barrier.Unlock()
	return fn(ctx)
}

func (c *retentionHistoryCoordinator) WithRead(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	if owner, ok := ctx.Value(retentionHistoryReadKey{}).(*retentionHistoryCoordinator); ok &&
		owner == c {
		return fn(ctx)
	}
	c.barrier.RLock()
	c.readDepth.Add(1)
	defer func() {
		c.readDepth.Add(-1)
		c.barrier.RUnlock()
	}()
	return fn(context.WithValue(ctx, retentionHistoryReadKey{}, c))
}

type blockingArchiver struct {
	coordinator *retentionHistoryCoordinator
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
}

func (a *blockingArchiver) Archive(
	ctx context.Context,
	_ string,
	_ uint64,
	_ string,
) (string, error) {
	if a.coordinator.readDepth.Load() == 0 {
		return "", fmt.Errorf("archive ran outside pinned history read")
	}
	a.once.Do(func() { close(a.entered) })
	select {
	case <-a.release:
		return "memory://retention/archive.jws", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

type blockingCheckpoints struct {
	*memCheckpoints
	entered chan struct{}
	release chan struct{}
	once    sync.Once
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

func (c *blockingCheckpoints) SaveAuditCheckpoint(ctx context.Context, cp audit.Checkpoint) error {
	c.once.Do(func() { close(c.entered) })
	select {
	case <-c.release:
		return c.memCheckpoints.SaveAuditCheckpoint(ctx, cp)
	case <-ctx.Done():
		return ctx.Err()
	}
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
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	cp := &memCheckpoints{}
	archiveDir := t.TempDir()
	svc := audit.NewService(log, key, audit.WithCheckpoints(cp))
	worker := auditcompliance.NewRetentionWorker(svc, log, auditcompliance.DirArchiver{Dir: archiveDir}, cp, 24*time.Hour, key)

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
	bundle, err := audit.VerifyRetentionBundle(string(signed), svc.VerificationKeys())
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

	// (c) VerifyChain holds across the logical checkpoint, and visible survivors
	// keep their original hashes.
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
	stream, seed, err := svc.SearchWithSeed(ctx, audit.Query{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	if seed != sealed.BoundaryHash || len(stream) != len(post) {
		t.Fatalf("stream seed/records = (%q, %d), want checkpoint (%q, %d)",
			seed, len(stream), sealed.BoundaryHash, len(post))
	}
	if head, err := audit.VerifyChainFrom(seed, stream); err != nil || head != stream[len(stream)-1].Hash {
		t.Fatalf("stream could not be verified from exported checkpoint: head=%q err=%v", head, err)
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
// no-op (Retention=0): nothing is archived or pruned.
func TestRetentionWorkerDoesNothingWithoutWindow(t *testing.T) {
	ctx := context.Background()
	log := openTestLog(t)
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	cp := &memCheckpoints{}
	svc := audit.NewService(log, key, audit.WithCheckpoints(cp))
	worker := auditcompliance.NewRetentionWorker(svc, log, auditcompliance.DirArchiver{Dir: t.TempDir()}, cp, 0, key)

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

func TestRetentionWorkerKeepsTenantQueryFloorsIndependent(t *testing.T) {
	ctx := context.Background()
	log := openTestLog(t)
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	const (
		tenantA = "66666666-6666-6666-6666-666666666666"
		tenantB = "77777777-7777-7777-7777-777777777777"
	)
	old := time.Now().Add(-48 * time.Hour)
	for _, event := range []events.Event{
		{ID: "retention-a-old", Type: "owner.created", TenantID: tenantA, Time: old},
		{ID: "retention-b-old", Type: "owner.created", TenantID: tenantB, Time: old},
		{ID: "retention-a-new", Type: "owner.updated", TenantID: tenantA, Time: time.Now()},
		{ID: "retention-b-new", Type: "owner.updated", TenantID: tenantB, Time: time.Now()},
	} {
		if _, err := log.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	checkpoints := &memCheckpoints{}
	svc := audit.NewService(log, key, audit.WithCheckpoints(checkpoints))
	worker := auditcompliance.NewRetentionWorker(
		svc, log, auditcompliance.DirArchiver{Dir: t.TempDir()}, checkpoints, time.Hour, key)
	summary, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.TenantsProcessed != 2 || summary.RecordsArchived != 2 {
		t.Fatalf("summary = %+v, want one retired record per tenant", summary)
	}
	for _, tenantID := range []string{tenantA, tenantB} {
		visible, err := svc.Search(ctx, audit.Query{TenantID: tenantID})
		if err != nil {
			t.Fatal(err)
		}
		if len(visible) != 2 ||
			visible[0].ID != "retention-"+map[string]string{tenantA: "a", tenantB: "b"}[tenantID]+"-new" ||
			visible[1].Type != audit.EventTypeArchived {
			t.Fatalf("tenant %s visible records = %+v, want own new event plus own checkpoint event", tenantID, visible)
		}
	}
}

func TestRetentionWorkerRetryHealsCheckpointWithoutDuplicatingArchivedEvent(t *testing.T) {
	ctx := context.Background()
	log := openTestLog(t)
	key, err := jose.GenerateRSASigningKey("audit-export")
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
	worker := auditcompliance.NewRetentionWorker(
		svc, log, auditcompliance.DirArchiver{Dir: t.TempDir()}, checkpoints, time.Hour, key)

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
	key, err := jose.GenerateRSASigningKey("audit-export")
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
	worker := auditcompliance.NewRetentionWorker(
		svc, log, auditcompliance.DirArchiver{Dir: t.TempDir()}, checkpoints, time.Hour, key)

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

func TestRetentionPinsArchiveAndExcludesRewriteWhileCheckpointCommits(t *testing.T) {
	ctx := context.Background()
	coordinator := &retentionHistoryCoordinator{}
	log, err := events.Open(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		events.WithHistoryRewriteCoordinator(coordinator),
	)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer func() { _ = log.Close() }()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	if _, err := log.Append(ctx, events.Event{
		ID: "retention-serialized", Type: "owner.updated", TenantID: tenantID,
		Time: time.Now().Add(-48 * time.Hour),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	baseCheckpoints := &memCheckpoints{}
	checkpoints := &blockingCheckpoints{
		memCheckpoints: baseCheckpoints,
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
	}
	archiver := &blockingArchiver{
		coordinator: coordinator,
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	svc := audit.NewService(log, key, audit.WithCheckpoints(checkpoints))
	worker := auditcompliance.NewRetentionWorker(svc, log, archiver, checkpoints, time.Hour, key)
	retentionDone := make(chan error, 1)
	go func() {
		_, err := worker.RunOnce(ctx)
		retentionDone <- err
	}()
	select {
	case <-archiver.entered:
		if coordinator.readDepth.Load() == 0 {
			t.Fatal("signed archive was not protected by a shared history lease")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retention never reached archive")
	}

	rewriteEntered := make(chan struct{})
	rewriteDone := make(chan error, 1)
	go func() {
		rewriteDone <- coordinator.WithRewriteOperation(ctx, func(context.Context) error {
			close(rewriteEntered)
			return nil
		})
	}()
	select {
	case <-rewriteEntered:
		t.Fatal("competing rewrite operation interleaved with pinned retention archive")
	case <-time.After(75 * time.Millisecond):
	}
	close(archiver.release)
	select {
	case <-checkpoints.entered:
		if coordinator.readDepth.Load() != 0 {
			t.Fatal("retention attempted shared-to-exclusive upgrade without releasing read lease")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retention never reached checkpoint")
	}
	select {
	case <-rewriteEntered:
		t.Fatal("competing rewrite entered between archive and checkpoint")
	default:
	}

	// Source history is immutable across logical retention, so a backup history
	// read may proceed while the PostgreSQL checkpoint waits. Its paired PG
	// snapshot will either include the checkpoint or rebuild it from the already
	// appended audit.archived event.
	backupEntered := make(chan struct{})
	backupDone := make(chan error, 1)
	go func() {
		backupDone <- coordinator.WithRead(ctx, func(context.Context) error {
			close(backupEntered)
			return nil
		})
	}()
	select {
	case <-backupEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("logical retention unnecessarily blocked an immutable backup history read")
	}
	select {
	case err := <-backupDone:
		if err != nil {
			t.Fatalf("backup read: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backup read did not finish")
	}
	close(checkpoints.release)
	select {
	case err := <-retentionDone:
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retention did not finish")
	}
	select {
	case err := <-rewriteDone:
		if err != nil {
			t.Fatalf("queued rewrite: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued rewrite did not continue")
	}
}

func TestRewriteRealRetentionCheckpointRetainsReceiptAndReopens(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	verifier := func(_ context.Context, evidence events.TenantDataContinuityEvidence) error {
		report, err := json.Marshal(evidence.Report)
		if err != nil {
			return err
		}
		if !bytes.Equal(report, evidence.Receipt.Data) {
			return fmt.Errorf("receipt does not bind exact report")
		}
		return nil
	}
	log, err := events.Open(
		ctx,
		cfg,
		events.WithHistoryRewriteContinuityVerifier(verifier),
	)
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: "rewrite-before-retention", Type: "secret.version.written",
		TenantID: tenantID, Time: time.Now().Add(-48 * time.Hour),
		Data: []byte(`{"sealed":"deployment-ciphertext"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	options := []events.TenantDataRewriteOption{
		events.WithTenantDataPairValidator(func(_ string, _ int, before, after []byte) error {
			if bytes.Equal(before, after) {
				return fmt.Errorf("unchanged rewrite pair")
			}
			return nil
		}),
		events.WithTenantDataCutoverPreparation(func(
			ctx context.Context,
			_ events.TenantDataRewriteReport,
			proceed func(context.Context) error,
		) error {
			return proceed(ctx)
		}),
		events.WithTenantDataAuditContinuity(func(
			context.Context,
			events.TenantDataAuditView,
		) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: "test-genesis"}, nil
		}),
		events.WithTenantDataContinuity(func(
			_ context.Context,
			report events.TenantDataRewriteReport,
		) (events.Event, error) {
			payload, err := json.Marshal(report)
			return events.Event{
				ID: "rewrite-retention-receipt", Type: "tenant.data.rewrite.receipt",
				TenantID: tenantID, Time: time.Now().UTC(),
				SchemaVersion: events.DefaultSchemaVersion, Data: payload,
			}, err
		}),
	}
	if _, err := log.RewriteTenantData(
		ctx,
		tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			next := bytes.ReplaceAll(data, []byte("deployment"), []byte("tenant"))
			return next, !bytes.Equal(next, data), nil
		},
		options...,
	); err != nil {
		t.Fatalf("RewriteTenantData: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	checkpoints := &memCheckpoints{}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	svc := audit.NewService(log, key, audit.WithCheckpoints(checkpoints))
	worker := auditcompliance.NewRetentionWorker(
		svc, log, auditcompliance.DirArchiver{Dir: t.TempDir()}, checkpoints, time.Nanosecond, key)
	summary, err := worker.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if summary.RecordsArchived < 2 || summary.RecordsSourceRetained < 2 ||
		summary.RecordsPruned != 0 {
		t.Fatalf("retention summary = %+v, want source event and rewrite receipt archived but retained", summary)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := events.Open(
		ctx,
		cfg,
		events.WithHistoryRewriteContinuityVerifier(verifier),
	)
	if err != nil {
		t.Fatalf("Open after logical retention retained rewrite receipt: %v", err)
	}
	_ = reopened.Close()
}

func TestPrivacyRewriteAfterLogicalRetentionKeepsCheckpointReplayable(t *testing.T) {
	ctx := context.Background()
	const tenantID = "55555555-5555-5555-5555-555555555555"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	verifier := func(_ context.Context, evidence events.TenantDataContinuityEvidence) error {
		report, err := json.Marshal(evidence.Report)
		if err != nil {
			return err
		}
		if !bytes.Equal(report, evidence.Receipt.Data) {
			return errors.New("receipt does not bind exact rewrite report")
		}
		return nil
	}
	log, err := events.Open(ctx, cfg, events.WithHistoryRewriteContinuityVerifier(verifier))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		ID: "retained-private-source", Type: "owner.updated", TenantID: tenantID,
		Time: time.Now().Add(-48 * time.Hour),
		Data: []byte(`{"email":"alice@example.com"}`),
	}); err != nil {
		t.Fatal(err)
	}
	checkpoints := &memCheckpoints{}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	svc := audit.NewService(log, key, audit.WithCheckpoints(checkpoints))
	worker := auditcompliance.NewRetentionWorker(
		svc, log, auditcompliance.DirArchiver{Dir: t.TempDir()}, checkpoints, time.Hour, key)
	if _, err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("logical retention: %v", err)
	}
	checkpoint, ok, err := checkpoints.LatestAuditCheckpoint(ctx, tenantID)
	if err != nil || !ok {
		t.Fatalf("checkpoint: ok=%v err=%v", ok, err)
	}

	_, err = log.RewriteTenantData(
		ctx,
		tenantID,
		func(_ string, _ int, data []byte) ([]byte, bool, error) {
			next := bytes.ReplaceAll(data, []byte("alice@example.com"), []byte("erased-subject"))
			return next, !bytes.Equal(next, data), nil
		},
		events.WithTenantDataPairValidator(func(_ string, _ int, before, after []byte) error {
			if bytes.Equal(before, after) {
				return errors.New("rewrite pair is unchanged")
			}
			return nil
		}),
		events.WithTenantDataCutoverPreparation(func(
			ctx context.Context,
			_ events.TenantDataRewriteReport,
			proceed func(context.Context) error,
		) error {
			return proceed(ctx)
		}),
		events.WithTenantDataAuditContinuity(func(
			context.Context,
			events.TenantDataAuditView,
		) (events.TenantDataAuditCheckpoint, error) {
			return events.TenantDataAuditCheckpoint{IdentityDigest: checkpoint.BoundaryHash}, nil
		}),
		events.WithTenantDataContinuity(func(
			_ context.Context,
			report events.TenantDataRewriteReport,
		) (events.Event, error) {
			data, err := json.Marshal(report)
			return events.Event{
				ID: "retained-private-rewrite-receipt", Type: "tenant.data.rewrite.receipt",
				TenantID: tenantID, Time: time.Now().UTC(),
				SchemaVersion: events.DefaultSchemaVersion, Data: data,
			}, err
		}),
	)
	if err != nil {
		t.Fatalf("rewrite after logical retention: %v", err)
	}
	if err := audit.VerifyCheckpointSourceRetained(ctx, log, checkpoint); err != nil {
		t.Fatalf("checkpoint after rewrite: %v", err)
	}
	var raw bytes.Buffer
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		raw.Write(event.Data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw.Bytes(), []byte("alice@example.com")) {
		t.Fatal("retained hidden source still contains erased subject after authorized rewrite")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := events.Open(ctx, cfg, events.WithHistoryRewriteContinuityVerifier(verifier))
	if err != nil {
		t.Fatalf("reopen after retained-prefix rewrite: %v", err)
	}
	_ = reopened.Close()
}
