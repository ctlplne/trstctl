// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/store"
)

func TestBackupWriteFenceNestedAuditCheckpointReadUsesOwningSession(t *testing.T) {
	primary := newStore(t)
	ctx := context.Background()
	checkpoint := audit.Checkpoint{
		TenantID:     tenantA,
		BoundarySeq:  42,
		BoundaryHash: "retained-chain-head",
		RecordCount:  17,
		ArchiveURI:   "s3://audit/tenant-a/42",
	}
	if err := primary.SaveAuditCheckpoint(ctx, checkpoint); err != nil {
		t.Fatalf("SaveAuditCheckpoint: %v", err)
	}

	// Reserve 15/16 connections. The exclusive fence owns the final session, so
	// both nested tenant reads can succeed only by reusing that exact session.
	// An implementation that merely skips the shared lock on a second pooled
	// connection deadlocks at this boundary.
	held := reserveStoreConnections(t, primary, 15)
	defer releaseStoreConnections(held)

	fenceCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := primary.WithBackupWriteFence(fenceCtx, func(ownerCtx context.Context) error {
		if got := primary.SystemPool().Stat().AcquiredConns(); got != 16 {
			t.Fatalf("connections while exclusive fence held = %d, want 16", got)
		}

		if cp, ok, err := primary.LatestAuditCheckpoint(ownerCtx, tenantB); err != nil {
			return err
		} else if ok {
			t.Fatalf("no-checkpoint tenant unexpectedly returned %+v", cp)
		}

		cp, ok, err := primary.LatestAuditCheckpoint(ownerCtx, tenantA)
		if err != nil {
			return err
		}
		if !ok {
			t.Fatal("existing checkpoint was not found")
		}
		if cp != checkpoint {
			t.Fatalf("checkpoint = %+v, want %+v", cp, checkpoint)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("nested audit reads under exclusive backup fence: %v", err)
	}
}

func TestBackupWriteFenceTokenIsStoreBoundAndExternalMutationBlocks(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	mutation := audit.Checkpoint{
		TenantID:     tenantA,
		BoundarySeq:  7,
		BoundaryHash: "external-mutation",
		RecordCount:  3,
		ArchiveURI:   "s3://audit/tenant-a/7",
	}
	mutationResult := make(chan error, 1)

	err := primary.WithBackupWriteFence(context.Background(), func(ownerCtx context.Context) error {
		// Even though the peer receives the owner's context, it is a different
		// Store and PostgreSQL session. The private lease must not authorize it.
		go func() {
			mutationResult <- peer.SaveAuditCheckpoint(ownerCtx, mutation)
		}()
		waitForAcquiredConnections(t, peer, 1)
		select {
		case err := <-mutationResult:
			t.Fatalf("external mutation bypassed the exclusive fence: %v", err)
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatalf("exclusive backup fence: %v", err)
	}
	if err := waitHistoryRewriteResult(t, mutationResult); err != nil {
		t.Fatalf("external mutation after fence release: %v", err)
	}
	cp, ok, err := peer.LatestAuditCheckpoint(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("LatestAuditCheckpoint: %v", err)
	}
	if !ok || cp != mutation {
		t.Fatalf("persisted external mutation = (%+v, %v), want (%+v, true)", cp, ok, mutation)
	}
}

func TestEscapedBackupWriteFenceContextBecomesInert(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)

	var escaped context.Context
	if err := primary.WithBackupWriteFence(context.Background(), func(ownerCtx context.Context) error {
		escaped = ownerCtx
		return nil
	}); err != nil {
		t.Fatalf("capture fence context: %v", err)
	}
	if escaped == nil {
		t.Fatal("exclusive fence did not pass its scoped context")
	}

	peerEntered := make(chan struct{})
	releasePeer := make(chan struct{})
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- peer.WithBackupWriteFence(context.Background(), func(context.Context) error {
			close(peerEntered)
			<-releasePeer
			return nil
		})
	}()
	<-peerEntered

	type checkpointResult struct {
		ok  bool
		err error
	}
	readResult := make(chan checkpointResult, 1)
	go func() {
		_, ok, err := primary.LatestAuditCheckpoint(escaped, tenantA)
		readResult <- checkpointResult{ok: ok, err: err}
	}()
	waitForAcquiredConnections(t, primary, 1)
	select {
	case result := <-readResult:
		t.Fatalf("escaped fence context bypassed a later exclusive fence: %+v", result)
	default:
	}

	close(releasePeer)
	if err := waitHistoryRewriteResult(t, peerResult); err != nil {
		t.Fatalf("release peer fence: %v", err)
	}
	select {
	case result := <-readResult:
		if result.err != nil {
			t.Fatalf("tenant read after later fence released: %v", result.err)
		}
		if result.ok {
			t.Fatal("unexpected checkpoint after escaped-context read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("escaped-context tenant read stayed blocked after fence release")
	}
}

func TestBackupWriteFenceCancelledExternalMutationDoesNotRun(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	fenceEntered := make(chan struct{})
	releaseFence := make(chan struct{})
	fenceResult := make(chan error, 1)
	go func() {
		fenceResult <- primary.WithBackupWriteFence(context.Background(), func(context.Context) error {
			close(fenceEntered)
			<-releaseFence
			return nil
		})
	}()
	<-fenceEntered

	waitCtx, cancelWait := context.WithCancel(context.Background())
	mutationResult := make(chan error, 1)
	go func() {
		mutationResult <- peer.SaveAuditCheckpoint(waitCtx, audit.Checkpoint{
			TenantID:     tenantA,
			BoundarySeq:  9,
			BoundaryHash: "must-not-land",
			ArchiveURI:   "s3://audit/tenant-a/9",
		})
	}()
	waitForAcquiredConnections(t, peer, 1)
	cancelWait()
	if err := waitHistoryRewriteResult(t, mutationResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled external mutation = %v, want context.Canceled", err)
	}

	close(releaseFence)
	if err := waitHistoryRewriteResult(t, fenceResult); err != nil {
		t.Fatalf("release backup fence: %v", err)
	}
	if _, ok, err := peer.LatestAuditCheckpoint(context.Background(), tenantA); err != nil {
		t.Fatalf("LatestAuditCheckpoint: %v", err)
	} else if ok {
		t.Fatal("canceled external mutation persisted a checkpoint")
	}
}

func TestPostgresStateSnapshotFenceBlocksExclusiveCutoverUntilSnapshotEnds(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	ctx := context.Background()
	tx, err := primary.BeginPostgresStateSnapshotTx(ctx)
	if err != nil {
		t.Fatalf("begin postgres-state snapshot: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	fenceEntered := make(chan struct{})
	fenceResult := make(chan error, 1)
	go func() {
		fenceResult <- peer.WithBackupWriteFence(ctx, func(context.Context) error {
			close(fenceEntered)
			return nil
		})
	}()
	waitForAcquiredConnections(t, peer, 1)
	select {
	case <-fenceEntered:
		t.Fatal("exclusive history cutover entered while PostgreSQL-state snapshot was active")
	default:
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("finish postgres-state snapshot: %v", err)
	}
	select {
	case err := <-fenceResult:
		if err != nil {
			t.Fatalf("exclusive cutover after snapshot: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exclusive cutover stayed blocked after PostgreSQL-state snapshot ended")
	}
}

func TestPostgresStateSnapshotRecognizesOwningExclusiveFenceContext(t *testing.T) {
	primary := newStore(t)
	held := reserveStoreConnections(t, primary, 15)
	defer releaseStoreConnections(held)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := primary.WithBackupWriteFence(ctx, func(fenceCtx context.Context) error {
		tx, err := primary.BeginPostgresStateSnapshotTx(fenceCtx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(fenceCtx) }()
		return nil
	}); err != nil {
		t.Fatalf("pin snapshot inside owning exclusive fence: %v", err)
	}
}

func TestStandalonePostgresStateSnapshotPinsAfterCrossingPrivacyCutover(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	ctx := context.Background()
	const tenantID = "a1140000-0000-4000-8000-000000000114"
	cleanup := func() {
		_, _ = primary.SystemPool().Exec(context.Background(),
			`DELETE FROM privacy_subject_erasure_preparations WHERE tenant_id = $1`, tenantID)
	}
	cleanup()
	t.Cleanup(cleanup)

	cutoverEntered := make(chan struct{})
	commitCutover := make(chan struct{})
	cutoverResult := make(chan error, 1)
	go func() {
		cutoverResult <- peer.WithBackupWriteFence(ctx, func(fenceCtx context.Context) error {
			close(cutoverEntered)
			<-commitCutover
			return peer.WithTenant(fenceCtx, tenantID, func(tx pgx.Tx) error {
				_, err := tx.Exec(fenceCtx,
					`INSERT INTO privacy_subject_erasure_preparations
				        (tenant_id, operation_id, request_binding, event_id,
				         rewrite_operation_id, target_generation, subject_ref,
				         requested_by_ref, reason, selectors, counts,
				         recovery_fences, erased_at)
				 VALUES ($1, 'privacy-crossing-backup', 'binding', 'event',
				         'rewrite', 'generation', $2, '', '', '{}'::jsonb,
				         '{}'::jsonb, '[]'::jsonb, now())`,
					tenantID, strings.Repeat("a", 64))
				return err
			})
		})
	}()
	<-cutoverEntered

	type exportResult struct {
		err error
	}
	var artifact bytes.Buffer
	exportDone := make(chan exportResult, 1)
	go func() {
		_, err := backup.WritePostgresState(ctx, primary, &artifact)
		exportDone <- exportResult{err: err}
	}()
	waitForAcquiredConnections(t, primary, 1)
	waitForAdvisoryLockWaiter(t, peer, store.BackupWriteFenceAdvisoryLockKey)
	select {
	case result := <-exportDone:
		t.Fatalf("standalone export crossed an active exclusive cutover: %v", result.err)
	default:
	}

	close(commitCutover)
	if err := waitHistoryRewriteResult(t, cutoverResult); err != nil {
		t.Fatalf("commit privacy cutover marker: %v", err)
	}
	select {
	case result := <-exportDone:
		if !errors.Is(result.err, store.ErrPrivacySubjectErasurePreparationActive) {
			t.Fatalf("crossing export error = %v, want committed privacy preparation", result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("standalone export did not resume after privacy cutover committed")
	}
	if artifact.Len() != 0 {
		t.Fatalf("crossing export wrote %d pre-preparation bytes", artifact.Len())
	}
}

func TestFullBackupSnapshotDowngradeBlocksCrossingPrivacyCutoverUntilExportEnds(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	ctx := context.Background()
	const tenantID = "a1140000-0000-4000-8000-000000000115"
	cleanup := func() {
		_, _ = primary.SystemPool().Exec(context.Background(),
			`DELETE FROM privacy_subject_erasure_preparations WHERE tenant_id = $1`, tenantID)
	}
	cleanup()
	t.Cleanup(cleanup)

	var snapshot *backup.PostgresStateSnapshot
	if err := primary.WithBackupWriteFence(ctx, func(fenceCtx context.Context) error {
		var err error
		snapshot, err = backup.BeginPostgresStateSnapshot(fenceCtx, primary)
		return err
	}); err != nil {
		t.Fatalf("pin full-backup snapshot under exclusive cut: %v", err)
	}
	defer func() {
		if snapshot != nil {
			_ = snapshot.Rollback(context.Background())
		}
	}()

	cutoverEntered := make(chan struct{})
	cutoverResult := make(chan error, 1)
	go func() {
		cutoverResult <- peer.WithBackupWriteFence(ctx, func(fenceCtx context.Context) error {
			close(cutoverEntered)
			return peer.WithTenant(fenceCtx, tenantID, func(tx pgx.Tx) error {
				_, err := tx.Exec(fenceCtx,
					`INSERT INTO privacy_subject_erasure_preparations
				        (tenant_id, operation_id, request_binding, event_id,
				         rewrite_operation_id, target_generation, subject_ref,
				         requested_by_ref, reason, selectors, counts,
				         recovery_fences, erased_at)
				 VALUES ($1, 'privacy-crossing-full-backup', 'binding', 'event',
				         'rewrite', 'generation', $2, '', '', '{}'::jsonb,
				         '{}'::jsonb, '[]'::jsonb, now())`,
					tenantID, strings.Repeat("b", 64))
				return err
			})
		})
	}()
	waitForAcquiredConnections(t, peer, 1)
	waitForAdvisoryLockWaiter(t, peer, store.BackupWriteFenceAdvisoryLockKey)
	select {
	case <-cutoverEntered:
		t.Fatal("privacy cutover crossed the full-backup exclusive-to-shared handoff")
	default:
	}

	// Model the full coordinator's later PostgreSQL stream. It must stay on the
	// pre-cutover snapshot paired with this event cut while the new cutover waits.
	const eventCut = uint64(114)
	var artifact bytes.Buffer
	summary, err := backup.WritePostgresStateTx(ctx, snapshot, &artifact, eventCut)
	if err != nil {
		t.Fatalf("stream full-backup PostgreSQL snapshot: %v", err)
	}
	if summary.EventCutSequence != eventCut ||
		summary.Tables["privacy_subject_erasure_preparations"] != 0 {
		t.Fatalf("pre-cutover PostgreSQL artifact summary = %+v", summary)
	}
	verified, err := backup.VerifyPostgresState(bytes.NewReader(artifact.Bytes()))
	if err != nil {
		t.Fatalf("verify pre-cutover PostgreSQL artifact: %v", err)
	}
	if verified.EventCutSequence != eventCut ||
		verified.Tables["privacy_subject_erasure_preparations"] != 0 {
		t.Fatalf("verified pre-cutover PostgreSQL artifact = %+v", verified)
	}
	select {
	case <-cutoverEntered:
		t.Fatal("privacy cutover entered before the full-backup snapshot committed")
	default:
	}

	if err := snapshot.Commit(ctx); err != nil {
		t.Fatalf("finish full-backup PostgreSQL snapshot: %v", err)
	}
	snapshot = nil
	if err := waitHistoryRewriteResult(t, cutoverResult); err != nil {
		t.Fatalf("privacy cutover after full-backup snapshot: %v", err)
	}
	var livePreparation int
	if err := primary.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM privacy_subject_erasure_preparations WHERE tenant_id = $1`,
		tenantID).Scan(&livePreparation); err != nil {
		t.Fatalf("inspect post-backup privacy preparation: %v", err)
	}
	if livePreparation != 1 {
		t.Fatalf("post-backup privacy preparations = %d, want 1", livePreparation)
	}
}

func TestFullBackupSnapshotHandoffGuardFailureReleasesConnectionAndFence(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	ctx := context.Background()
	const tenantID = "a1140000-0000-4000-8000-000000000116"
	if _, err := primary.SystemPool().Exec(ctx,
		`INSERT INTO privacy_subject_erasure_preparations
		        (tenant_id, operation_id, request_binding, event_id,
		         rewrite_operation_id, target_generation, subject_ref,
		         requested_by_ref, reason, selectors, counts,
		         recovery_fences, erased_at)
		 VALUES ($1, 'privacy-full-backup-failure', 'binding', 'event',
		         'rewrite', 'generation', $2, '', '', '{}'::jsonb,
		         '{}'::jsonb, '[]'::jsonb, now())`,
		tenantID, strings.Repeat("c", 64)); err != nil {
		t.Fatalf("seed active privacy preparation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = primary.SystemPool().Exec(context.Background(),
			`DELETE FROM privacy_subject_erasure_preparations WHERE tenant_id = $1`, tenantID)
	})

	err := primary.WithBackupWriteFence(ctx, func(fenceCtx context.Context) error {
		_, err := backup.BeginPostgresStateSnapshot(fenceCtx, primary)
		return err
	})
	if !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
		t.Fatalf("full-backup handoff guard error = %v, want active preparation", err)
	}
	waitForAcquiredConnections(t, primary, 0)

	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := peer.WithBackupWriteFence(probeCtx, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("exclusive fence after failed full-backup handoff: %v", err)
	}
}

func TestStandalonePostgresStateSnapshotUsesOneAvailablePoolConnection(t *testing.T) {
	primary := newStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := primary.SystemPool().Exec(ctx,
		`DELETE FROM privacy_subject_erasure_preparations`); err != nil {
		t.Fatalf("clear privacy preparations: %v", err)
	}

	// Reserve 15 of the store's 16 bounded slots. The snapshot must acquire the
	// last connection, establish both advisory grants, begin, export, and commit
	// on that same connection. A two-connection fence/snapshot design deadlocks.
	held := reserveStoreConnections(t, primary, 15)
	defer releaseStoreConnections(held)
	var artifact bytes.Buffer
	if _, err := backup.WritePostgresState(ctx, primary, &artifact); err != nil {
		t.Fatalf("one-slot standalone PostgreSQL-state export: %v", err)
	}
	if artifact.Len() == 0 {
		t.Fatal("one-slot standalone PostgreSQL-state export wrote no artifact")
	}
}

func TestPostgresStateRestorePhysicallyPurgesLegacySnapshotPayloadAUD114(t *testing.T) {
	primary := newStore(t)
	ctx := context.Background()
	if _, err := primary.SystemPool().Exec(ctx,
		`DELETE FROM privacy_subject_erasure_preparations`); err != nil {
		t.Fatalf("clear privacy preparations: %v", err)
	}

	// The independent-state stream deliberately never contains the ephemeral
	// snapshot table. Seed the valid stream first, then model an already-migrated
	// restore target on which an old replica left one raw v21 blob behind.
	var artifact bytes.Buffer
	if _, err := backup.WritePostgresState(ctx, primary, &artifact); err != nil {
		t.Fatalf("write postgres-state fixture: %v", err)
	}
	if _, err := primary.SystemPool().Exec(ctx,
		`ALTER TABLE read_model_snapshots
		 DROP CONSTRAINT IF EXISTS read_model_snapshots_format_floor_v22`); err != nil {
		t.Fatalf("model externally restored legacy snapshot schema: %v", err)
	}
	const rawSubject = "aud114-restore-raw-subject"
	if _, err := primary.SystemPool().Exec(ctx, `
		INSERT INTO read_model_snapshots
		       (tenant_id, covered_seq, format_version, payload)
		VALUES ('a1140000-0000-4000-8000-000000000004', 21, 21,
		        jsonb_build_object('owners', jsonb_build_array(
		          jsonb_build_object('name', $1::text))))`, rawSubject); err != nil {
		t.Fatalf("seed legacy snapshot before restore: %v", err)
	}
	if _, err := backup.RestorePostgresState(ctx, primary, bytes.NewReader(artifact.Bytes())); err != nil {
		t.Fatalf("restore postgres state: %v", err)
	}
	var rows, rawRows int
	if err := primary.SystemPool().QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE payload::text LIKE '%' || $1 || '%')
		  FROM read_model_snapshots`, rawSubject).Scan(&rows, &rawRows); err != nil {
		t.Fatalf("inspect snapshots after postgres-state restore: %v", err)
	}
	if rows != 0 || rawRows != 0 {
		t.Fatalf("snapshots after postgres-state restore = rows:%d raw-subject-rows:%d, want empty",
			rows, rawRows)
	}
	if err := primary.Migrate(ctx); err != nil {
		t.Fatalf("repair snapshot format floor after external-schema restore fixture: %v", err)
	}
}

func waitForAdvisoryLockWaiter(t *testing.T, s *store.Store, key int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := s.SystemPool().QueryRow(context.Background(), `
			SELECT EXISTS (
				SELECT 1
				  FROM pg_locks
				 WHERE locktype = 'advisory'
				   AND NOT granted
				   AND objsubid = 1
				   AND ((classid::bigint << 32) | objid::bigint) = $1
			)`, key).Scan(&waiting); err != nil {
			t.Fatalf("inspect advisory lock waiter: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("standalone PostgreSQL-state snapshot never waited on the privacy cutover fence")
}

func reserveStoreConnections(t *testing.T, s *store.Store, count int) []*pgxpool.Conn {
	t.Helper()
	held := make([]*pgxpool.Conn, 0, count)
	for i := 0; i < count; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := s.SystemPool().Acquire(ctx)
		cancel()
		if err != nil {
			releaseStoreConnections(held)
			t.Fatalf("reserve store connection %d: %v", i, err)
		}
		held = append(held, conn)
	}
	return held
}

func releaseStoreConnections(conns []*pgxpool.Conn) {
	for _, conn := range conns {
		conn.Release()
	}
}
