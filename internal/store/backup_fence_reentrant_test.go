// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/audit"
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
		t.Fatalf("cancelled external mutation = %v, want context.Canceled", err)
	}

	close(releaseFence)
	if err := waitHistoryRewriteResult(t, fenceResult); err != nil {
		t.Fatalf("release backup fence: %v", err)
	}
	if _, ok, err := peer.LatestAuditCheckpoint(context.Background(), tenantA); err != nil {
		t.Fatalf("LatestAuditCheckpoint: %v", err)
	} else if ok {
		t.Fatal("cancelled external mutation persisted a checkpoint")
	}
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
