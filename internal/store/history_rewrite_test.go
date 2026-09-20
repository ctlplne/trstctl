// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func openHistoryRewritePeer(t *testing.T) *store.Store {
	t.Helper()
	peer, err := store.Open(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("store.Open peer: %v", err)
	}
	t.Cleanup(peer.Close)
	return peer
}

func waitForAcquiredConnections(t *testing.T, s *store.Store, want int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.SystemPool().Stat().AcquiredConns(); got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("acquired connections = %d, want %d", s.SystemPool().Stat().AcquiredConns(), want)
}

func waitHistoryRewriteResult(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for history-rewrite callback")
		return nil
	}
}

func TestHistoryRewriteOperationIsSingleAcrossStoreInstances(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	first := store.NewHistoryRewriteCoordinator(primary)
	second := store.NewHistoryRewriteCoordinator(peer)

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- first.WithRewriteOperation(context.Background(), func(context.Context) error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	<-firstEntered

	secondEntered := make(chan struct{}, 1)
	waitCtx, cancelWait := context.WithCancel(context.Background())
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- second.WithRewriteOperation(waitCtx, func(context.Context) error {
			secondEntered <- struct{}{}
			return nil
		})
	}()
	waitForAcquiredConnections(t, peer, 1)
	select {
	case <-secondEntered:
		t.Fatal("second PostgreSQL instance entered while the first rewriter held the operation lock")
	default:
	}

	cancelWait()
	if err := waitHistoryRewriteResult(t, secondResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel blocked second rewriter: got %v, want context.Canceled", err)
	}
	select {
	case <-secondEntered:
		t.Fatal("cancelled second rewriter invoked its callback")
	default:
	}

	close(releaseFirst)
	if err := waitHistoryRewriteResult(t, firstResult); err != nil {
		t.Fatalf("first rewriter: %v", err)
	}

	if err := second.WithRewriteOperation(context.Background(), func(context.Context) error {
		secondEntered <- struct{}{}
		return nil
	}); err != nil {
		t.Fatalf("second rewriter after release: %v", err)
	}
	select {
	case <-secondEntered:
	default:
		t.Fatal("second rewriter did not enter after the first released the operation lock")
	}
}

func TestHistoryRewriteLocalOperationWaitersCannotStarveCutoverConnection(t *testing.T) {
	primary := newStore(t)
	coordinator := store.NewHistoryRewriteCoordinator(primary)

	// The production pool has 16 connections. Without the process-local gate,
	// these 16 contenders can each pin one PostgreSQL session while 15 poll the
	// operation advisory lock; the winner then has no session left for cutover.
	const contenders = 16
	start := make(chan struct{})
	ready := make(chan struct{}, contenders)
	results := make(chan error, contenders)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range contenders {
		go func() {
			ready <- struct{}{}
			<-start
			results <- coordinator.WithRewriteOperation(ctx, func(operationCtx context.Context) error {
				// Give every losing contender time to reach the local/database
				// operation wall before the elected callback asks for its second
				// pooled session.
				time.Sleep(100 * time.Millisecond)
				return coordinator.WithCutover(operationCtx, func(context.Context) error {
					return nil
				})
			})
		}()
	}
	for range contenders {
		<-ready
	}
	close(start)
	for index := range contenders {
		if err := waitHistoryRewriteResult(t, results); err != nil {
			t.Fatalf("concurrent rewrite %d/%d: %v", index+1, contenders, err)
		}
	}
}

func TestHistoryRewriteBarrierBlocksReadAndCutoverInBothDirections(t *testing.T) {
	t.Run("read views share the barrier", func(t *testing.T) {
		primary := newStore(t)
		peer := openHistoryRewritePeer(t)
		first := store.NewHistoryRewriteCoordinator(primary)
		second := store.NewHistoryRewriteCoordinator(peer)

		firstEntered := make(chan struct{})
		releaseFirst := make(chan struct{})
		firstResult := make(chan error, 1)
		go func() {
			firstResult <- first.WithRead(context.Background(), func(context.Context) error {
				close(firstEntered)
				<-releaseFirst
				return nil
			})
		}()
		<-firstEntered

		var secondCalls atomic.Int32
		if err := second.WithRead(context.Background(), func(context.Context) error {
			secondCalls.Add(1)
			return nil
		}); err != nil {
			t.Fatalf("second concurrent read: %v", err)
		}
		if got := secondCalls.Load(); got != 1 {
			t.Fatalf("second concurrent read callback calls = %d, want 1", got)
		}

		close(releaseFirst)
		if err := waitHistoryRewriteResult(t, firstResult); err != nil {
			t.Fatalf("first read: %v", err)
		}
	})

	t.Run("read blocks cutover", func(t *testing.T) {
		primary := newStore(t)
		peer := openHistoryRewritePeer(t)
		reader := store.NewHistoryRewriteCoordinator(primary)
		cutover := store.NewHistoryRewriteCoordinator(peer)

		readEntered := make(chan struct{})
		releaseRead := make(chan struct{})
		readResult := make(chan error, 1)
		go func() {
			readResult <- reader.WithRead(context.Background(), func(context.Context) error {
				close(readEntered)
				<-releaseRead
				return nil
			})
		}()
		<-readEntered

		cutoverEntered := make(chan struct{}, 1)
		cutoverResult := make(chan error, 1)
		go func() {
			cutoverResult <- cutover.WithCutover(context.Background(), func(context.Context) error {
				cutoverEntered <- struct{}{}
				return nil
			})
		}()
		waitForAcquiredConnections(t, peer, 1)
		select {
		case <-cutoverEntered:
			t.Fatal("cutover entered while a cross-instance read view was active")
		default:
		}

		close(releaseRead)
		if err := waitHistoryRewriteResult(t, readResult); err != nil {
			t.Fatalf("read view: %v", err)
		}
		if err := waitHistoryRewriteResult(t, cutoverResult); err != nil {
			t.Fatalf("cutover after read: %v", err)
		}
		select {
		case <-cutoverEntered:
		default:
			t.Fatal("cutover did not enter after the read view released")
		}
	})

	t.Run("cutover blocks read", func(t *testing.T) {
		primary := newStore(t)
		peer := openHistoryRewritePeer(t)
		cutover := store.NewHistoryRewriteCoordinator(primary)
		reader := store.NewHistoryRewriteCoordinator(peer)

		cutoverEntered := make(chan struct{})
		releaseCutover := make(chan struct{})
		cutoverResult := make(chan error, 1)
		go func() {
			cutoverResult <- cutover.WithCutover(context.Background(), func(context.Context) error {
				close(cutoverEntered)
				<-releaseCutover
				return nil
			})
		}()
		<-cutoverEntered

		readEntered := make(chan struct{}, 1)
		readResult := make(chan error, 1)
		go func() {
			readResult <- reader.WithRead(context.Background(), func(context.Context) error {
				readEntered <- struct{}{}
				return nil
			})
		}()
		waitForAcquiredConnections(t, peer, 1)
		select {
		case <-readEntered:
			t.Fatal("read view entered while a cross-instance cutover was active")
		default:
		}

		close(releaseCutover)
		if err := waitHistoryRewriteResult(t, cutoverResult); err != nil {
			t.Fatalf("cutover: %v", err)
		}
		if err := waitHistoryRewriteResult(t, readResult); err != nil {
			t.Fatalf("read after cutover: %v", err)
		}
		select {
		case <-readEntered:
		default:
			t.Fatal("read view did not enter after cutover released")
		}
	})
}

func TestHistoryRewriteBarrierWaitIsContextCancellable(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	holder := store.NewHistoryRewriteCoordinator(primary)
	waiter := store.NewHistoryRewriteCoordinator(peer)

	holderEntered := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderResult := make(chan error, 1)
	go func() {
		holderResult <- holder.WithCutover(context.Background(), func(context.Context) error {
			close(holderEntered)
			<-releaseHolder
			return nil
		})
	}()
	<-holderEntered

	var callbackCalls atomic.Int32
	waitCtx, cancelWait := context.WithCancel(context.Background())
	waitResult := make(chan error, 1)
	go func() {
		waitResult <- waiter.WithRead(waitCtx, func(context.Context) error {
			callbackCalls.Add(1)
			return nil
		})
	}()
	waitForAcquiredConnections(t, peer, 1)
	cancelWait()
	if err := waitHistoryRewriteResult(t, waitResult); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel blocked read view: got %v, want context.Canceled", err)
	}
	if got := callbackCalls.Load(); got != 0 {
		t.Fatalf("cancelled read callback calls = %d, want 0", got)
	}

	close(releaseHolder)
	if err := waitHistoryRewriteResult(t, holderResult); err != nil {
		t.Fatalf("holder cutover: %v", err)
	}
	if err := waiter.WithRead(context.Background(), func(context.Context) error {
		callbackCalls.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("read after cancellation/release: %v", err)
	}
	if got := callbackCalls.Load(); got != 1 {
		t.Fatalf("successful read callback calls = %d, want 1", got)
	}
}

func TestHistoryRewriteReadViewsMayOutliveStatementTimeout(t *testing.T) {
	primary := newStore(t)
	short, err := store.Open(
		context.Background(),
		testDSN,
		store.WithStatementTimeout(10*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("store.Open with short statement timeout: %v", err)
	}
	t.Cleanup(short.Close)
	coordinator := store.NewHistoryRewriteCoordinator(short)

	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- coordinator.WithRead(context.Background(), func(context.Context) error {
			close(callbackEntered)
			<-releaseCallback
			return nil
		})
	}()
	<-callbackEntered

	// Prove PostgreSQL's 10 ms statement limit elapsed while the read grant
	// remained alive. The callback is not an SQL statement or transaction.
	time.Sleep(25 * time.Millisecond)
	close(releaseCallback)
	if err := waitHistoryRewriteResult(t, result); err != nil {
		t.Fatalf("long read view: %v", err)
	}

	// Keep primary live so this test also proves the shared database remained
	// healthy after releasing the long-lived session grant.
	if err := primary.SystemPool().Ping(context.Background()); err != nil {
		t.Fatalf("database after long read view: %v", err)
	}
}

func TestHistoryRewriteNestedReadUsesNoSecondConnection(t *testing.T) {
	primary := newStore(t)
	coordinator := store.NewHistoryRewriteCoordinator(primary)

	// Store pools have 16 connections. Occupy 15 so the outer read grant owns
	// the only remaining connection: this is the same deadlock boundary as a
	// max_conns=1 pool, without weakening the production pool configuration.
	held := make([]*pgxpool.Conn, 0, 15)
	for i := 0; i < 15; i++ {
		conn, err := primary.SystemPool().Acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire reserved pool connection %d: %v", i, err)
		}
		held = append(held, conn)
	}
	defer func() {
		for _, conn := range held {
			conn.Release()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var outerCalls atomic.Int32
	var innerCalls atomic.Int32
	err := coordinator.WithRead(ctx, func(readCtx context.Context) error {
		outerCalls.Add(1)
		if got := primary.SystemPool().Stat().AcquiredConns(); got != 16 {
			return fmt.Errorf("connections during outer read = %d, want 16", got)
		}
		return coordinator.WithRead(readCtx, func(nestedCtx context.Context) error {
			innerCalls.Add(1)
			if got := primary.SystemPool().Stat().AcquiredConns(); got != 16 {
				return fmt.Errorf("connections during nested read = %d, want 16", got)
			}
			if nestedCtx.Err() != nil {
				return nestedCtx.Err()
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("nested read with one available pool connection: %v", err)
	}
	if got := outerCalls.Load(); got != 1 {
		t.Fatalf("outer read calls = %d, want 1", got)
	}
	if got := innerCalls.Load(); got != 1 {
		t.Fatalf("inner read calls = %d, want 1", got)
	}
}

func TestHistoryRewriteCutoverAllowsNestedReadWithNoSecondConnection(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	coordinator := store.NewHistoryRewriteCoordinator(primary)

	// Leave one pooled session. The outer cutover owns it and the deployment-wide
	// exclusive barrier, so a nested history read must recognize that stronger
	// scoped grant instead of waiting for a second session/shared lock.
	held := make([]*pgxpool.Conn, 0, 15)
	for i := 0; i < 15; i++ {
		conn, err := primary.SystemPool().Acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire reserved pool connection %d: %v", i, err)
		}
		held = append(held, conn)
	}
	defer func() {
		for _, conn := range held {
			conn.Release()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var nestedCalls atomic.Int32
	err := coordinator.WithCutover(ctx, func(cutoverCtx context.Context) error {
		assertAdvisoryLockUnavailable(
			t, peer, store.HistoryRewriteBarrierAdvisoryLockKey, true,
			"exclusive cutover before nested read",
		)
		return coordinator.WithRead(cutoverCtx, func(context.Context) error {
			nestedCalls.Add(1)
			if got := primary.SystemPool().Stat().AcquiredConns(); got != 16 {
				return fmt.Errorf("connections during nested cutover read = %d, want 16", got)
			}
			assertAdvisoryLockUnavailable(
				t, peer, store.HistoryRewriteBarrierAdvisoryLockKey, true,
				"exclusive cutover during nested read",
			)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("cutover nested history read: %v", err)
	}
	if got := nestedCalls.Load(); got != 1 {
		t.Fatalf("nested read callback calls = %d, want 1", got)
	}
}

func TestHistoryRewriteLeakedCutoverContextCannotBypassLaterCutover(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	reader := store.NewHistoryRewriteCoordinator(primary)
	cutover := store.NewHistoryRewriteCoordinator(peer)

	var leaked context.Context
	if err := reader.WithCutover(context.Background(), func(cutoverCtx context.Context) error {
		leaked = cutoverCtx
		return nil
	}); err != nil {
		t.Fatalf("capture cutover context: %v", err)
	}
	if leaked == nil {
		t.Fatal("cutover callback did not expose its scoped context")
	}

	cutoverEntered := make(chan struct{})
	releaseCutover := make(chan struct{})
	cutoverResult := make(chan error, 1)
	go func() {
		cutoverResult <- cutover.WithCutover(context.Background(), func(context.Context) error {
			close(cutoverEntered)
			<-releaseCutover
			return nil
		})
	}()
	<-cutoverEntered

	var leakedCalls atomic.Int32
	leakedResult := make(chan error, 1)
	go func() {
		leakedResult <- reader.WithRead(leaked, func(context.Context) error {
			leakedCalls.Add(1)
			return nil
		})
	}()
	waitForAcquiredConnections(t, primary, 1)
	select {
	case err := <-leakedResult:
		t.Fatalf("escaped cutover context bypassed a later cutover: %v", err)
	default:
	}
	if got := leakedCalls.Load(); got != 0 {
		t.Fatalf("escaped cutover callback calls during later cutover = %d, want 0", got)
	}

	close(releaseCutover)
	if err := waitHistoryRewriteResult(t, cutoverResult); err != nil {
		t.Fatalf("release later cutover: %v", err)
	}
	if err := waitHistoryRewriteResult(t, leakedResult); err != nil {
		t.Fatalf("escaped context read after cutover: %v", err)
	}
	if got := leakedCalls.Load(); got != 1 {
		t.Fatalf("escaped cutover callback calls after release = %d, want 1", got)
	}
}

func TestHistoryRewriteCutoverWaitsForEnteredNestedRead(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	cutover := store.NewHistoryRewriteCoordinator(primary)
	reader := store.NewHistoryRewriteCoordinator(peer)

	nestedEntered := make(chan struct{})
	releaseNested := make(chan struct{})
	nestedResult := make(chan error, 1)
	cutoverReturning := make(chan struct{})
	cutoverResult := make(chan error, 1)
	go func() {
		cutoverResult <- cutover.WithCutover(context.Background(), func(cutoverCtx context.Context) error {
			go func() {
				nestedResult <- cutover.WithRead(cutoverCtx, func(context.Context) error {
					close(nestedEntered)
					<-releaseNested
					return nil
				})
			}()
			<-nestedEntered
			close(cutoverReturning)
			return nil
		})
	}()
	<-cutoverReturning

	readEntered := make(chan struct{}, 1)
	readResult := make(chan error, 1)
	go func() {
		readResult <- reader.WithRead(context.Background(), func(context.Context) error {
			readEntered <- struct{}{}
			return nil
		})
	}()
	waitForAcquiredConnections(t, peer, 1)
	select {
	case err := <-cutoverResult:
		t.Fatalf("cutover returned while its entered nested read was active: %v", err)
	case <-readEntered:
		t.Fatal("peer read crossed the exclusive cutover while its nested read was active")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseNested)
	if err := waitHistoryRewriteResult(t, nestedResult); err != nil {
		t.Fatalf("nested cutover read: %v", err)
	}
	if err := waitHistoryRewriteResult(t, cutoverResult); err != nil {
		t.Fatalf("cutover after nested read: %v", err)
	}
	if err := waitHistoryRewriteResult(t, readResult); err != nil {
		t.Fatalf("peer read after cutover: %v", err)
	}
	select {
	case <-readEntered:
	default:
		t.Fatal("peer read did not enter after nested read and cutover grants released")
	}
}

func TestHistoryRewriteOuterReadWaitsForEnteredNestedCallback(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	reader := store.NewHistoryRewriteCoordinator(primary)
	cutover := store.NewHistoryRewriteCoordinator(peer)

	nestedEntered := make(chan struct{})
	releaseNested := make(chan struct{})
	nestedResult := make(chan error, 1)
	outerReturning := make(chan struct{})
	outerResult := make(chan error, 1)
	go func() {
		outerResult <- reader.WithRead(context.Background(), func(readCtx context.Context) error {
			go func() {
				nestedResult <- reader.WithRead(readCtx, func(context.Context) error {
					close(nestedEntered)
					<-releaseNested
					return nil
				})
			}()
			<-nestedEntered
			close(outerReturning)
			return nil
		})
	}()
	<-outerReturning

	cutoverEntered := make(chan struct{}, 1)
	cutoverResult := make(chan error, 1)
	go func() {
		cutoverResult <- cutover.WithCutover(context.Background(), func(context.Context) error {
			cutoverEntered <- struct{}{}
			return nil
		})
	}()
	waitForAcquiredConnections(t, peer, 1)
	select {
	case err := <-outerResult:
		t.Fatalf("outer read returned while its entered nested callback was active: %v", err)
	case <-cutoverEntered:
		t.Fatal("cutover crossed an entered nested read after its outer callback returned")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseNested)
	if err := waitHistoryRewriteResult(t, nestedResult); err != nil {
		t.Fatalf("nested read: %v", err)
	}
	if err := waitHistoryRewriteResult(t, outerResult); err != nil {
		t.Fatalf("outer read: %v", err)
	}
	if err := waitHistoryRewriteResult(t, cutoverResult); err != nil {
		t.Fatalf("cutover after nested read: %v", err)
	}
	select {
	case <-cutoverEntered:
	default:
		t.Fatal("cutover did not enter after nested and outer read grants released")
	}
}

func TestHistoryRewriteLeakedReadContextCannotBypassLaterCutover(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	reader := store.NewHistoryRewriteCoordinator(primary)
	cutover := store.NewHistoryRewriteCoordinator(peer)

	var leaked context.Context
	if err := reader.WithRead(context.Background(), func(readCtx context.Context) error {
		leaked = readCtx
		return nil
	}); err != nil {
		t.Fatalf("capture read context: %v", err)
	}
	if leaked == nil {
		t.Fatal("outer read callback did not expose its scoped context")
	}

	cutoverEntered := make(chan struct{})
	releaseCutover := make(chan struct{})
	cutoverResult := make(chan error, 1)
	go func() {
		cutoverResult <- cutover.WithCutover(context.Background(), func(context.Context) error {
			close(cutoverEntered)
			<-releaseCutover
			return nil
		})
	}()
	<-cutoverEntered

	var leakedCallbackCalls atomic.Int32
	leakedResult := make(chan error, 1)
	go func() {
		leakedResult <- reader.WithRead(leaked, func(context.Context) error {
			leakedCallbackCalls.Add(1)
			return nil
		})
	}()
	waitForAcquiredConnections(t, primary, 1)
	select {
	case err := <-leakedResult:
		t.Fatalf("escaped read context bypassed a later cutover: %v", err)
	default:
	}
	if got := leakedCallbackCalls.Load(); got != 0 {
		t.Fatalf("escaped read callback calls during cutover = %d, want 0", got)
	}

	close(releaseCutover)
	if err := waitHistoryRewriteResult(t, cutoverResult); err != nil {
		t.Fatalf("release cutover: %v", err)
	}
	if err := waitHistoryRewriteResult(t, leakedResult); err != nil {
		t.Fatalf("escaped context read after cutover: %v", err)
	}
	if got := leakedCallbackCalls.Load(); got != 1 {
		t.Fatalf("escaped read callback calls after cutover = %d, want 1", got)
	}
}

func TestHistoryReadGrantDoesNotBypassOperationOrCutover(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	coordinator := store.NewHistoryRewriteCoordinator(primary)
	var operationCalls atomic.Int32
	var cutoverCalls atomic.Int32

	err := coordinator.WithRead(context.Background(), func(readCtx context.Context) error {
		if err := coordinator.WithRewriteOperation(readCtx, func(context.Context) error {
			operationCalls.Add(1)
			assertAdvisoryLockUnavailable(
				t,
				peer,
				store.HistoryRewriteOperationAdvisoryLockKey,
				false,
				"rewrite-operation lock nested under read",
			)
			return nil
		}); err != nil {
			return err
		}

		// A read-to-cutover upgrade cannot succeed while this callback owns the
		// shared barrier. A short deadline proves the private read token did not
		// make WithCutover skip its exclusive PostgreSQL lock.
		cutoverCtx, cancel := context.WithTimeout(readCtx, 75*time.Millisecond)
		defer cancel()
		err := coordinator.WithCutover(cutoverCtx, func(context.Context) error {
			cutoverCalls.Add(1)
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("nested cutover = %v, want context deadline", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read token isolation: %v", err)
	}
	if got := operationCalls.Load(); got != 1 {
		t.Fatalf("operation calls = %d, want 1", got)
	}
	if got := cutoverCalls.Load(); got != 0 {
		t.Fatalf("cutover calls = %d, want 0", got)
	}
}

func TestHistoryRewriteLockKeysDoNotCollide(t *testing.T) {
	keys := map[int64]string{
		store.HistoryRewriteOperationAdvisoryLockKey: "history operation",
		store.HistoryRewriteBarrierAdvisoryLockKey:   "history barrier",
		store.BackupWriteFenceAdvisoryLockKey:        "backup fence",
		store.MigrateAdvisoryLockKey:                 "migration",
		store.ProjectionAdvisoryLockKey:              "projection",
		store.LeaderAdvisoryLockKey:                  "leader",
		store.CAProvisionAdvisoryLockKey:             "CA provision",
	}
	if len(keys) != 7 {
		t.Fatalf("advisory-lock key collision: got %d unique keys, want 7 (%v)", len(keys), keys)
	}
}

func TestPrepareTenantDataCutoverInvalidatesSnapshotsBeforeOneFencedProceed(t *testing.T) {
	primary := newStore(t)
	peer := openHistoryRewritePeer(t)
	ctx := context.Background()
	insertTestSnapshots(t, primary, 2)

	coordinator := store.NewHistoryRewriteCoordinator(primary)
	var proceedCalls atomic.Int32
	err := coordinator.WithCutover(ctx, func(cutoverCtx context.Context) error {
		return primary.PrepareTenantDataCutover(
			cutoverCtx,
			events.TenantDataRewriteReport{TenantID: tenantA},
			func(proceedCtx context.Context) error {
				proceedCalls.Add(1)
				if count, err := primary.SnapshotCount(proceedCtx); err != nil {
					return fmt.Errorf("count snapshots in proceed: %w", err)
				} else if count != 0 {
					return fmt.Errorf("proceed saw %d snapshots, want 0", count)
				}
				assertAdvisoryLockUnavailable(
					t,
					peer,
					store.HistoryRewriteBarrierAdvisoryLockKey,
					true,
					"history cutover barrier",
				)
				assertAdvisoryLockUnavailable(
					t,
					peer,
					store.BackupWriteFenceAdvisoryLockKey,
					true,
					"backup write fence",
				)
				return nil
			},
		)
	})
	if err != nil {
		t.Fatalf("prepare tenant-data cutover: %v", err)
	}
	if got := proceedCalls.Load(); got != 1 {
		t.Fatalf("proceed calls = %d, want exactly 1", got)
	}
	if count, err := primary.SnapshotCount(ctx); err != nil {
		t.Fatalf("SnapshotCount after cutover: %v", err)
	} else if count != 0 {
		t.Fatalf("snapshots after cutover = %d, want 0", count)
	}
	assertAdvisoryLockAvailable(
		t,
		peer,
		store.HistoryRewriteBarrierAdvisoryLockKey,
		true,
		"history barrier after cutover",
	)
	assertAdvisoryLockAvailable(
		t,
		peer,
		store.BackupWriteFenceAdvisoryLockKey,
		true,
		"backup fence after cutover",
	)
}

func TestPrepareTenantDataCutoverFailsClosed(t *testing.T) {
	t.Run("nil proceed leaves snapshots intact", func(t *testing.T) {
		primary := newStore(t)
		insertTestSnapshots(t, primary, 1)

		err := primary.PrepareTenantDataCutover(
			context.Background(),
			events.TenantDataRewriteReport{},
			nil,
		)
		if err == nil {
			t.Fatal("nil proceed unexpectedly succeeded")
		}
		if count, countErr := primary.SnapshotCount(context.Background()); countErr != nil {
			t.Fatalf("SnapshotCount: %v", countErr)
		} else if count != 1 {
			t.Fatalf("snapshots after refused nil proceed = %d, want 1", count)
		}
	})

	t.Run("proceed error is returned once and locks release", func(t *testing.T) {
		primary := newStore(t)
		peer := openHistoryRewritePeer(t)
		insertTestSnapshots(t, primary, 1)
		coordinator := store.NewHistoryRewriteCoordinator(primary)
		proceedErr := errors.New("activation refused")
		var proceedCalls atomic.Int32

		err := coordinator.WithCutover(context.Background(), func(cutoverCtx context.Context) error {
			return primary.PrepareTenantDataCutover(
				cutoverCtx,
				events.TenantDataRewriteReport{},
				func(context.Context) error {
					proceedCalls.Add(1)
					return proceedErr
				},
			)
		})
		if !errors.Is(err, proceedErr) {
			t.Fatalf("prepare error = %v, want %v", err, proceedErr)
		}
		if got := proceedCalls.Load(); got != 1 {
			t.Fatalf("failing proceed calls = %d, want exactly 1", got)
		}
		if count, countErr := primary.SnapshotCount(context.Background()); countErr != nil {
			t.Fatalf("SnapshotCount: %v", countErr)
		} else if count != 0 {
			t.Fatalf("snapshots after verified invalidation = %d, want 0", count)
		}
		assertAdvisoryLockAvailable(
			t,
			peer,
			store.HistoryRewriteBarrierAdvisoryLockKey,
			true,
			"history barrier after failed proceed",
		)
		assertAdvisoryLockAvailable(
			t,
			peer,
			store.BackupWriteFenceAdvisoryLockKey,
			true,
			"backup fence after failed proceed",
		)
	})

	t.Run("cancelled backup-fence wait neither deletes nor proceeds", func(t *testing.T) {
		primary := newStore(t)
		peer := openHistoryRewritePeer(t)
		insertTestSnapshots(t, peer, 1)

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

		var proceedCalls atomic.Int32
		waitCtx, cancelWait := context.WithCancel(context.Background())
		prepareResult := make(chan error, 1)
		go func() {
			prepareResult <- peer.PrepareTenantDataCutover(
				waitCtx,
				events.TenantDataRewriteReport{},
				func(context.Context) error {
					proceedCalls.Add(1)
					return nil
				},
			)
		}()
		waitForAcquiredConnections(t, peer, 1)
		cancelWait()
		if err := waitHistoryRewriteResult(t, prepareResult); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled preparation = %v, want context.Canceled", err)
		}
		if got := proceedCalls.Load(); got != 0 {
			t.Fatalf("proceed calls after cancelled fence wait = %d, want 0", got)
		}
		if count, err := peer.SnapshotCount(context.Background()); err != nil {
			t.Fatalf("SnapshotCount after cancel: %v", err)
		} else if count != 1 {
			t.Fatalf("snapshots after cancelled fence wait = %d, want 1", count)
		}

		close(releaseFence)
		if err := waitHistoryRewriteResult(t, fenceResult); err != nil {
			t.Fatalf("release held backup fence: %v", err)
		}
	})
}

func insertTestSnapshots(t *testing.T, s *store.Store, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		tenantID := fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)
		if _, err := s.SystemPool().Exec(
			context.Background(),
			`INSERT INTO read_model_snapshots
			     (tenant_id, covered_seq, format_version, payload)
			 VALUES ($1, $2, $3, '{}'::jsonb)`,
			tenantID,
			i+1,
			store.SnapshotFormatVersion,
		); err != nil {
			t.Fatalf("insert test snapshot %d: %v", i, err)
		}
	}
}

func assertAdvisoryLockUnavailable(
	t *testing.T,
	s *store.Store,
	key int64,
	shared bool,
	label string,
) {
	t.Helper()
	query := "SELECT pg_try_advisory_lock($1)"
	unlock := "SELECT pg_advisory_unlock($1)"
	if shared {
		query = "SELECT pg_try_advisory_lock_shared($1)"
		unlock = "SELECT pg_advisory_unlock_shared($1)"
	}
	conn, err := s.SystemPool().Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire peer for %s probe: %v", label, err)
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(context.Background(), query, key).Scan(&got); err != nil {
		t.Fatalf("probe %s: %v", label, err)
	}
	if got {
		_, _ = conn.Exec(context.Background(), unlock, key)
		t.Fatalf("%s was available while its exclusive wall should be held", label)
	}
}

func assertAdvisoryLockAvailable(
	t *testing.T,
	s *store.Store,
	key int64,
	shared bool,
	label string,
) {
	t.Helper()
	query := "SELECT pg_try_advisory_lock($1)"
	unlock := "SELECT pg_advisory_unlock($1)"
	if shared {
		query = "SELECT pg_try_advisory_lock_shared($1)"
		unlock = "SELECT pg_advisory_unlock_shared($1)"
	}
	conn, err := s.SystemPool().Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire peer for %s probe: %v", label, err)
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(context.Background(), query, key).Scan(&got); err != nil {
		t.Fatalf("probe %s: %v", label, err)
	}
	if !got {
		t.Fatalf("%s remained locked after callback returned", label)
	}
	var released bool
	if err := conn.QueryRow(context.Background(), unlock, key).Scan(&released); err != nil {
		t.Fatalf("release %s probe: %v", label, err)
	}
	if !released {
		t.Fatalf("release %s probe reported no owned lock", label)
	}
}
