// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestTenantServiceFenceCoordinatesReplicasAndNestedWork(t *testing.T) {
	_ = newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	open := func() *store.Store {
		t.Helper()
		s, err := store.Open(ctx, testDSN, store.WithPoolSizes(store.PoolSizes{Lock: 1}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	first, second := open(), open()
	work, release, err := first.BeginTenantService(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// A second replica can run shared work, but cannot finish a lifecycle
	// transition until both replicas' admitted operations have completed.
	_, releaseSecond, err := second.BeginTenantService(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	releaseSecond()
	called := false
	err = second.WithTenantServiceBarrier(ctx, tenantA, func(context.Context) error { called = true; return nil })
	if !errors.Is(err, store.ErrTenantServiceBusy) || called {
		t.Fatalf("active work did not exclude lifecycle: %v %v", called, err)
	}
	for _, alias := range []string{strings.ReplaceAll(tenantA, "-", ""), "{" + tenantA + "}"} {
		var sameTenant bool
		if err := second.SystemPool().QueryRow(ctx, `SELECT $1::uuid=$2::uuid`, tenantA, alias).Scan(&sameTenant); err != nil || !sameTenant {
			t.Fatalf("test alias is not the same PostgreSQL tenant: %v %v", sameTenant, err)
		}
		if err := second.WithTenantServiceBarrier(ctx, alias, func(context.Context) error { return nil }); !errors.Is(err, store.ErrTenantServiceBusy) {
			t.Fatalf("equivalent PostgreSQL tenant UUID bypassed active work: %v", err)
		}
	}
	if err := second.WithTenantServiceBarrier(ctx, tenantB, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("another customer blocked: %v", err)
	}
	if err := first.WithTenantServiceBarrier(work, tenantA, func(context.Context) error { t.Fatal("upgraded shared fence"); return nil }); err == nil {
		t.Fatal("shared lock upgrade accepted")
	}
	if _, end, err := first.BeginTenantService(work, tenantB); err == nil {
		end()
		t.Fatal("nested foreign customer admitted")
	}
	if err := first.WithIdentityIssuanceFence(work, tenantB, "identity", func(context.Context) error { return nil }); err == nil {
		t.Fatal("another customer's signing reused the admitted tenant's service lease")
	}
	// The single lock-pool slot is occupied by service admission. Signing and
	// projection must reuse it; a second acquisition would time out.
	if err := first.WithIdentityIssuanceFence(work, tenantA, "identity", func(signed context.Context) error {
		return first.WithProjectionLock(signed, func(context.Context) error { return nil })
	}); err != nil {
		t.Fatal(err)
	}
	if err := first.WithProjectionLock(work, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	release()
	if _, end, err := first.BeginTenantService(work, tenantA); err == nil {
		end()
		t.Fatal("escaped lifetime accepted")
	}
	if err := first.WithProjectionLock(work, func(context.Context) error { t.Fatal("used returned session"); return nil }); err == nil {
		t.Fatal("escaped projection accepted")
	}
	if err := second.WithTenantServiceBarrier(ctx, tenantA, func(barrier context.Context) error {
		if _, end, err := first.BeginTenantService(ctx, tenantA); !errors.Is(err, store.ErrTenantServiceBusy) {
			if end != nil {
				end()
			}
			t.Fatalf("exclusive lifecycle admitted another request: %v", err)
		}
		return second.WithProjectionLock(barrier, func(context.Context) error { return nil })
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTenantServiceFenceCancellationWhileWaitingForProjection(t *testing.T) {
	first := newStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	second, err := store.Open(ctx, testDSN, store.WithPoolSizes(store.PoolSizes{Lock: 1}))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var leasePID int
	if err := second.WithProjectionLock(ctx, func(context.Context) error {
		work, release, err := first.BeginTenantService(ctx, tenantA)
		if err != nil {
			return err
		}
		defer release()
		// Inspect only this test's tenant-service lock. PostgreSQL can observe
		// a closed client socket after its blocked query wakes, so connection
		// close is not a synchronous backend-termination acknowledgement.
		if err := first.SystemPool().QueryRow(ctx, `SELECT pid FROM pg_locks
			WHERE locktype='advisory' AND mode='ShareLock' AND granted
			AND ((classid::bigint << 32) | objid::bigint)=hashtextextended($1,0)`,
			"tenant-service\x1f"+tenantA).Scan(&leasePID); err != nil {
			return err
		}
		blocked, stop := context.WithTimeout(work, 100*time.Millisecond)
		defer stop()
		if err := first.WithProjectionLock(blocked, func(context.Context) error { t.Error("entered held projection lock"); return nil }); err == nil {
			t.Fatal("canceled lock acquisition succeeded")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Wait for the exact owned backend's locks to disappear, bounded by the
	// test deadline. Never infer cleanup from a client-side cancellation alone.
	cleanupStarted := time.Now()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var held bool
		if err := first.SystemPool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory')`, leasePID).Scan(&held); err != nil {
			t.Fatal(err)
		}
		if !held {
			break
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("canceled session retained locks: %v", ctx.Err())
		}
	}
	t.Logf("owned canceled backend released advisory locks after %s", time.Since(cleanupStarted))
	if err := first.WithTenantServiceBarrier(ctx, tenantA, func(fenced context.Context) error {
		return first.WithProjectionLock(fenced, func(context.Context) error { return nil })
	}); err != nil {
		t.Fatalf("canceled acquisition poisoned service/projection session: %v", err)
	}
}

func TestTenantServiceFenceReleasesCanceledOperation(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	work, release, err := s.BeginTenantService(ctx, tenantA)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if work.Err() == nil {
		t.Fatal("work lost cancellation")
	}
	release()
	retry, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	if err := s.WithTenantServiceBarrier(retry, tenantA, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("canceled operation retained its lock: %v", err)
	}
}
