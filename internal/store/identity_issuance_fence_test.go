// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestIdentityIssuanceFenceAcrossReplicasAndProjectionPool(t *testing.T) {
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
	const identityID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	var retained context.Context
	err := first.WithIdentityIssuanceFence(ctx, tenantA, identityID, func(fenced context.Context) error {
		retained = fenced
		if !first.IdentityIssuanceFenceHeld(fenced, tenantA, identityID) || second.IdentityIssuanceFenceHeld(fenced, tenantA, identityID) {
			t.Fatal("fence context does not identify its owning store")
		}
		called := false
		busy := second.WithIdentityIssuanceFence(ctx, tenantA, identityID, func(context.Context) error { called = true; return nil })
		if !errors.Is(busy, store.ErrIdentityIssuanceBusy) || called {
			t.Fatalf("replica entered held identity: called=%v err=%v", called, busy)
		}
		// Same identity UUID in another tenant and unrelated identities proceed.
		for _, key := range [][2]string{{tenantB, identityID}, {tenantA, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}} {
			if err := second.WithIdentityIssuanceFence(ctx, key[0], key[1], func(context.Context) error { return nil }); err != nil {
				return err
			}
		}
		// Only one lock connection exists. Reentrant same-identity commands and
		// nested projection must reuse it, while database work uses its own pool.
		return first.WithIdentityIssuanceFence(fenced, tenantA, identityID, func(nested context.Context) error {
			return first.WithProjectionLock(nested, func(projected context.Context) error {
				_, err := first.ProjectionCheckpoint(projected)
				return err
			})
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.IdentityIssuanceFenceHeld(retained, tenantA, identityID) {
		t.Fatal("returned callback retained signing authority")
	}
	if err := first.WithProjectionLock(retained, func(context.Context) error { t.Fatal("used released session"); return nil }); err == nil {
		t.Fatal("released context accepted")
	}
	if err := second.WithIdentityIssuanceFence(ctx, tenantA, identityID, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("lock not released: %v", err)
	}
}

func TestIdentityIssuanceFenceReleasesAfterCancellation(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	const identityID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	err := s.WithIdentityIssuanceFence(ctx, tenantA, identityID, func(fenced context.Context) error {
		if err := s.WithIdentityIssuanceFence(fenced, tenantB, identityID, func(context.Context) error { t.Fatal("nested foreign identity admitted"); return nil }); err == nil {
			t.Fatal("foreign nested fence accepted")
		}
		return s.WithProjectionLock(fenced, func(context.Context) error { cancel(); return ctx.Err() })
	})
	cancel()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	retry, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	if err := s.WithIdentityIssuanceFence(retry, tenantA, identityID, func(fenced context.Context) error {
		return s.WithProjectionLock(fenced, func(context.Context) error { return nil })
	}); err != nil {
		t.Fatalf("canceled locks were retained: %v", err)
	}
}
