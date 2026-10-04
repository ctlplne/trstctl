// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestResourceCreationFenceCoordinatesReplicasWithoutHoldingTransaction(t *testing.T) {
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
	err := first.WithTenantResourceCreation(ctx, tenantA, "agents", func(work context.Context) error {
		// Projection must reuse the held session; a one-slot lock pool catches
		// self-deadlock that would make every first heartbeat stall.
		if err := first.WithProjectionLock(work, func(context.Context) error { return nil }); err != nil {
			return err
		}
		called := false
		err := second.WithTenantResourceCreation(ctx, tenantA, "agents", func(context.Context) error {
			called = true
			return nil
		})
		if !errors.Is(err, store.ErrResourceAdmissionBusy) || called {
			t.Fatalf("same tenant/resource admitted twice: err=%v called=%v", err, called)
		}
		if err := second.WithTenantResourceCreation(ctx, tenantA, "secrets_stored", func(context.Context) error { return nil }); err != nil {
			t.Fatalf("distinct resource blocked: %v", err)
		}
		if err := second.WithTenantResourceCreation(ctx, tenantB, "agents", func(context.Context) error { return nil }); err != nil {
			t.Fatalf("distinct tenant blocked: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.WithTenantResourceCreation(ctx, tenantA, "agents", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("released admission lock was retained: %v", err)
	}
}
