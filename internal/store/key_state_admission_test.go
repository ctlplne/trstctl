// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func withKeyStateOwnerTenantTx(
	ctx context.Context, s *store.Store, tenantID string,
	fn func(context.Context, pgx.Tx) error,
) error {
	return s.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive, func(admitted context.Context) error {
		return s.WithTenant(admitted, tenantID, func(tx pgx.Tx) error {
			owned, err := s.BindKeyStateOwnerTx(admitted, tx, tenantID, store.KeyStateExclusive)
			if err != nil {
				return err
			}
			return fn(owned, tx)
		})
	})
}

// CR-045: losing the outer session admission cannot let a key transition
// commit while an earlier projection transaction still owns its commit lock.
func TestKeyStateCommitLockOutlivesAdmissionSession(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	var held pgx.Tx
	if err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(granted context.Context) error {
		tx, err := s.SystemPool().Begin(granted)
		if err != nil {
			return err
		}
		held = tx
		return s.LockGlobalKeyStateCommitTx(granted, tx, store.KeyStateShared)
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Rollback(context.Background()) }()
	entered := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		completed <- s.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive, func(granted context.Context) error {
			tx, err := s.SystemPool().Begin(granted)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if err := s.LockGlobalKeyStateCommitTx(granted, tx, store.KeyStateExclusive); err != nil {
				return err
			}
			close(entered)
			return nil
		})
	}()
	select {
	case <-entered:
		t.Fatal("key transition entered while the projection transaction was still open")
	case err := <-completed:
		t.Fatalf("key transition stopped before commit lock released: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("key transition did not enter after projection rollback")
	}
}

func TestKeyStateAdmissionRefusesSharedToExclusiveUpgrade(t *testing.T) {
	s := newStore(t)
	if err := s.WithGlobalKeyStateAdmission(context.Background(), store.KeyStateShared, func(granted context.Context) error {
		if err := s.WithGlobalKeyStateAdmission(granted, store.KeyStateExclusive, func(context.Context) error {
			t.Fatal("shared admission upgraded to exclusive")
			return nil
		}); err == nil {
			t.Fatal("shared admission accepted an exclusive nested request")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDirectTenantOffboardWaitsForOrphanedPairCommit(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var proofTx pgx.Tx
	if err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(granted context.Context) error {
		var err error
		proofTx, err = s.SystemPool().Begin(granted)
		if err != nil {
			return err
		}
		return s.LockGlobalKeyStateCommitTx(granted, proofTx, store.KeyStateShared)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proofTx.Rollback(context.Background()) })
	done := make(chan error, 1)
	go func() {
		_, err := s.OffboardTenant(ctx, tenantA)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("offboard crossed an orphaned pair proof transaction: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := proofTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("offboard did not finish after pair proof rollback")
	}
}

func TestKeyStateOwnerBindsTenantAndExactLiveTransaction(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	if err := s.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive, func(admitted context.Context) error {
		return s.WithTenant(admitted, tenantA, func(tx pgx.Tx) error {
			owned, err := s.BindKeyStateOwnerTx(admitted, tx, tenantA, store.KeyStateExclusive)
			if err != nil {
				return err
			}
			if err := s.RequireKeyStateOwnerTx(owned, tx, tenantA, store.KeyStateExclusive); err != nil {
				t.Fatalf("exact owner rejected: %v", err)
			}
			if err := s.RequireKeyStateOwnerTx(admitted, tx, tenantA, store.KeyStateExclusive); err == nil {
				t.Fatal("bare admitted context authorized a key-state write")
			}
			if err := s.RequireKeyStateOwnerTx(owned, tx, tenantB, store.KeyStateExclusive); err == nil {
				t.Fatal("tenant A owner authorized tenant B")
			}
			other, err := s.SystemPool().Begin(admitted)
			if err != nil {
				return err
			}
			defer func() { _ = other.Rollback(context.Background()) }()
			if err := s.RequireKeyStateOwnerTx(owned, other, tenantA, store.KeyStateExclusive); err == nil {
				t.Fatal("owner context authorized another PostgreSQL transaction")
			}
			if _, err := tx.Exec(owned, `SELECT set_config('trstctl.key_state_owner', 'changed', true)`); err != nil {
				return err
			}
			if err := s.RequireKeyStateOwnerTx(owned, tx, tenantA, store.KeyStateExclusive); err == nil {
				t.Fatal("owner context survived transaction-local marker change")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestKeyStateSinksRefuseBareTransactions(t *testing.T) {
	for name, write := range map[string]func(context.Context, *store.Store, pgx.Tx) error{
		"tenant snapshot": func(ctx context.Context, s *store.Store, tx pgx.Tx) error {
			return s.ApplyTenantKeyDomainSnapshotTx(ctx, tx, tenantKeyDomainFixture(tenantA))
		},
		"deployment snapshot": func(ctx context.Context, s *store.Store, tx pgx.Tx) error {
			return s.ApplyDeploymentKEKSnapshotTx(ctx, tx, store.DeploymentKEKDomain{
				DomainID:    "6c7a0f4e-6d8e-4a51-9a0c-0d8f8c3f2a11",
				OperationID: "op-1", OperatorTenantID: tenantA,
			})
		},
		"tenant offboard": func(ctx context.Context, s *store.Store, tx pgx.Tx) error {
			_, err := s.OffboardTenantTx(ctx, tx, tenantA)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			seedTwoTenants(t, s)
			ctx := t.Context()
			err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return write(ctx, s, tx) })
			if !errors.Is(err, store.ErrKeyStateOwnerUnavailable) {
				t.Fatalf("bare key-state sink = %v, want owner refusal", err)
			}
		})
	}
}
