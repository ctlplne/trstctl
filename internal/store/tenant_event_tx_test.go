// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestTenantEventTransactionBorrowIsScopedToTenantAndCommit(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	if found, err := s.UseTenantEventTx(ctx, tenantA, func(pgx.Tx) error { return nil }); found || err != nil {
		t.Fatalf("direct producer has a transaction: found=%v, err=%v", found, err)
	}
	var retained context.Context
	err := s.WithTenantEvent(ctx, tenantA, func(eventCtx context.Context, tx pgx.Tx) error {
		retained = eventCtx
		found, borrowErr := s.UseTenantEventTx(eventCtx, tenantA, func(borrowed pgx.Tx) error {
			if borrowed != tx {
				return errors.New("tenant event borrow changed the transaction")
			}
			var tenant string
			if err := borrowed.QueryRow(eventCtx, `SELECT current_setting('trstctl.tenant_id')`).Scan(&tenant); err != nil {
				return err
			}
			if tenant != tenantA {
				return fmt.Errorf("tenant event borrow used %s, want %s", tenant, tenantA)
			}
			return nil
		})
		if !found || borrowErr != nil {
			return fmt.Errorf("borrow active tenant transaction: found=%v, err=%w", found, borrowErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	found, err := s.UseTenantEventTx(retained, tenantA, func(pgx.Tx) error {
		called = true
		return nil
	})
	if !found || !errors.Is(err, store.ErrTenantEventTxUnavailable) || called {
		t.Fatalf("borrow after commit: found=%v, err=%v, called=%v", found, err, called)
	}
	called = false
	err = s.WithTenantEvent(ctx, tenantA, func(eventCtx context.Context, _ pgx.Tx) error {
		found, borrowErr := s.UseTenantEventTx(eventCtx, tenantB, func(pgx.Tx) error {
			called = true
			return nil
		})
		if !found || !errors.Is(borrowErr, store.ErrTenantEventTxUnavailable) {
			return fmt.Errorf("cross-tenant borrow: found=%v, err=%v", found, borrowErr)
		}
		return nil
	})
	if !errors.Is(err, store.ErrTenantEventTxUnavailable) || called {
		t.Fatalf("cross-tenant borrow committed: err=%v, called=%v", err, called)
	}
}

func TestTenantEventAdmissionRemainsHeldThroughCommit(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	commandDone := make(chan error, 1)
	go func() {
		commandDone <- s.WithTenantEvent(ctx, tenantA, func(context.Context, pgx.Tx) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-commandDone:
		t.Fatalf("tenant event admission: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	exclusiveDone := make(chan error, 1)
	go func() {
		exclusiveDone <- s.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive,
			func(context.Context) error { return nil })
	}()
	select {
	case err := <-exclusiveDone:
		t.Fatalf("exclusive admission completed before tenant commit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-commandDone; err != nil {
		t.Fatal(err)
	}
	if err := <-exclusiveDone; err != nil {
		t.Fatal(err)
	}
}

func TestTenantEventBorrowFailureRequiresRollback(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	stop := errors.New("tenant event apply failed")
	err := s.WithTenantEvent(t.Context(), tenantA, func(eventCtx context.Context, _ pgx.Tx) error {
		found, borrowErr := s.UseTenantEventTx(eventCtx, tenantA, func(pgx.Tx) error {
			return stop
		})
		if !found || !errors.Is(borrowErr, stop) {
			return fmt.Errorf("borrow failure: found=%v, err=%v", found, borrowErr)
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatalf("tenant event transaction accepted an ignored apply failure: %v", err)
	}
}
