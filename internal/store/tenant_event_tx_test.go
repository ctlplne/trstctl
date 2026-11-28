// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

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
		called := false
		found, borrowErr = s.UseTenantEventTx(eventCtx, tenantB, func(pgx.Tx) error {
			called = true
			return nil
		})
		if !found || !errors.Is(borrowErr, store.ErrTenantEventTxUnavailable) || called {
			return fmt.Errorf("cross-tenant borrow: found=%v, err=%v, called=%v", found, borrowErr, called)
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
}
