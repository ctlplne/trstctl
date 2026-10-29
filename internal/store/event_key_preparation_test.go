// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func TestEventKeyPreparationOutboxIsAtomicBoundAndTenantIsolated(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	command := store.EventKeyPreparationCommand{
		Ref:                  eventprotect.KeyRef{TenantID: tenantA, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"},
		RegistrationIdentity: "registered-source", RequestedEventID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb:requested",
		RequestedSequence: 7, RequestedAt: time.Now().UTC(), RetentionNanos: int64(time.Hour),
	}
	want := errors.New("force projection rollback")
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.EnsureEventKeyPreparationTx(ctx, tx, command); err != nil {
			return err
		}
		return want
	}); !errors.Is(err, want) {
		t.Fatal(err)
	}
	count := func(tenant string) int {
		t.Helper()
		var count int
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination=$2`, tenant, store.EventKeyPreparationDestination).Scan(&count)
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if count(tenantA) != 0 {
		t.Fatal("rolled-back projection leaked an external intent")
	}
	for i := 0; i < 2; i++ {
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.EnsureEventKeyPreparationTx(ctx, tx, command) }); err != nil {
			t.Fatal(err)
		}
	}
	if count(tenantA) != 1 {
		t.Fatal("canonical replay duplicated key preparation")
	}
	changed := command
	changed.RetentionNanos++
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.EnsureEventKeyPreparationTx(ctx, tx, changed) }); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed protection policy replaced the first command: %v", err)
	}
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error { return s.EnsureEventKeyPreparationTx(ctx, tx, command) }); err == nil {
		t.Fatal("foreign RLS transaction queued another tenant's key effect")
	}
	if count(tenantA) != 1 || count(tenantB) != 0 {
		t.Fatal("cross-tenant command changed queue ownership")
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var role string
		if err := tx.QueryRow(ctx, `SELECT required_agent_role FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyPreparationOutboxKey(command.Ref.ID)).Scan(&role); err != nil {
			return err
		}
		if role != "control_plane" {
			t.Fatal("key preparation became claimable by a remote agent")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
