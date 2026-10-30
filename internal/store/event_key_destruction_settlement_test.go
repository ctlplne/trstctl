// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

// SQL settlement is not proof of key removal. The receiver integration supplies
// source and independent-custody verification before calling this transaction.
func TestEventKeyDestructionSettlementIsExactAtomicAndPreservesDeliveryFinalization(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	at := time.Now().UTC()
	request := eventprotect.DestructionRequest{
		Ref:         eventprotect.KeyRef{TenantID: tenantA, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"},
		OperationID: "eb08db3a-2d9e-4192-b2b9-b156308860e4", RegistrationIdentity: "registered-source",
		ActivationEventID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", ActivationSequence: 7,
		CreationDigest: strings.Repeat("a", 64), OffboardEventID: "offboard-source", OffboardSequence: 9,
		OffboardedAt: at, NotBefore: at.Add(time.Hour),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := s.OffboardTenantForEventKeyDestructionTx(ctx, tx, request); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='processing',worker_id='fixture',attempts=1,
		 lease_until=clock_timestamp()+interval '1 minute',receiver_pending_ids=ARRAY['fdc5ca32-fb7d-4ea3-b640-fcf032cb0ac5'::uuid]
		 WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyDestructionOutboxKey(request.OperationID))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	read := func() (string, int) {
		t.Helper()
		var status string
		var tokens int
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status,cardinality(receiver_pending_ids) FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyDestructionOutboxKey(request.OperationID)).Scan(&status, &tokens)
		}); err != nil {
			t.Fatal(err)
		}
		return status, tokens
	}
	changed := request
	changed.CreationDigest = strings.Repeat("b", 64)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.SettleEventKeyDestructionTx(ctx, tx, changed) }); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("different creation settled same operation: %v", err)
	}
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error { return s.SettleEventKeyDestructionTx(ctx, tx, request) }); err != nil {
		t.Fatal(err)
	}
	if status, tokens := read(); status != "processing" || tokens != 1 {
		t.Fatal("changed/foreign settlement affected invocation")
	}
	rollback := errors.New("fixture rollback after settlement")
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.SettleEventKeyDestructionTx(ctx, tx, request); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if status, tokens := read(); status != "processing" || tokens != 1 {
		t.Fatal("SQL rollback discarded unresolved invocation")
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.SettleEventKeyDestructionTx(ctx, tx, request) }); err != nil {
		t.Fatal(err)
	}
	if status, tokens := read(); status != "processing" || tokens != 0 {
		t.Fatal("verified settlement changed generic delivery state")
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		removed, err := s.RemoveSettledEventKeyDestructionTx(ctx, tx, request)
		if removed {
			t.Fatal("cleanup bypassed generic finalization")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='delivered' WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyDestructionOutboxKey(request.OperationID))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			removed, err := s.RemoveSettledEventKeyDestructionTx(ctx, tx, request)
			if err == nil && removed != (i == 0) {
				t.Fatalf("exact cleanup retry changed result: %v", removed)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}
