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

// This tests the SQL half only. The source-backed projector and the destructive
// receiver must separately prove that these public coordinates grant an effect.
func TestEventKeyDestructionIntentCommitsWithEraseAndSurvivesRetry(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "fixture"}); err != nil {
			t.Fatal(err)
		}
		seedTenant(t, s, tenant)
	}
	neighborRows := countTenantRows(t, s, tenantB)
	before := countTenantRows(t, s, tenantA)
	at := time.Now().UTC()
	request := eventprotect.DestructionRequest{
		Ref:         eventprotect.KeyRef{TenantID: tenantA, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"},
		OperationID: "eb08db3a-2d9e-4192-b2b9-b156308860e4", RegistrationIdentity: "registered-source",
		ActivationEventID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", ActivationSequence: 7,
		CreationDigest: strings.Repeat("a", 64), OffboardEventID: "offboard-source", OffboardSequence: 9,
		OffboardedAt: at, NotBefore: at.Add(time.Hour),
	}
	rollback := errors.New("force SQL rollback after retained offboard")
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if _, err := s.OffboardTenantForEventKeyDestructionTx(ctx, tx, request); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if got := countTenantRows(t, s, tenantA); got != before {
		t.Fatalf("rollback leaked erase or key intent: got %d rows, want %d", got, before)
	}
	for i := 0; i < 2; i++ {
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			att, err := s.OffboardTenantForEventKeyDestructionTx(ctx, tx, request)
			if err != nil {
				return err
			}
			if att.Complete || len(att.Residue) != 1 || att.Residue["outbox"] != 1 {
				t.Fatalf("pending independent key effect claimed zero residue: %+v", att)
			}
			var payload []byte
			var role, destination string
			var eligible bool
			if err := tx.QueryRow(ctx, `SELECT payload,required_agent_role,destination,next_attempt_at<=clock_timestamp()
			 FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyDestructionOutboxKey(request.OperationID)).Scan(&payload, &role, &destination, &eligible); err != nil {
				return err
			}
			if role != "control_plane" || destination != store.EventKeyDestructionDestination || eligible || strings.Contains(string(payload), "fixture") {
				t.Fatal("pending intent lost its fixed receiver, retention deadline or minimal public body")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := countTenantRows(t, s, tenantA); got != 0 {
		t.Fatalf("protected erase left ordinary seeded tenant rows: %d", got)
	}
	if got := countTenantRows(t, s, tenantB); got != neighborRows {
		t.Fatal("neighbor tenant changed")
	}
	changed := request
	changed.NotBefore = changed.NotBefore.Add(time.Second)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.OffboardTenantForEventKeyDestructionTx(ctx, tx, changed)
		return err
	}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("retry replaced the retained deadline: %v", err)
	}
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		_, err := s.OffboardTenantForEventKeyDestructionTx(ctx, tx, request)
		return err
	}); err == nil {
		t.Fatal("foreign transaction could authorize another tenant's erase")
	}
	// A retry must inspect, rather than delete, unexpected residue. It must also
	// preserve unresolved invocation tokens already held by the exact worker.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET receiver_pending_ids=ARRAY['bf693d74-4d87-4e9c-94ae-e2362d6ffec6'::uuid] WHERE tenant_id=$1`, tenantA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.OffboardTenantForEventKeyDestructionTx(ctx, tx, request)
		return err
	}); err != nil {
		t.Fatalf("pending retry tried to erase the live invocation instead of retaining it: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT cardinality(receiver_pending_ids) FROM outbox WHERE tenant_id=$1`, tenantA).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatal("pending retry discarded unresolved receiver authority")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "unexpected residue"}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.OffboardTenantForEventKeyDestructionTx(ctx, tx, request)
		return err
	}); err == nil {
		t.Fatal("pending retry silently erased a reintroduced registration")
	}
	if _, err := s.GetTenant(ctx, tenantA); err != nil {
		t.Fatal("failed residue validation deleted the unexpected registration")
	}
	// The non-opt-in path retains its original strict zero-row guarantee.
	if att, err := s.OffboardTenant(ctx, tenantB); err != nil || !att.Complete || len(att.Residue) != 0 {
		t.Fatalf("ordinary offboard guarantee changed: %+v %v", att, err)
	}
}
