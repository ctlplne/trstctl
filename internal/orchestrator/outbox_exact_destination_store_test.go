// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestOutboxExactDestinationClaimKeepsNormalAndDedicatedQueuesDisjoint(t *testing.T) {
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	outbox := orchestrator.NewOutbox(st)
	ids := map[string]int64{}
	for _, destination := range []string{"eventprivacy.destroy", "eventprivacy.destroy.extra", "connector.deploy"} {
		ids[destination] = enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: destination, IdempotencyKey: destination, Payload: []byte(`{}`)})
	}
	var special []string
	n, err := outbox.DispatchScoped(t.Context(), orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		special = append(special, message.Destination)
		return nil
	}), orchestrator.DestinationScope{IncludeDestinations: []string{"eventprivacy.destroy"}})
	if err != nil || n != 1 || len(special) != 1 || special[0] != "eventprivacy.destroy" {
		t.Fatalf("exact SQL claim crossed scope: n%d destinations%v err%v", n, special, err)
	}
	for _, destination := range []string{"eventprivacy.destroy.extra", "connector.deploy"} {
		record, err := outbox.Get(t.Context(), tenantA, ids[destination])
		if err != nil || record.Status != "pending" || record.Attempts != 0 {
			t.Fatalf("special scope changed ordinary row %q: %+v %v", destination, record, err)
		}
	}
	var normal []string
	n, err = outbox.DispatchScoped(t.Context(), orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		normal = append(normal, message.Destination)
		return nil
	}), orchestrator.DestinationScope{ExcludeDestinations: []string{"eventprivacy.destroy"}})
	if err != nil || n != 2 || len(normal) != 2 {
		t.Fatalf("normal SQL claim scope lost its remaining rows: n%d destinations%v err%v", n, normal, err)
	}
	for _, destination := range normal {
		if destination == "eventprivacy.destroy" {
			t.Fatal("normal scope claimed the special destination")
		}
	}
}

func TestOutboxExactDestinationLeaseRecoveryDoesNotMutatePrefixCollision(t *testing.T) {
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	outbox := orchestrator.NewOutbox(st)
	exact := enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: "eventprivacy.destroy", IdempotencyKey: "exact-expired", Payload: []byte(`{}`)})
	collision := enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: "eventprivacy.destroy.extra", IdempotencyKey: "collision-expired", Payload: []byte(`{}`)})
	// Fault injection into owned fixture bookkeeping, not domain state mutation.
	if err := st.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE outbox SET status='processing',worker_id='expired-exact-fixture',lease_until=clock_timestamp()-interval '1 minute',attempts=1 WHERE tenant_id=$1 AND id=ANY($2::bigint[])`, tenantA, []int64{exact, collision})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n, err := outbox.DispatchScoped(t.Context(), orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		if message.Destination != "eventprivacy.destroy" {
			t.Fatal("special recovery reached collision handler")
		}
		return nil
	}), orchestrator.DestinationScope{IncludeDestinations: []string{"eventprivacy.destroy"}})
	if err != nil || n != 1 {
		t.Fatalf("exact expired claim did not recover: n%d err%v", n, err)
	}
	untouched, err := outbox.Get(t.Context(), tenantA, collision)
	if err != nil || untouched.Status != "processing" || untouched.Attempts != 1 {
		t.Fatalf("special sweep rewrote ordinary expired lease: %+v %v", untouched, err)
	}
}

func TestOutboxExactDestinationInFlightBudgetExcludesOrdinaryPrefixCollision(t *testing.T) {
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	outbox := orchestrator.NewOutbox(st, orchestrator.WithMaxInFlightPerTenant(1))
	collision := enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: "eventprivacy.destroy.extra", IdempotencyKey: "collision-held", Payload: []byte(`{}`)})
	enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: "eventprivacy.destroy", IdempotencyKey: "exact-progress", Payload: []byte(`{}`)})
	if err := st.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE outbox SET status='processing',worker_id='held-exact-fixture',lease_until=clock_timestamp()+interval '1 minute',attempts=1 WHERE tenant_id=$1 AND id=$2`, tenantA, collision)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n, err := outbox.DispatchScoped(t.Context(), orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		if message.Destination != "eventprivacy.destroy" {
			t.Fatal("special budget crossed scope")
		}
		return nil
	}), orchestrator.DestinationScope{IncludeDestinations: []string{"eventprivacy.destroy"}})
	if err != nil || n != 1 {
		t.Fatalf("ordinary in-flight work consumed the dedicated exact budget: n%d err%v", n, err)
	}
}

func TestOutboxExactDestinationExclusionLeavesSpecialPendingAndExpiredRowsUnchanged(t *testing.T) {
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	outbox := orchestrator.NewOutbox(st)
	pending := enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: "eventprivacy.destroy", IdempotencyKey: "special-pending", Payload: []byte(`{}`)})
	expired := enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: "eventprivacy.destroy", IdempotencyKey: "special-expired", Payload: []byte(`{}`)})
	enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: "eventprivacy.destroy.extra", IdempotencyKey: "normal-collision", Payload: []byte(`{}`)})
	if err := st.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE outbox SET status='processing',worker_id='excluded-expired-fixture',lease_until=clock_timestamp()-interval '1 minute',attempts=1 WHERE tenant_id=$1 AND id=$2`, tenantA, expired)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n, err := outbox.DispatchScoped(t.Context(), orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		if message.Destination != "eventprivacy.destroy.extra" {
			t.Fatal("normal SQL scope admitted its excluded destination")
		}
		return nil
	}), orchestrator.DestinationScope{ExcludeDestinations: []string{"eventprivacy.destroy"}})
	if err != nil || n != 1 {
		t.Fatalf("normal exact exclusion did not select only ordinary work: n%d err%v", n, err)
	}
	for _, want := range []struct {
		id       int64
		status   string
		attempts int
	}{{pending, "pending", 0}, {expired, "processing", 1}} {
		row, err := outbox.Get(t.Context(), tenantA, want.id)
		if err != nil || row.Status != want.status || row.Attempts != want.attempts {
			t.Fatalf("normal sweep modified excluded special row: %+v %v", row, err)
		}
	}
}

func TestOutboxExactDestinationSQLTreatsPatternCharactersLiterally(t *testing.T) {
	st := newStore(t)
	mustRegisterTenant(t, st, tenantA)
	outbox := orchestrator.NewOutbox(st)
	for _, destination := range []string{"literal.%_", "literal.ab", "literal.%_.extra"} {
		enqueue(t, st, outbox, orchestrator.Entry{TenantID: tenantA, Destination: destination, IdempotencyKey: destination, Payload: []byte(`{}`)})
	}
	n, err := outbox.DispatchScoped(t.Context(), orchestrator.HandlerFunc(func(_ context.Context, message orchestrator.Message) error {
		if message.Destination != "literal.%_" {
			t.Fatal("SQL exact scope acted as a wildcard")
		}
		return nil
	}), orchestrator.DestinationScope{IncludeDestinations: []string{"literal.%_"}})
	if err != nil || n != 1 {
		t.Fatalf("literal exact SQL scope selected the wrong rows: n%d err%v", n, err)
	}
}
