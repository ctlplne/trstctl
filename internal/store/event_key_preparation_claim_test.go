// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	guuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func TestEventKeyPreparationRequiresCurrentDurableInvocation(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "fixture", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	command := store.EventKeyPreparationCommand{
		Ref:                  eventprotect.KeyRef{TenantID: tenantA, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"},
		RegistrationIdentity: "registration", RequestedEventID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb:requested",
		RequestedSequence: 7, RequestedAt: time.Now().UTC(), RetentionNanos: int64(time.Hour),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.EnsureEventKeyPreparationTx(ctx, tx, command) }); err != nil {
		t.Fatal(err)
	}
	claim := store.EventKeyPreparationClaim{AttemptID: guuid.NewString(), Attempts: 1, Command: command}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyPreparationOutboxKey(command.Ref.ID)).Scan(&claim.ID)
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	visit := func(context.Context) error { called = true; return nil }
	if err := s.WithEventKeyPreparationClaim(ctx, claim, visit); err == nil || called {
		t.Fatal("pending row authorized a key effect")
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='processing', worker_id='fixture', attempts=1, lease_until=clock_timestamp()+interval '1 minute', receiver_pending_ids=ARRAY[$3::uuid] WHERE tenant_id=$1 AND id=$2`, tenantA, claim.ID, claim.AttemptID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WithEventKeyPreparationClaim(ctx, claim, visit); err != nil || !called {
		t.Fatalf("current durable invocation refused: %v", err)
	}
	for _, change := range []struct {
		name   string
		mutate func(*store.EventKeyPreparationClaim)
	}{
		{"token", func(c *store.EventKeyPreparationClaim) { c.AttemptID = guuid.NewString() }},
		{"attempt", func(c *store.EventKeyPreparationClaim) { c.Attempts++ }},
		{"tenant", func(c *store.EventKeyPreparationClaim) { c.Command.Ref.TenantID = tenantB }},
		{"payload", func(c *store.EventKeyPreparationClaim) { c.Command.RetentionNanos++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			bad := claim
			change.mutate(&bad)
			called = false
			if err := s.WithEventKeyPreparationClaim(ctx, bad, visit); err == nil || called {
				t.Fatal("changed invocation reached key callback")
			}
		})
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenantA, claim.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	called = false
	if err := s.WithEventKeyPreparationClaim(ctx, claim, visit); err == nil || called {
		t.Fatal("expired invocation reached key callback")
	}
}
