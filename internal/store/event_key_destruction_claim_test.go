// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	guuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func TestEventKeyDestructionRequiresExactPostDeleteInvocation(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	at := time.Now().UTC()
	command := eventprotect.DestructionRequest{
		Ref:         eventprotect.KeyRef{TenantID: tenantA, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"},
		OperationID: "eb08db3a-2d9e-4192-b2b9-b156308860e4", RegistrationIdentity: "registered-source",
		ActivationEventID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb", ActivationSequence: 7,
		CreationDigest: strings.Repeat("a", 64), OffboardEventID: "offboard-source", OffboardSequence: 9,
		OffboardedAt: at, NotBefore: at.Add(time.Hour),
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := s.OffboardTenantForEventKeyDestructionTx(ctx, tx, command)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	claim := store.EventKeyDestructionClaim{AttemptID: guuid.NewString(), Attempts: 1, Command: command}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, tenantA, store.EventKeyDestructionOutboxKey(command.OperationID)).Scan(&claim.ID)
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	visit := func(context.Context) error { called = true; return nil }
	if err := s.WithEventKeyDestructionClaim(ctx, claim, visit); err == nil || called {
		t.Fatal("a pending intent alone authorized key I/O")
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE outbox SET status='processing',worker_id='fixture',attempts=1,
		 lease_until=clock_timestamp()+interval '1 minute',receiver_pending_ids=ARRAY[$3::uuid]
		 WHERE tenant_id=$1 AND id=$2`, tenantA, claim.ID, claim.AttemptID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireLiveTenantService(ctx, tenantA); err == nil {
		t.Fatal("normal deleted-tenant service check was weakened")
	}
	if err := s.RequireEventKeyDestructionService(ctx, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := s.WithEventKeyDestructionClaim(ctx, claim, visit); err != nil || !called {
		t.Fatalf("current dedicated invocation refused after relational erasure: %v", err)
	}
	for _, change := range []struct {
		name   string
		mutate func(*store.EventKeyDestructionClaim)
	}{
		{"token", func(c *store.EventKeyDestructionClaim) { c.AttemptID = guuid.NewString() }},
		{"attempt", func(c *store.EventKeyDestructionClaim) { c.Attempts++ }},
		{"tenant", func(c *store.EventKeyDestructionClaim) { c.Command.Ref.TenantID = tenantB }},
		{"key", func(c *store.EventKeyDestructionClaim) { c.Command.Ref.ID = guuid.NewString() }},
		{"operation", func(c *store.EventKeyDestructionClaim) { c.Command.OperationID = guuid.NewString() }},
		{"lifetime", func(c *store.EventKeyDestructionClaim) { c.Command.RegistrationIdentity = "different-registration" }},
		{"creation", func(c *store.EventKeyDestructionClaim) { c.Command.CreationDigest = strings.Repeat("b", 64) }},
		{"activation", func(c *store.EventKeyDestructionClaim) { c.Command.ActivationSequence++ }},
		{"offboard", func(c *store.EventKeyDestructionClaim) { c.Command.OffboardSequence++ }},
		{"deadline", func(c *store.EventKeyDestructionClaim) { c.Command.NotBefore = c.Command.NotBefore.Add(time.Second) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			bad := claim
			change.mutate(&bad)
			called = false
			if err := s.WithEventKeyDestructionClaim(ctx, bad, visit); err == nil || called {
				t.Fatal("changed invocation reached key callback")
			}
		})
	}
	for _, routing := range []struct{ name, change, restore string }{
		{"role", `UPDATE outbox SET required_agent_role='network' WHERE tenant_id=$1 AND id=$2`, `UPDATE outbox SET required_agent_role='control_plane' WHERE tenant_id=$1 AND id=$2`},
		{"lane", `UPDATE outbox SET effect_lane='unrelated' WHERE tenant_id=$1 AND id=$2`, `UPDATE outbox SET effect_lane=destination WHERE tenant_id=$1 AND id=$2`},
	} {
		t.Run(routing.name, func(t *testing.T) {
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, routing.change, tenantA, claim.ID); return err }); err != nil {
				t.Fatal(err)
			}
			called = false
			if err := s.WithEventKeyDestructionClaim(ctx, claim, visit); err == nil || called {
				t.Fatal("changed persisted routing reached key callback")
			}
			if err := s.RequireEventKeyDestructionService(ctx, tenantA); err == nil {
				t.Fatal("dedicated service precheck admitted changed routing")
			}
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, routing.restore, tenantA, claim.ID); return err }); err != nil {
				t.Fatal(err)
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
	if err := s.WithEventKeyDestructionClaim(ctx, claim, visit); err == nil || called {
		t.Fatal("expired invocation reached key callback")
	}
}
