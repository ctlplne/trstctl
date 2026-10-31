// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// Uses only existing APIs so it can reproduce default-off compatibility before
// any alternate audit schema is implemented. Actual orchestrator and PG/NATS;
// signer is a component fixture, not separate-process qualification.
func TestDefaultOffEventKeyRuntimeRetainsLegacyAuditAfterTenantOffboarding(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.Privacy.EventProtection.KeyDirectory = ""
	key := testAuditSigningKey(t)
	log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = protection.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "7ab4d354-dd79-423a-b9d9-ef585b26a36c"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"legacy audit fixture"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, protection.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: protection})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	if _, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registration.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetTenant(t.Context(), tenant); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("offboard fixture left live tenant state")
	}
	const subject = "legacy-private-reader@example.invalid"
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: subject})
	if err := srv.orch.RecordAuthzDecision(ctx, tenant, orchestrator.AuthzDecision{Actor: subject, Permission: "owners:write", Resource: "api_route", Target: "/api/v1/owners", Decision: "deny"}); err != nil {
		t.Fatalf("default-off source runtime lost the existing audit-only post-delete writer: %v", err)
	}
	var recorded []events.Event
	if err := log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.Type == "authz.decision" {
			recorded = append(recorded, event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 1 || recorded[0].SchemaVersion != 1 || recorded[0].Protection != nil || recorded[0].Actor == nil || recorded[0].Actor.Subject != subject || !bytes.Contains(recorded[0].Data, []byte(subject)) {
		t.Fatal("default-off audit representation changed")
	}
	head, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.orch.CreateOwner(ctx, tenant, "team", "refused", "refused@example.invalid"); err == nil {
		t.Fatal("audit-only exception granted an ordinary post-delete mutation")
	}
	after, err := log.LastSequence(t.Context())
	if err != nil || after != head {
		t.Fatal("refused mutation changed source")
	}
	if _, err := st.GetTenant(t.Context(), tenant); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("audit-only write recreated tenant state")
	}
}
