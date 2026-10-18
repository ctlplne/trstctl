// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A pre-append command must outlive the read-model rebuild that deletes its
// ceremony parent. Otherwise recovery can mistake the ceremony for unclaimed
// and mint a second release event after a restart.
func TestCACeremonyEffectFenceSurvivesReadModelRebuild(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)
	ceremonyID, err := s.CreateKeyCeremony(ctx, tenantA, "release-test", "opener", 2)
	if err != nil {
		t.Fatal(err)
	}
	actor := events.Actor{Subject: "release-operator", Roles: []string{"admin"}}
	const keyID = "00000000-0000-4000-8000-00000000a039"
	const certificateID = "00000000-0000-4000-8000-00000000a040"
	payload := func(id string) []byte {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"tenant_id": tenantA, "key_id": keyID, "ceremony_id": id,
			"dependent": map[string]string{"class": "credential", "id": certificateID},
		})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	ev := events.Event{ID: events.NewID(), TenantID: tenantA, Type: "dependency.released",
		SchemaVersion: 2, Time: time.Now().UTC().Truncate(time.Microsecond),
		Actor: &actor, Data: payload(ceremonyID)}
	command := store.CACeremonyEffectCommand{TenantID: tenantA, CeremonyID: ceremonyID,
		KeyID: keyID, CertificateID: certificateID, Event: ev}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ReserveCACeremonyEffectCommandTx(ctx, tx, command)
	}); err != nil {
		t.Fatalf("reserve pre-append command: %v", err)
	}
	secondCeremonyID, err := s.CreateKeyCeremony(ctx, tenantA, "second release attempt", "other-opener", 2)
	if err != nil {
		t.Fatal(err)
	}
	secondEvent := ev
	secondEvent.ID = events.NewID()
	secondEvent.Data = payload(secondCeremonyID)
	second := store.CACeremonyEffectCommand{TenantID: tenantA, CeremonyID: secondCeremonyID,
		KeyID: keyID, CertificateID: certificateID, Event: secondEvent}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ReserveCACeremonyEffectCommandTx(ctx, tx, second)
	}); err == nil {
		t.Fatal("a second ceremony claimed the same CA key and certificate before the first append")
	}
	if err := s.RebuildReadModelTx(ctx, func(pgx.Tx) error { return nil }); err != nil {
		t.Fatalf("rebuild must not cascade into independent command: %v", err)
	}
	got, err := s.GetCACeremonyEffectCommand(ctx, tenantA, ceremonyID)
	if err != nil || got.Status != "pending" || got.Event.ID != ev.ID {
		t.Fatalf("pending first-writer command lost across rebuild: %+v, %v", got, err)
	}
	if _, err := s.GetCACeremonyEffectCommand(ctx, tenantB, ceremonyID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("other tenant can read command: %v", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.CompleteCACeremonyEffectCommandTx(ctx, tx, tenantA, ceremonyID, ev)
	}); err != nil {
		t.Fatalf("complete exact command after rebuild: %v", err)
	}
	got, err = s.GetCACeremonyEffectCommand(ctx, tenantA, ceremonyID)
	if err != nil || got.Status != "completed" || len(got.Event.Data) != 0 || got.Event.Actor != nil {
		t.Fatalf("completed command retained transient material: %+v, %v", got, err)
	}
}
