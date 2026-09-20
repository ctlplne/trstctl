// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestACMEDNS01ProviderProjectionQuarantinesLegacyDuplicateNameEvent(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	apply := func(candidate store.ACMEDNS01ProviderConfig) error {
		return s.WithTenant(ctx, candidate.TenantID, func(tx pgx.Tx) error {
			return s.ApplyACMEDNS01ProviderConfigUpsertedTx(ctx, tx, candidate)
		})
	}
	original := store.ACMEDNS01ProviderConfig{
		ID: "69000000-0000-0000-0000-000000000001", TenantID: tenantA,
		Name: "production-webhook", Provider: "webhook", Zone: "one.example.test",
		CredentialRefs: json.RawMessage(`{}`), Config: json.RawMessage(`{"endpoint":"http://dns-one.invalid"}`),
		AllowedMethods: []string{"dns-01"}, CreatedAt: now, UpdatedAt: now,
	}
	if err := apply(original); err != nil {
		t.Fatalf("project original provider config: %v", err)
	}

	legacyDuplicate := original
	legacyDuplicate.ID = "69000000-0000-0000-0000-000000000002"
	legacyDuplicate.Zone = "two.example.test"
	legacyDuplicate.Config = json.RawMessage(`{"endpoint":"http://dns-two.invalid"}`)
	if err := apply(legacyDuplicate); err != nil {
		t.Fatalf("legacy duplicate-name event poisoned projection replay: %v", err)
	}
	if _, err := s.GetACMEDNS01ProviderConfig(ctx, tenantA, legacyDuplicate.ID); !errors.Is(err, store.ErrACMEDNS01ProviderConfigNotFound) {
		t.Fatalf("legacy duplicate-name event materialized a second row: %v", err)
	}
	got, err := s.GetACMEDNS01ProviderConfig(ctx, tenantA, original.ID)
	var gotConfig map[string]string
	if err == nil {
		err = json.Unmarshal(got.Config, &gotConfig)
	}
	if err != nil || got.Name != original.Name || got.Zone != original.Zone || gotConfig["endpoint"] != "http://dns-one.invalid" {
		t.Fatalf("legacy duplicate-name event changed first-writer authority: got=%+v err=%v", got, err)
	}

	trailing := original
	trailing.ID = "69000000-0000-0000-0000-000000000003"
	trailing.Name = "staging-webhook"
	trailing.Zone = "three.example.test"
	if err := apply(trailing); err != nil {
		t.Fatalf("valid event after legacy duplicate did not project: %v", err)
	}
	if got, err := s.GetACMEDNS01ProviderConfig(ctx, tenantA, trailing.ID); err != nil || got.Name != trailing.Name {
		t.Fatalf("valid event after legacy duplicate is missing: got=%+v err=%v", got, err)
	}
}
