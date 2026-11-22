// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// CR-020: the person who minted a historical delegated token has a privacy
// interest in its metadata even though another person holds the bearer.
func TestAPITokenMinterPrivacyExportAndErasure(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: tenant}); err != nil {
			t.Fatal(err)
		}
	}
	const minter = "cr020-privacy-minter"
	const holder = "cr020-privacy-holder"
	var tokenA, tokenB store.APITokenRecord
	for _, tenant := range []string{tenantA, tenantB} {
		token, err := s.CreateAPIToken(ctx, store.APITokenRecord{
			TenantID: tenant, TokenHash: "cr020-" + tenant, Subject: holder,
			MintedBy: minter, Scopes: []string{"owners:read"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if tenant == tenantA {
			tokenA = token
		} else {
			tokenB = token
		}
	}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, minter)
	if err != nil || len(exported.Tokens) != 1 || exported.Tokens[0].ID != tokenA.ID ||
		exported.Tokens[0].MintedBy != minter || exported.Counts["api_tokens"] != 1 {
		t.Fatalf("minter export token metadata = %+v err=%v", exported.Tokens, err)
	}
	plan, err := s.SelectPrivacySubjectErasure(ctx, tenantA, minter)
	if err != nil || plan.Counts["api_tokens"] != 1 {
		t.Fatalf("minter erasure plan tokens = %v err=%v", plan.Counts, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyPrivacySubjectErasedTx(ctx, tx, plan)
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAPIToken(ctx, tenantA, tokenA.ID)
	if err != nil || got.Subject != holder || got.MintedBy != privacy.Placeholder(privacy.SubjectRef(tenantA, minter)) || got.RevokedAt == nil {
		t.Fatalf("erased minter token metadata = subject %q minter %q revoked %v err=%v", got.Subject, got.MintedBy, got.RevokedAt, err)
	}
	exported, err = s.SelectPrivacySubjectExport(ctx, tenantA, minter)
	if err != nil || len(exported.Tokens) != 0 || exported.Counts["api_tokens"] != 0 {
		t.Fatalf("erased minter still in export = %+v counts=%v err=%v", exported.Tokens, exported.Counts, err)
	}
	other, err := s.GetAPIToken(ctx, tenantB, tokenB.ID)
	if err != nil || other.MintedBy != minter || other.RevokedAt != nil {
		t.Fatalf("cross-tenant minter changed = minter %q revoked %v err=%v", other.MintedBy, other.RevokedAt, err)
	}
	// A lagging projector must not restore the erased minter or revive its
	// delegated bearer when it encounters an older source event later.
	lateID := uuid(tenantA, 92020)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyAPITokenCreatedTx(ctx, tx, store.APITokenRecord{
			ID: lateID, TenantID: tenantA, TokenHash: privacy.SubjectRef(tenantA, "cr020-late-projection"),
			Subject: holder, MintedBy: minter, Scopes: []string{"owners:read"},
		})
	}); err != nil {
		t.Fatal(err)
	}
	late, err := s.GetAPIToken(ctx, tenantA, lateID)
	if err != nil || late.MintedBy != privacy.Placeholder(privacy.SubjectRef(tenantA, minter)) || late.RevokedAt == nil {
		t.Fatalf("late delegated projection restored erased minter = minter %q revoked %v err=%v", late.MintedBy, late.RevokedAt, err)
	}
}

// An upgraded database can have delegated rows whose old read model did not
// retain the actor. Until source replay recovers that actor, the bearer must
// fail closed because minter offboarding cannot be enforced for it.
func TestDelegatedAPITokenWithUnknownHistoricalMinterIsRefused(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "CR-020 legacy"}); err != nil {
		t.Fatal(err)
	}
	const hash = "cr020-legacy-delegated-hash"
	token, err := s.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID: tenantA, TokenHash: hash, Subject: "legacy-recipient", Scopes: []string{"owners:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_tokens SET delegated = true WHERE tenant_id = $1 AND id = $2`, tenantA, token.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupAPITokenByHash(ctx, hash); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("legacy delegated bearer without minter provenance was accepted: %v", err)
	}
}
