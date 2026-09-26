// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestBootstrapRedemptionRequiresExactLiveConsumedRow(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	create := func(hash string) store.BootstrapTokenRecord {
		t.Helper()
		r, err := s.CreateBootstrapToken(ctx, store.BootstrapTokenRecord{TenantID: tenantA, TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	used := create("sha256:used-redemption")
	unused := create("sha256:unused-redemption")
	if _, err := s.RedeemBootstrapToken(ctx, used.TokenHash); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateBootstrapTokenRedemption(ctx, tenantA, used.ID, used.TokenHash); err != nil {
		t.Fatalf("live consumed row refused: %v", err)
	}
	for _, tt := range []struct{ name, tenant, id, hash string }{
		{"other tenant", tenantB, used.ID, used.TokenHash},
		{"other row", tenantA, unused.ID, used.TokenHash},
		{"other hash", tenantA, used.ID, unused.TokenHash},
		{"unused", tenantA, unused.ID, unused.TokenHash},
		{"missing id", tenantA, "", used.TokenHash},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.ValidateBootstrapTokenRedemption(ctx, tt.tenant, tt.id, tt.hash); !store.IsNotFound(err) {
				t.Fatalf("invalid redemption accepted: %v", err)
			}
		})
	}
	// Expire only this owned fixture row after redemption. No host clock changes.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agent_bootstrap_tokens SET expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenantA, used.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateBootstrapTokenRedemption(ctx, tenantA, used.ID, used.TokenHash); !store.IsNotFound(err) {
		t.Fatalf("expired redemption accepted: %v", err)
	}
	// Store errors must remain errors rather than masquerading as valid authority.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.ValidateBootstrapTokenRedemption(canceled, tenantA, used.ID, used.TokenHash); err == nil {
		t.Fatal("canceled validation admitted signing")
	}
}
