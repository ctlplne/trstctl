// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestTokenListShowsOnlyLiveEntriesByDefault(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	now := time.Now().UTC()
	var ids []string
	for _, item := range []struct {
		name    string
		expiry  time.Time
		revoked bool
	}{
		{"live", now.Add(time.Hour), false},
		{"expired", now.Add(-time.Hour), false},
		{"revoked", now.Add(time.Hour), true},
	} {
		rec, err := s.CreateAPIToken(ctx, store.APITokenRecord{
			TenantID: tenantA, Subject: "listed-member", TokenHash: privacy.SubjectRef(tenantA, "listing-"+item.name),
			Scopes: []string{"certs:read"}, ExpiresAt: &item.expiry,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, rec.ID)
		if item.revoked {
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at=now() WHERE tenant_id=$1 AND id=$2`, tenantA, rec.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	active, err := s.ListAPITokensPage(ctx, tenantA, store.ZeroUUID, "listed-member", false, 10)
	if err != nil || len(active) != 1 || active[0].ID != ids[0] {
		t.Fatalf("live token list = %v, err = %v", active, err)
	}
	history, err := s.ListAPITokensPage(ctx, tenantA, store.ZeroUUID, "listed-member", true, 10)
	if err != nil || len(history) != 3 {
		t.Fatalf("token history count = %d, err = %v", len(history), err)
	}
	other, err := s.ListAPITokensPage(ctx, tenantB, store.ZeroUUID, "listed-member", true, 10)
	if err != nil || len(other) != 0 {
		t.Fatalf("other tenant token count = %d, err = %v", len(other), err)
	}
}
