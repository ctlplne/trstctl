// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A235's application view: an owner's certificates and identities are counted
// and listed soonest-expiring first; an unknown owner joins nothing.
func TestOwnerApplicationInventoryA235(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenant := googleuuid.NewString()
	seedTenant(t, s, tenant)
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenant, Kind: store.OwnerTeam, Name: "Payments team"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateOwner(ctx, store.Owner{TenantID: tenant, Kind: store.OwnerTeam, Name: "Billing team"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		for i, c := range []struct {
			owner string
			days  int
		}{{owner.ID, 90}, {owner.ID, 10}, {other.ID, 1}} {
			if _, err := tx.Exec(ctx, `INSERT INTO certificates (id, tenant_id, owner_id, subject, fingerprint, not_after) VALUES ($1, $2, $3, $4, $5, $6)`,
				googleuuid.NewString(), tenant, c.owner, "CN=svc-"+string(rune('a'+i)), "fp-"+googleuuid.NewString(), now.Add(time.Duration(c.days)*24*time.Hour)); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO identities (id, tenant_id, kind, name, owner_id, status) VALUES ($1, $2, 'spiffe', 'payments-api', $3, 'active')`,
			googleuuid.NewString(), tenant, owner.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	inv, err := s.OwnerApplicationInventory(ctx, tenant, owner.ID, 5)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Certificates != 2 || inv.Identities != 1 || len(inv.SoonestCertificate) != 2 || inv.SoonestCertificate[0].Name != "CN=svc-b" ||
		len(inv.SoonestIdentities) != 1 || inv.SoonestIdentities[0].Kind != "spiffe" {
		t.Fatalf("inventory = %+v", inv)
	}
	if none, err := s.OwnerApplicationInventory(ctx, tenant, "", 5); err != nil || none.Certificates != 0 || none.SoonestCertificate != nil {
		t.Fatalf("an unknown owner joined %+v (%v)", none, err)
	}
}
