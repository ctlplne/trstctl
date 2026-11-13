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

// A235-L5: when the project's owner names a CMDB application, the
// application view spans every owner of that application — another team's
// certificates and identities for the same application are part of it — and
// an owner without an application still sees only its own.
func TestOwnerApplicationInventorySpansTheOwnersApplicationA235L5(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenant := googleuuid.NewString()
	seedTenant(t, s, tenant)
	owner := func(name, application string) string {
		t.Helper()
		o, err := s.CreateOwner(ctx, store.Owner{TenantID: tenant, Kind: store.OwnerTeam, Name: name, ApplicationID: application})
		if err != nil {
			t.Fatal(err)
		}
		return o.ID
	}
	payments, platform, billing, solo := owner("Payments team", "APP-PAY"), owner("Platform team", " APP-PAY "), owner("Billing team", "APP-BILL"), owner("Solo", "")
	now := time.Now().UTC()
	if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		for i, c := range []struct {
			owner string
			days  int
		}{{payments, 90}, {platform, 5}, {billing, 1}, {solo, 30}} {
			if _, err := tx.Exec(ctx, `INSERT INTO certificates (id, tenant_id, owner_id, subject, fingerprint, not_after) VALUES ($1, $2, $3, $4, $5, $6)`,
				googleuuid.NewString(), tenant, c.owner, "CN=a235l5-"+string(rune('a'+i)), "fp-"+googleuuid.NewString(), now.Add(time.Duration(c.days)*24*time.Hour)); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO identities (id, tenant_id, kind, name, owner_id, status) VALUES ($1, $2, 'spiffe', 'platform-gateway', $3, 'active')`,
			googleuuid.NewString(), tenant, platform)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	inv, err := s.OwnerApplicationInventory(ctx, tenant, payments, 5)
	if err != nil {
		t.Fatal(err)
	}
	if inv.ApplicationID != "APP-PAY" || inv.Owners != 2 || inv.Certificates != 2 || inv.Identities != 1 ||
		len(inv.SoonestCertificate) != 2 || inv.SoonestCertificate[0].Name != "CN=a235l5-b" || inv.SoonestIdentities[0].Name != "platform-gateway" {
		t.Fatalf("application inventory = %+v; want APP-PAY across both of its owners", inv)
	}
	alone, err := s.OwnerApplicationInventory(ctx, tenant, solo, 5)
	if err != nil || alone.ApplicationID != "" || alone.Owners != 1 || alone.Certificates != 1 || alone.Identities != 0 {
		t.Fatalf("an owner without an application = %+v (%v)", alone, err)
	}
	if gone, err := s.OwnerApplicationInventory(ctx, tenant, googleuuid.NewString(), 5); err != nil || gone.Owners != 1 || gone.Certificates != 0 {
		t.Fatalf("an owner that no longer resolves = %+v (%v)", gone, err)
	}
}
