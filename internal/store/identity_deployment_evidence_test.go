// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestIdentityDeploymentEvidenceKeepsExactHistoricalCompletion(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "same owner"})
	if err != nil {
		t.Fatal(err)
	}
	var identities []store.Identity
	for range 2 {
		identity, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA, OwnerID: owner.ID, Kind: store.KindX509Certificate, Name: "same.example"})
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
	}
	if _, found, err := s.LatestIdentityDeploymentReceipt(ctx, tenantA, identities[0].ID); err != nil || found {
		t.Fatalf("empty: found=%v err=%v", found, err)
	}
	now := time.Now().UTC()
	for n, row := range []struct {
		identity                         int
		destination, status, fingerprint string
	}{
		{0, "connector.deploy", "verified", "first"},
		{0, "connector.deploy", "verify_failed", "failed"},
		{0, "connector.rollback", "queued", "queued"},
		{0, "connector.rollback", "rollback_failed", "failed-restore"},
		{1, "connector.deploy", "verified", "other-identity"},
		{0, "connector.rollback", "rolled_back", "restored"},
		{0, "connector.deploy", "delivered", "renewed"},
	} {
		at := now.Add(time.Duration(n) * time.Second)
		err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: fmt.Sprintf("03500000-0000-4000-8000-%012d", n+1), TenantID: tenantA,
				IdentityID: &identities[row.identity].ID, Destination: row.destination, Connector: "traefik", Target: "same-target",
				Fingerprint: row.fingerprint, Status: row.status, IdempotencyKey: fmt.Sprintf("evidence-%d", n), CreatedAt: at, UpdatedAt: at,
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		want := "first"
		if n == 5 {
			want = "restored"
		}
		if n == 6 {
			want = "renewed"
		}
		got, found, err := s.LatestIdentityDeploymentReceipt(ctx, tenantA, identities[0].ID)
		if err != nil || !found || got.Fingerprint != want {
			t.Fatalf("step %d: found=%v got=%s want=%s err=%v", n, found, got.Fingerprint, want, err)
		}
	}
	// Same ID in another tenant, and an unrelated identity, never inherit proof.
	for _, ids := range [][2]string{{tenantB, identities[0].ID}, {tenantA, store.ZeroUUID}} {
		if _, found, err := s.LatestIdentityDeploymentReceipt(ctx, ids[0], ids[1]); err != nil || found {
			t.Fatalf("isolation: found=%v err=%v", found, err)
		}
	}
}
