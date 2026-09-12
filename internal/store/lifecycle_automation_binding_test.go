// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Same owner and SAN are common during CA replacement. A short-lived successor
// must not inherit the old CA's later expiry in the operator's automation plan.
func TestLifecycleAutomationUsesIdentityBoundServedCertificate(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	owner, err := s.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerTeam, Name: "same service owner"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var identities []store.Identity
	var certs []store.Certificate
	// These are relational read-model fixtures, not signing or live TLS proof.
	for i, lifetime := range []time.Duration{10 * time.Minute, 90 * 24 * time.Hour} {
		identity, err := s.CreateIdentity(ctx, store.Identity{TenantID: tenantA,
			Kind: store.KindX509Certificate, Name: "shared.example.test", OwnerID: owner.ID})
		if err != nil {
			t.Fatal(err)
		}
		identity.Status = "deployed"
		if err := s.UpsertIdentity(ctx, identity); err != nil {
			t.Fatal(err)
		}
		end := now.Add(lifetime)
		cert, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, OwnerID: &owner.ID,
			Subject: "CN=shared.example.test", SANs: []string{"shared.example.test"}, Issuer: fmt.Sprintf("CA %d", i),
			Serial: fmt.Sprint(i + 1), Fingerprint: strings.Repeat(fmt.Sprint(i+1), 64),
			Source: "issued", Status: "active", NotBefore: &now, NotAfter: &end})
		if err != nil {
			t.Fatal(err)
		}
		identities, certs = append(identities, identity), append(certs, cert)
	}
	for i, fixture := range []struct {
		identity, certificate int
		status                string
	}{{0, 0, "verified"}, {1, 1, "verified"}, {0, 1, "verify_failed"}} {
		at := now.Add(time.Duration(i) * time.Second)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: fmt.Sprintf("33333333-3333-4333-8333-%012d", i+1), TenantID: tenantA,
				IdentityID: &identities[fixture.identity].ID, Destination: "connector.deploy", Connector: "caddy", Target: "same-target",
				Fingerprint: certs[fixture.certificate].Fingerprint, Status: fixture.status,
				IdempotencyKey: fmt.Sprintf("delivery-%d", i), CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
	if err != nil || len(rows) != 2 {
		t.Fatalf("inventory count=%d error=%v", len(rows), err)
	}
	for _, row := range rows {
		for i, identity := range identities {
			if row.IdentityID == identity.ID && (row.CertificateID != certs[i].ID || !row.CertificateEnd.Equal(*certs[i].NotAfter)) {
				t.Fatalf("identity %s plan uses certificate %s expiring %v; exact deployed certificate is %s expiring %v",
					identity.ID, row.CertificateID, row.CertificateEnd, certs[i].ID, certs[i].NotAfter)
			}
		}
	}
	// A restore changes the served leaf only after the executor proves success.
	// In particular, the older leaf's earlier expiry must become authoritative.
	// Issuance keeps the predecessor as superseded even when an executor restores it.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.SetCertificateSupersededTx(ctx, tx, tenantA, certs[0].Fingerprint, now)
	}); err != nil {
		t.Fatal(err)
	}
	for i, step := range []struct {
		destination, status string
		certificate, want   int
	}{
		{"connector.rollback", "rollback_queued", 0, 1},
		{"connector.rollback", "rollback_failed", 0, 1},
		{"connector.rollback", "rolled_back", 0, 0},
		{"connector.deploy", "verify_failed", 1, 0},
		{"connector.deploy", "verified", 1, 1},
		{"connector.rollback", "rolled_back", 0, 1},
	} {
		at := now.Add(time.Duration(i+10) * time.Second)
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if i == 5 {
				// Even a newer retained receipt must never revive a revoked leaf.
				if err := s.SetCertificateRevokedTx(ctx, tx, tenantA, certs[0].Fingerprint, "keyCompromise", at); err != nil {
					return err
				}
			}
			return s.ApplyConnectorDeliveryRecordedTx(ctx, tx, store.ConnectorDeliveryReceipt{
				ID: fmt.Sprintf("44444444-4444-4444-8444-%012d", i+1), TenantID: tenantA,
				IdentityID: &identities[1].ID, Destination: step.destination, Connector: "caddy", Target: "same-target",
				Fingerprint: certs[step.certificate].Fingerprint, Status: step.status,
				IdempotencyKey: fmt.Sprintf("restore-step-%d", i), CreatedAt: at, UpdatedAt: at,
			})
		}); err != nil {
			t.Fatal(err)
		}
		fingerprint, found, err := s.LatestDeployedCertificateFingerprintForIdentity(ctx, tenantA, identities[1].ID)
		if err != nil || !found || fingerprint != certs[step.want].Fingerprint {
			t.Fatalf("after %s/%s scheduler selected %q found=%v error=%v; want %q", step.destination, step.status, fingerprint, found, err, certs[step.want].Fingerprint)
		}
		rows, err := s.ListLifecycleAutomationInventory(ctx, tenantA, 100)
		if err != nil || len(rows) != 2 {
			t.Fatalf("after restore inventory count=%d error=%v", len(rows), err)
		}
		for _, row := range rows {
			if row.IdentityID == identities[1].ID && (row.CertificateID != certs[step.want].ID || !row.CertificateEnd.Equal(*certs[step.want].NotAfter)) {
				t.Fatalf("after %s/%s plan selected %s expiring %v; want %s expiring %v", step.destination, step.status, row.CertificateID, row.CertificateEnd, certs[step.want].ID, certs[step.want].NotAfter)
			}
		}
	}
	if fingerprint, found, err := s.LatestDeployedCertificateFingerprintForIdentity(ctx, tenantB, identities[1].ID); err != nil || found || fingerprint != "" {
		t.Fatalf("foreign tenant resolved certificate=%q found=%v error=%v", fingerprint, found, err)
	}
}
