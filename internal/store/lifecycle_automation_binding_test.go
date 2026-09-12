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
}
