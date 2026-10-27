// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A178: the validity-readiness report reads the tenant's active, unexpired,
// non-ephemeral certificates in expiry order, and the scheduler inventory
// carries which receipt selected each served certificate.
func TestValidityReadinessCertificatesAreTheTenantsLiveOnes(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	seed := func(tenant, serial, status, key string, notAfter time.Time) string {
		t.Helper()
		notBefore := now.Add(-time.Hour)
		cert, err := s.UpsertCertificate(ctx, store.Certificate{
			TenantID: tenant, Subject: "CN=" + serial + ".example.test", SANs: []string{serial + ".example.test"},
			Issuer: "CN=issuer", Serial: serial, Fingerprint: strings.Repeat(serial[:1], 64),
			Source: "import", IssuanceIdempotencyKey: key, Status: status, NotBefore: &notBefore, NotAfter: &notAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
		return cert.ID
	}
	later := seed(tenantA, "a-later", "active", "", now.Add(90*24*time.Hour))
	sooner := seed(tenantA, "b-sooner", "active", "", now.Add(10*24*time.Hour))
	seed(tenantA, "c-expired", "active", "", now.Add(-time.Minute))
	revoked := seed(tenantA, "d-revoked", "active", "", now.Add(30*24*time.Hour))
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET status = 'revoked', revoked_at = $3 WHERE tenant_id = $1 AND id = $2`, tenantA, revoked, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	seed(tenantA, "e-ephemeral", "active", "ephemeral-issue:fixture", now.Add(time.Hour))
	seed(tenantB, "f-other-tenant", "active", "", now.Add(5*24*time.Hour))

	certs, truncated, err := s.ListValidityReadinessCertificates(ctx, tenantA, now)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, cert := range certs {
		ids = append(ids, cert.ID)
	}
	if truncated || len(ids) != 2 || ids[0] != sooner || ids[1] != later {
		t.Fatalf("live certificates = %v (truncated %v), want [%s %s]", ids, truncated, sooner, later)
	}
	if len(certs[0].SANs) != 1 || certs[0].NotBefore == nil {
		t.Fatalf("certificate columns not scanned: %+v", certs[0])
	}
}
