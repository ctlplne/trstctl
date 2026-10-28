// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// A215: recovered bytes fill only a row that holds none, record where they
// came from only then, never replace bytes a row already has, and stay in
// their tenant.
func TestRecoveredCertificateBytesFillOnlyAnEmptyRow(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	der, held := []byte("a215 recovered certificate"), []byte("a215 certificate already held")
	empty, full := crypto.SHA256Hex(der), crypto.SHA256Hex(held)
	for _, row := range []store.Certificate{
		{TenantID: tenantA, Subject: "CN=empty", Issuer: "CN=A215", Serial: "a1", Fingerprint: empty, Source: "discovery:network", Status: "active"},
		{TenantID: tenantA, Subject: "CN=full", Issuer: "CN=A215", Serial: "a2", Fingerprint: full, Source: "issued", Status: "active", CertificateDER: held},
	} {
		if _, err := s.UpsertCertificate(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	apply := func(tenant, fingerprint string, bytesIn []byte, seq uint64) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyCertificateDERRecoveredTx(ctx, tx, store.CertificateDERRecovery{
				TenantID: tenant, Fingerprint: fingerprint, Method: store.DERRecoveredFromEndpoint,
				Evidence: "10.0.0.5:443", RecoveredAt: time.Date(2026, 10, 28, 8, 0, 0, 0, time.UTC), EventSequence: seq,
			}, bytesIn, []byte("pem"))
		}); err != nil {
			t.Fatal(err)
		}
	}
	apply(tenantA, empty, der, 2150)
	if got, err := s.GetCertificateByFingerprint(ctx, tenantA, empty); err != nil || !bytes.Equal(got.CertificateDER, der) {
		t.Fatalf("empty row after recovery holds %q (%v)", got.CertificateDER, err)
	}
	if rec, found, err := s.CertificateDERRecoveryFor(ctx, tenantA, empty); err != nil || !found ||
		rec.Method != store.DERRecoveredFromEndpoint || rec.Evidence != "10.0.0.5:443" {
		t.Fatalf("recovery record = %+v found=%v (%v)", rec, found, err)
	}
	apply(tenantA, full, []byte("other bytes"), 2151)
	if got, err := s.GetCertificateByFingerprint(ctx, tenantA, full); err != nil || !bytes.Equal(got.CertificateDER, held) {
		t.Fatalf("a row with bytes was overwritten: %q (%v)", got.CertificateDER, err)
	}
	if _, found, err := s.CertificateDERRecoveryFor(ctx, tenantA, full); err != nil || found {
		t.Fatalf("a recovery that changed nothing was recorded (found=%v, %v)", found, err)
	}
	if _, found, err := s.CertificateDERRecoveryFor(ctx, tenantB, empty); err != nil || found {
		t.Fatalf("tenant B read tenant A's recovery (found=%v, %v)", found, err)
	}
}
