// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/store"
)

// B11-8 fix: projecting a keyCompromise revocation records the certificate's
// SPKI SHA-256; another reason records nothing; the lookup stays inside the
// tenant; the startup backfill records revocations an older build projected;
// and a snapshot restore keeps every recorded key, so a restore can never
// make a compromised key certifiable again.
func TestCompromisedSubjectKeysRecordBackfillAndSurviveSnapshotRestore(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	seedTwoTenants(t, s)
	ders, err := certtest.DistinctLeaves(3, "compromised-keys")
	if err != nil {
		t.Fatal(err)
	}
	infos := make([]certinfo.Info, len(ders))
	for i, der := range ders {
		if infos[i], err = certinfo.Inspect(der); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpsertCertificate(ctx, store.Certificate{TenantID: tenantA, Subject: infos[i].Subject,
			Fingerprint: infos[i].SHA256Fingerprint, CertificateDER: der, Source: "import"}); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Date(2026, 10, 24, 3, 0, 0, 0, time.UTC)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.SetCertificateRevokedTx(ctx, tx, tenantA, infos[0].SHA256Fingerprint, "superseded", at); err != nil {
			return err
		}
		return s.SetCertificateRevokedTx(ctx, tx, tenantA, infos[1].SHA256Fingerprint, "keyCompromise", at)
	}); err != nil {
		t.Fatal(err)
	}
	lookup := func(tenantID string, i int) (string, bool) {
		t.Helper()
		fingerprint, found, err := s.CompromisedSubjectKey(ctx, tenantID, infos[i].SPKISHA256)
		if err != nil {
			t.Fatal(err)
		}
		return fingerprint, found
	}
	if fingerprint, found := lookup(tenantA, 1); !found || fingerprint != infos[1].SHA256Fingerprint {
		t.Fatalf("keyCompromise revocation recorded %q found=%v", fingerprint, found)
	}
	if _, found := lookup(tenantA, 0); found {
		t.Fatal("a superseded revocation recorded its key as compromised")
	}
	if _, found := lookup(tenantB, 1); found {
		t.Fatal("another tenant saw tenant A's compromised key")
	}

	// An older build left a keyCompromise revocation with no recorded key.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET status = 'revoked', revocation_reason = 'keyCompromise', revoked_at = $3
			WHERE tenant_id = $1 AND fingerprint = $2`, tenantA, infos[2].SHA256Fingerprint, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, found := lookup(tenantA, 2); found {
		t.Fatal("an unprojected revocation was recorded before the backfill")
	}
	if recorded, unreadable, err := s.BackfillCompromisedSubjectKeys(ctx); err != nil || recorded != 1 || unreadable != 0 {
		t.Fatalf("backfill recorded=%d unreadable=%d err=%v; want the one older revocation", recorded, unreadable, err)
	}
	if _, found := lookup(tenantA, 2); !found {
		t.Fatal("the backfill did not record the older revocation's key")
	}

	if count, err := s.WriteReadModelSnapshots(ctx); err != nil || count != 2 {
		t.Fatalf("capture compromised keys = %d, %v", count, err)
	}
	if err := s.RestoreReadModelTx(ctx, func(tx pgx.Tx) error {
		_, err := s.RestoreSnapshotsTx(ctx, tx)
		return err
	}); err != nil {
		t.Fatalf("restore compromised keys snapshot: %v", err)
	}
	for _, i := range []int{1, 2} {
		if _, found := lookup(tenantA, i); !found {
			t.Fatalf("snapshot restore lost compromised key %d", i)
		}
	}
}
