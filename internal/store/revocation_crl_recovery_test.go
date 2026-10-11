// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestCRLDueForRegenerationRepairsRevocationAfterPublicationCrash(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const caID = "49200000-0000-4000-8000-000000000001"
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if err := s.RecordIssuedCert(ctx, tenantA, caID, "1234", at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCRL(ctx, store.CRL{TenantID: tenantA, CAID: caID, Number: 1,
		DER: []byte{1}, ThisUpdate: at, NextUpdate: at.Add(7 * 24 * time.Hour), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		got, err := s.CRLDueForRegeneration(ctx, tenantA, caID, at.Add(time.Hour), 24*time.Hour)
		if err != nil || got != want {
			t.Fatalf("CRL due=%v error=%v, want %v", got, err, want)
		}
	}
	check(false)
	if err := s.RevokeIssuedCert(ctx, tenantA, caID, "1234", 1, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	check(true)
	// A publication followed by a cold restart leaves no overdue work.
	if err := s.InsertCRL(ctx, store.CRL{TenantID: tenantA, CAID: caID, Number: 2,
		DER: []byte{2}, ThisUpdate: at.Add(2 * time.Minute), NextUpdate: at.Add(7 * 24 * time.Hour), CreatedAt: at.Add(2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	check(false)
	// The same CA ID in another tenant must not inherit this tenant's revocation.
	if err := s.RecordIssuedCert(ctx, tenantB, caID, "5678", at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCRL(ctx, store.CRL{TenantID: tenantB, CAID: caID, Number: 1,
		DER: []byte{3}, ThisUpdate: at, NextUpdate: at.Add(7 * 24 * time.Hour), CreatedAt: at}); err != nil {
		t.Fatal(err)
	}
	otherDue, err := s.CRLDueForRegeneration(ctx, tenantB, caID, at.Add(time.Hour), 24*time.Hour)
	if err != nil || otherDue {
		t.Fatalf("other tenant CRL due=%v error=%v", otherDue, err)
	}
}
