// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestCACrossSignReceiptTenantReplayAndCollision(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	rec := store.CACrossSignReceipt{
		TenantID: tenantA, CeremonyID: "11111111-1111-4111-8111-111111111111",
		IssuerAuthorityID:    "22222222-2222-4222-8222-222222222222",
		TargetSHA256:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetCertificateDER: []byte{1, 2, 3}, CrossCertificateDER: []byte{4, 5, 6},
		CompletedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
	}
	apply := func(candidate store.CACrossSignReceipt) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.ApplyCACrossSignReceiptTx(ctx, tx, candidate)
		})
	}
	if err := apply(rec); err != nil {
		t.Fatal(err)
	}
	if err := apply(rec); err != nil {
		t.Fatalf("cold replay: %v", err)
	}
	saved, err := s.GetCACrossSignReceipt(ctx, tenantA, rec.CeremonyID)
	if err != nil || !bytes.Equal(saved.CrossCertificateDER, rec.CrossCertificateDER) {
		t.Fatalf("readback: %+v, %v", saved, err)
	}
	if _, err := s.GetCACrossSignReceipt(ctx, tenantB, rec.CeremonyID); !store.IsNotFound(err) {
		t.Fatalf("cross-tenant read = %v", err)
	}
	changed := rec
	changed.CrossCertificateDER = []byte{7, 8, 9}
	if err := apply(changed); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed event = %v", err)
	}
	saved, err = s.GetCACrossSignReceipt(ctx, tenantA, rec.CeremonyID)
	if err != nil || !bytes.Equal(saved.CrossCertificateDER, rec.CrossCertificateDER) {
		t.Fatalf("collision changed receipt: %+v, %v", saved, err)
	}
}
