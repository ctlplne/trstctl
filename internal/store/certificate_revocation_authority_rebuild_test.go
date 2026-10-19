// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

func TestCompletedCertificateRevocationAuthorityRebuildsFromEventWithoutClaim(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const caID = "22222222-2222-4222-8222-222222222222"
	const certID = "33333333-3333-4333-8333-333333333333"
	digest := crypto.SHA256Hex([]byte("public certificate"))
	binding := crypto.SHA256Hex([]byte("exact revocation request"))
	data, err := json.Marshal(map[string]any{"request_binding": binding, "reason": "cessationOfOperation",
		"items": []map[string]any{{"id": certID, "matched": true, "status": "revoked",
			"ca_id": caID, "serial": "7a", "fingerprint": digest}}})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: "event-only-revocation", TenantID: tenantA,
		Type: "certificate.revocation.batch.applied", SchemaVersion: 1,
		Time: time.Date(2026, 10, 19, 18, 0, 0, 0, time.UTC), Sequence: 17, Data: data}
	for replay := 0; replay < 2; replay++ {
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.CompleteCertificateRevocationAuthorityTx(ctx, tx, event)
		}); err != nil {
			t.Fatalf("event-only replay %d: %v", replay, err)
		}
	}
	drifted := event
	drifted.SchemaVersion = 2
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.CompleteCertificateRevocationAuthorityTx(ctx, tx, drifted)
	}); err == nil {
		t.Fatal("completed revocation command accepted an event schema change")
	}
	receipt, err := s.CompletedCertificateRevocationForSerial(ctx, tenantA, caID, "7a")
	if err != nil || receipt.EventID != event.ID || receipt.Sequence != event.Sequence || receipt.Fingerprint != digest {
		t.Fatalf("event-only revocation authority absent: %+v %v", receipt, err)
	}
	if _, err := s.CompletedCertificateRevocationForSerial(ctx, tenantB, caID, "7a"); err == nil {
		t.Fatal("neighbor tenant read restored revocation authority")
	}
	// A different immutable outcome cannot take the same issuer/serial.
	other := event
	other.ID, other.Sequence = "competing-event-only-revocation", 18
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.CompleteCertificateRevocationAuthorityTx(ctx, tx, other)
	}); err == nil {
		t.Fatal("event-only rebuild accepted a competing issuer/serial decision")
	}
	command, err := s.CertificateRevocationAuthorityCommandByEventID(ctx, tenantA, event.ID)
	if err != nil || command.Status != "completed" || command.Event.Sequence != event.Sequence ||
		command.RequestBinding != binding {
		t.Fatalf("event-only command recovery: %+v %v", command, err)
	}
}
