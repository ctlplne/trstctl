// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

func TestResponderIssuanceFactsBindExactEventAndCustomerLifetime(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_responder_lifetime")
	log, projector, orch := billingHistory(t, cs)
	ctx := t.Context()
	c := billingMintedCertificate(t, "issued", "issue:transition:same-leaf")
	caID := uuid.NewString()
	c.CAID = caID
	data, err := json.Marshal(projections.CAIssuedCertificate{CAID: caID, Serial: c.Serial, CertificateDER: c.CertificateDER, Fingerprint: c.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	e, err := log.Append(ctx, events.Event{Type: projections.EventCAEndEntityIssued, SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion, TenantID: quotaTenant, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := projector.Apply(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	// Migration and other paths may record this same public leaf in inventory
	// after its CA serial event. Count the certificate only once, at its first event.
	if _, err := orch.RecordCertificate(ctx, quotaTenant, c); err != nil {
		t.Fatal(err)
	}
	n, known, err := pg.IssuedInPeriod(ctx, quotaTenant, e.Time.Add(-time.Second), time.Now().UTC().Add(time.Second))
	if err != nil || !known || n != 1 {
		t.Fatalf("two source families for one leaf: count=%d known=%t error=%v", n, known, err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := cs.WithTenant(ctx, quotaTenant, func(tx pgx.Tx) error {
		var eventID, eventType string
		if err := tx.QueryRow(ctx, `SELECT issuance_event_id,issuance_event_type FROM ca_issued_certs
			WHERE tenant_id=$1 AND ca_id=$2 AND serial=$3`, quotaTenant, caID, c.Serial).Scan(&eventID, &eventType); err != nil {
			return err
		}
		if eventID != e.ID || eventType != e.Type {
			t.Errorf("rebuild/re-observation changed first-issuance authority: %s %s", eventID, eventType)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n, known, err := pg.IssuedInPeriod(ctx, quotaTenant, e.Time.Add(-time.Second), time.Now().UTC().Add(time.Second)); err != nil || !known || n != 1 {
		t.Errorf("rebuild changed the verified mint count: count=%d known=%t error=%v", n, known, err)
	}
	changed := e
	changed.Data = append(append([]byte(nil), e.Data[:len(e.Data)-1]...), []byte(`,"source":"changed"}`)...)
	if err := projector.Apply(ctx, changed); !errors.Is(err, corestore.ErrIdempotencyConflict) {
		t.Errorf("changed completed envelope accepted: %v", err)
	}
	// A legacy registration event also represented a rename. An exact existing
	// receipt remains valid in that same lifetime; erasure below removes it.
	rename, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: quotaTenant, Data: []byte(`{"name":"renamed-customer"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, rename); err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, e); err != nil {
		t.Errorf("exact receipt refused after same-lifetime rename: %v", err)
	}
	proof, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, cs, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{TenantID: quotaTenant, RegistrationIdentity: proof.EventID}); err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, e); err == nil {
		t.Error("old issuance replay accepted after customer erasure")
	}
	_, err = orchestrator.ExecuteTenantRegistration(ctx, log, cs, projector, orchestrator.NewIdempotency(cs), orchestrator.TenantRegistrationCommand{
		TenantID: quotaTenant, Name: "replacement", IdempotencyKey: "replacement-responder-registration", RequestMaterial: []byte("replacement"),
		PayloadAt: func(time.Time) ([]byte, error) { return json.Marshal(map[string]string{"name": "replacement"}) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(ctx, e); err == nil {
		t.Error("old issuance replay accepted after customer UUID reuse")
	}
	n, known, err = pg.IssuedInPeriod(ctx, quotaTenant, e.Time.Add(-time.Second), time.Now().UTC().Add(time.Second))
	if err != nil || !known || n != 0 {
		t.Errorf("replacement customer inherited old issuance: count=%d known=%t error=%v", n, known, err)
	}
	if _, found, err := cs.LookupIssuedCert(ctx, quotaTenant, caID, c.Serial); err != nil || found {
		t.Errorf("erased CA serial reappeared: found=%t error=%v", found, err)
	}
}
