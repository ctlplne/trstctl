// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/usage"
)

func TestOlderWriterSerialCannotBecomeVerifiedPartialIssuance(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_older_writer")
	log, projector, orch := billingHistory(t, cs)
	hour := time.Now().UTC().Truncate(time.Hour)
	billingRecordAt(t, orch, quotaTenant, hour.Add(time.Minute))
	if err := pg.AddCounters(t.Context(), []billing.CounterDelta{{TenantID: quotaTenant, Meter: usage.MeterCertificatesIssued, Period: hour, Delta: 7}}); err != nil {
		t.Fatal(err)
	}
	caID := uuid.NewString()
	leaf := billingMintedCertificate(t, "issued", "older-writer")
	data, err := json.Marshal(map[string]string{"ca_id": caID, "serial": leaf.Serial, "subject": leaf.Subject})
	if err != nil {
		t.Fatal(err)
	}
	event, err := log.Append(t.Context(), events.Event{Type: projections.EventCAEndEntityIssued, TenantID: quotaTenant, SchemaVersion: 1, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	// This is the previous production projector's exact effect: a real serial
	// row, but no issuance receipt. It also occurs after a binary rollback when
	// the new database schema and its default-true tenant flag are retained.
	if err := cs.RecordIssuedCert(t.Context(), quotaTenant, caID, leaf.Serial, event.Time); err != nil {
		t.Fatal(err)
	}
	count, known, err := pg.IssuedInPeriod(t.Context(), quotaTenant, hour, hour.Add(time.Hour))
	if err != nil || count != 1 || known {
		t.Errorf("older writer: count=%d known=%t error=%v; want one retained fact with incomplete history", count, known, err)
	}
	if err := pg.RefreshIssuedCounters(t.Context()); !errors.Is(err, billing.ErrIssuanceHistoryUnknown) {
		t.Errorf("partial-history refresh error=%v, want refusal", err)
	}
	rows, err := pg.Query(t.Context(), hour, hour.Add(time.Hour), quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	var measured int64
	for _, row := range rows {
		if row.Meter == usage.MeterCertificatesIssued {
			measured += row.Value
		}
	}
	if measured != 7 {
		t.Errorf("partial history overwrote measured count with %d, want 7", measured)
	}
	// A later valid observation cannot retroactively prove when the old writer
	// first minted this serial. Keep the missing first-event binding intact.
	data, err = json.Marshal(projections.CAIssuedCertificate{CAID: caID, Serial: leaf.Serial, CertificateDER: leaf.CertificateDER, Fingerprint: leaf.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	later, err := log.Append(t.Context(), events.Event{Type: projections.EventCAEndEntityIssued, TenantID: quotaTenant, SchemaVersion: projections.CAIssuedCertificateEvidenceSchemaVersion, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Apply(t.Context(), later); err != nil {
		t.Fatal(err)
	}
	if _, known, err := pg.IssuedInPeriod(t.Context(), quotaTenant, hour, hour.Add(time.Hour)); err != nil || known {
		t.Errorf("later observation laundered the missing first-event binding: known=%t error=%v", known, err)
	}
	if count, known, err := pg.IssuedInPeriod(t.Context(), otherTenant, hour, hour.Add(time.Hour)); err != nil || !known || count != 0 {
		t.Errorf("neighbor history contaminated: count=%d known=%t error=%v", count, known, err)
	}
}
