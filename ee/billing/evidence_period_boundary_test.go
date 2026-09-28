// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/usage"
)

// A gauge sampled after the requested end is stored at its
// hour's start. A matching zero issuance recount cannot attest that later level
// as the requested partial-hour period's level. Auth is outside this unit: the
// shared handler is called with the exact already-authorized customer.
func TestPartialHourEvidenceDoesNotSignAGaugeFromAfterItsEnd(t *testing.T) {
	store, connection := newBillingStoreOn(t, "billing_partial_hour_signature")
	billingHistory(t, connection)
	ctx := t.Context()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	// Populate all four hour buckets, not merely two sparse bookends. This does
	// not claim that point snapshots prove uninterrupted coverage (F179).
	for hour := 0; hour < 4; hour++ {
		value := int64(1)
		if hour >= 2 {
			value = 7
		}
		observedAt := base.Add(time.Duration(hour)*time.Hour + 50*time.Minute)
		if err := store.SetGauge(ctx, quotaTenant, usage.MeterAgents, billing.PeriodStart(observedAt), value); err != nil {
			t.Fatal(err)
		}
	}
	key, err := jose.GenerateRSASigningKey("partial-hour-usage-evidence")
	if err != nil {
		t.Fatal(err)
	}
	start, end := base.Add(90*time.Minute), base.Add(150*time.Minute)
	query := url.Values{"period_start": {start.Format(time.RFC3339)}, "period_end": {end.Format(time.RFC3339)}}
	req := httptest.NewRequest(http.MethodGet, "/usage/evidence?"+query.Encode(), nil)
	rec := httptest.NewRecorder()
	billing.ServeEvidenceForCustomer(rec, req, billing.EvidenceDeps{Reader: store, Reconciler: store, Signer: &billing.AuditKeySigner{Key: key}}, quotaTenant)
	// A boundary refusal or an explicit unsigned document is acceptable; silently
	// rounding the requested period or signing bucket2's2:50 observation is not.
	if rec.Code == http.StatusBadRequest {
		return
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected explicit period handling, status=%d body=%s", rec.Code, rec.Body.String())
	}
	var doc billing.EvidenceDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.PeriodStart != start.Format(time.RFC3339) || doc.PeriodEnd != end.Format(time.RFC3339) {
		t.Fatalf("requested period silently changed: %+v", doc)
	}
	if doc.Signable || doc.Signature != nil || doc.Reason == "" {
		t.Fatalf("partial-hour evidence must not attest a later gauge: signable=%t signed=%t lines=%+v reason=%q", doc.Signable, doc.Signature != nil, doc.Lines, doc.Reason)
	}
}
