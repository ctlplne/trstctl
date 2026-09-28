// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/usage"
)

// A real tenant registration establishes known empty issuance history.
// Real durable observations on either side of a gap cannot attest its absence
// of usage, even when both independently queried totals happen to be zero.
func TestSparseDurableObservationsDoNotAuthorizeAZeroUsageSignature(t *testing.T) {
	for _, kind := range []string{"counter", "gauge"} {
		t.Run(kind, func(t *testing.T) {
			store, connection := newBillingStoreOn(t, "billing_sparse_signature_"+kind)
			billingHistory(t, connection)
			ctx := t.Context()
			start := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
			period := billing.EvidencePeriod{CustomerID: quotaTenant, Start: start, End: start.Add(time.Hour)}
			for _, at := range []time.Time{start.Add(-time.Hour), period.End.Add(time.Hour)} {
				var err error
				if kind == "counter" {
					err = store.AddCounters(ctx, []billing.CounterDelta{{TenantID: quotaTenant, Meter: usage.MeterCertificatesIssued, Period: at, Delta: 1}})
				} else {
					err = store.SetGauge(ctx, quotaTenant, usage.MeterAgents, at, 0)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			records, err := store.Query(ctx, period.Start, period.End, quotaTenant)
			if err != nil || len(records) != 0 {
				t.Fatalf("the gap must contain no observations: rows=%d err=%v", len(records), err)
			}
			coverage, err := store.CoverageFor(ctx, quotaTenant)
			if err != nil {
				t.Fatal(err)
			}
			key, err := jose.GenerateRSASigningKey("sparse-usage-evidence")
			if err != nil {
				t.Fatal(err)
			}
			doc, err := billing.BuildSignedEvidence(ctx, period, coverage, records, store, &billing.AuditKeySigner{Key: key}, period.End.Add(24*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Reconciliation) != 1 || !doc.Reconciliation[0].Checked || !doc.Reconciliation[0].Matches || doc.Reconciliation[0].Metered != 0 || doc.Reconciliation[0].EventHistory != 0 {
				t.Fatalf("fixture must isolate coverage, with matching independent zero totals: %+v", doc.Reconciliation)
			}
			if doc.Signable || doc.Signature != nil || doc.Reason == "" {
				t.Fatalf("unobserved hour must refuse a signature despite matching zeros: signable=%t signature=%t reason=%q", doc.Signable, doc.Signature != nil, doc.Reason)
			}
		})
	}
}
