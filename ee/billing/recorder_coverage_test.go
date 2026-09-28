// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

func TestQuietRecorderFlushesProveAClosedZeroUsagePeriod(t *testing.T) {
	store, connection := newBillingStoreOn(t, "billing_quiet_recorder_coverage")
	billingHistory(t, connection)
	ctx := t.Context()
	start := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
	now := start.Add(-time.Minute)
	recorder := billing.NewRecorder(store, nil).WithClock(func() time.Time { return now })
	// Start observing before the requested window. The one issuance belongs to
	// the preceding hour; the requested hour really has no issuance events.
	recorder.Record(quotaTenant, usage.MeterCertificatesIssued, 1)
	if err := recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{start, start.Add(30 * time.Minute), start.Add(time.Hour)} {
		now = at
		if err := recorder.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	period := billing.EvidencePeriod{CustomerID: quotaTenant, Start: start, End: now}
	coverage, err := store.CoverageFor(ctx, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateRSASigningKey("quiet-usage-proof")
	if err != nil {
		t.Fatal(err)
	}
	records, err := store.Query(ctx, period.Start, period.End, quotaTenant)
	if err != nil || len(records) != 0 {
		t.Fatalf("zero-use window rows=%d err=%v", len(records), err)
	}
	doc, err := billing.BuildSignedEvidence(ctx, period, coverage, records, store, &billing.AuditKeySigner{Key: key}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Signable || doc.Signature == nil {
		t.Fatalf("continuously observed quiet period must be signable: %s", doc.Reason)
	}
	payload, err := key.JWKS().VerifyArtifact(doc.Signature.JWS, jose.ArtifactBillingInvoice)
	if err != nil || crypto.SHA256Hex(payload) != doc.Digest {
		t.Fatalf("positive evidence signature must verify the document digest: %v", err)
	}
	other, err := store.CoverageFor(ctx, otherTenant)
	if err != nil {
		t.Fatal(err)
	}
	period.CustomerID = otherTenant
	if billing.MaySign(period, other, now).Signable {
		t.Fatal("another tenant inherited the observed customer's coverage")
	}
}

func TestQuietRecorderCannotResurrectAnErasedCustomer(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		name := "missing"
		if recreate {
			name = "reused_uuid"
		}
		t.Run(name, func(t *testing.T) {
			store, connection := newBillingStoreOn(t, "billing_erased_observer_"+name)
			ctx := t.Context()
			start := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
			if err := connection.UpsertTenant(ctx, corestore.Tenant{TenantID: quotaTenant, Name: "original", CreatedAt: start, EventSeq: 1}); err != nil {
				t.Fatal(err)
			}
			now := start
			recorder := billing.NewRecorder(store, nil).WithClock(func() time.Time { return now })
			recorder.Record(quotaTenant, usage.MeterCertificatesIssued, 1)
			now = start.Add(15 * time.Minute)
			if err := recorder.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			// A late flush has both a retained observer and an old pending delta.
			recorder.Record(quotaTenant, usage.MeterCertificatesIssued, 2)
			if _, err := connection.OffboardTenant(ctx, quotaTenant); err != nil {
				t.Fatal(err)
			}
			if recreate {
				if err := connection.UpsertTenant(ctx, corestore.Tenant{TenantID: quotaTenant, Name: "replacement", CreatedAt: start.Add(30 * time.Minute), EventSeq: 2}); err != nil {
					t.Fatal(err)
				}
			}
			now = start.Add(2 * time.Hour)
			_ = recorder.Flush(ctx) // A stale registration may be refused explicitly.
			rows, err := store.Query(ctx, start, now, quotaTenant)
			if err != nil || len(rows) != 0 {
				t.Fatalf("late flush resurrected erased usage: rows=%+v err=%v", rows, err)
			}
			coverage, err := store.CoverageFor(ctx, quotaTenant)
			if err != nil || !coverage.ObservedFrom.IsZero() || !coverage.ObservedTo.IsZero() {
				t.Fatalf("late flush resurrected erased observation: coverage=%+v err=%v", coverage, err)
			}
			if recreate {
				recorder.Record(quotaTenant, usage.MeterCertificatesIssued, 3)
				now = now.Add(15 * time.Minute)
				if err := recorder.Flush(ctx); err != nil {
					t.Fatal(err)
				}
				rows, err := store.Query(ctx, start, now, quotaTenant)
				if err != nil || len(rows) != 1 || rows[0].Value != 3 {
					t.Fatalf("replacement's own usage must survive without old deltas: rows=%+v err=%v", rows, err)
				}
			}
		})
	}
}

func TestRecorderRestartDoesNotBridgeUnflushedUsage(t *testing.T) {
	store, connection := newBillingStoreOn(t, "billing_recorder_restart_gap")
	billingHistory(t, connection)
	ctx := t.Context()
	start := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
	now := start.Add(-time.Minute)
	before := billing.NewRecorder(store, nil).WithClock(func() time.Time { return now })
	before.Record(quotaTenant, usage.MeterCertificatesIssued, 1)
	now = start.Add(15 * time.Minute)
	if err := before.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// An abrupt process loss drops this unflushed increment. Reopening the
	// same durable store must not turn the lost interval into observed zero.
	now = start.Add(20 * time.Minute)
	before.Record(quotaTenant, usage.MeterCertificatesIssued, 1)
	now = start.Add(45 * time.Minute)
	after := billing.NewRecorder(store, nil).WithClock(func() time.Time { return now })
	after.Record(quotaTenant, usage.MeterCertificatesIssued, 1)
	now = start.Add(2 * time.Hour)
	after.Record(quotaTenant, usage.MeterCertificatesIssued, 1)
	if err := after.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	coverage, err := store.CoverageFor(ctx, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	period := billing.EvidencePeriod{CustomerID: quotaTenant, Start: start, End: start.Add(time.Hour)}
	if got := billing.MaySign(period, coverage, now); got.Signable || got.Reason == "" {
		t.Fatalf("restart gap must remain unsignable: %+v", got)
	}
}
