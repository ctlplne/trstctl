// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/usage"
)

type syncReader struct {
	durable map[string]bool
	asOf    time.Time
}

func (r syncReader) CoverageFor(_ context.Context, tenantID string) (billing.Coverage, error) {
	from := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	return billing.Coverage{Durable: r.durable[tenantID], ObservedFrom: from, ObservedTo: r.asOf,
		Intervals: []billing.ObservationInterval{{From: from, To: r.asOf}}}, nil
}

func (r syncReader) Query(_ context.Context, from, to time.Time, tenantID string) ([]billing.UsageRecord, error) {
	at := from.Add(time.Hour)
	row := func(meter, kind string, value int64) billing.UsageRecord {
		return billing.UsageRecord{TenantID: tenantID, Meter: meter, Kind: kind, PeriodStart: at, PeriodEnd: at.Add(time.Hour), Value: value}
	}
	return []billing.UsageRecord{
		row(usage.MeterCertificatesIssued, "counter", 5),
		row(usage.MeterCertificatesCurrent, "gauge", 7),
		row(usage.MeterAgents, "gauge", 2),
		row(usage.MeterSecretsStored, "gauge", 4),
	}, nil
}

type syncReconciler struct{}

func (syncReconciler) IssuedInPeriod(context.Context, string, time.Time, time.Time) (int64, bool, error) {
	return 5, true, nil
}

type syncQueuer struct {
	mu     sync.Mutex
	queued []string
	held   []string
	pushes []projections.BillingSyncPushEvent
}

func (q *syncQueuer) QueueBillingSyncPush(_ context.Context, tenantID string, push projections.BillingSyncPushEvent) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queued = append(q.queued, tenantID+"/"+push.PeriodStart.Format("2006-01"))
	q.pushes = append(q.pushes, push)
	return true, nil
}

func (q *syncQueuer) HoldBillingSyncPush(_ context.Context, tenantID string, push projections.BillingSyncPushEvent) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if push.Reason == "" {
		panic("a held period has no reason")
	}
	q.held = append(q.held, tenantID+"/"+push.PeriodStart.Format("2006-01"))
	return true, nil
}

// MSP-2 Done-when (sweep): for each customer mapped in a target, each of the
// last three closed periods of the target's cadence is signed and queued
// with its current certificates, agents and secrets and the evidence JWS, or
// held with its reason when the evidence cannot be signed; a period already
// queued is skipped on the next sweep; nothing runs before the orchestrator
// is bound.
func TestBillingSyncSweepQueuesSignablePeriodsAndHoldsTheRestMSP2(t *testing.T) {
	ctx := context.Background()
	_, cs := newBillingStoreOn(t, "billing_sync_sweep_msp2")
	const customerA, customerB = "1a2b3c4d-0000-4000-8000-00000000000a", "1a2b3c4d-0000-4000-8000-00000000000b"
	for tenant, company := range map[string]string{customerA: "COMPANY-A", customerB: "COMPANY-B"} {
		if _, err := cs.SystemPool().Exec(ctx, `INSERT INTO provider_billing_companies (tenant_id, target_id, external_company_id, mapped_by, mapped_at)
			VALUES ($1, 'psa', $2, 'op', now())`, tenant, company); err != nil {
			t.Fatal(err)
		}
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	asOf := time.Date(2026, time.November, 13, 12, 0, 0, 0, time.UTC)
	sweeper := &billing.SyncSweeper{
		Store: cs,
		Evidence: billing.EvidenceDeps{Reader: syncReader{durable: map[string]bool{customerA: true}, asOf: asOf},
			Reconciler: syncReconciler{}, Signer: &billing.AuditKeySigner{Key: key}},
		Targets: []config.ProviderBillingTarget{{ID: "psa", Type: "json", Cadence: "monthly"}},
		Now:     func() time.Time { return asOf },
	}
	if res, err := sweeper.Sweep(ctx); err != nil || res != (billing.SweepResult{}) {
		t.Fatalf("an unbound sweep did %+v (%v)", res, err)
	}
	q := &syncQueuer{}
	sweeper.Bind(q)
	res, err := sweeper.Sweep(ctx)
	if err != nil || res.Queued != 3 || res.Held != 3 {
		t.Fatalf("sweep = %+v (%v), want 3 queued and 3 held", res, err)
	}
	want := map[string]bool{customerA + "/2026-08": true, customerA + "/2026-09": true, customerA + "/2026-10": true}
	for _, got := range q.queued {
		if !want[got] {
			t.Fatalf("queued %v, want A's August to October", q.queued)
		}
	}
	for _, push := range q.pushes {
		if push.ExternalCompanyID != "COMPANY-A" || push.EvidenceJWS == "" || push.EvidenceDigest == "" || len(push.Lines) != 3 {
			t.Fatalf("queued push = %+v", push)
		}
		for _, line := range push.Lines {
			if line.Meter == usage.MeterCertificatesIssued {
				t.Fatalf("a push carries a meter outside current certificates, agents and secrets: %+v", line)
			}
		}
	}
	if len(q.held) != 3 {
		t.Fatalf("held %v, want B's three periods (its metering is not durable)", q.held)
	}

	// A's October is queued in the record: the next sweep skips it.
	if _, err := cs.SystemPool().Exec(ctx, `INSERT INTO provider_billing_sync_pushes
		(tenant_id, target_id, period_start, period_end, status, external_company_id, event_sequence, updated_at)
		VALUES ($1, 'psa', '2026-10-01T00:00:00Z', '2026-11-01T00:00:00Z', 'queued', 'COMPANY-A', 1, now())`, customerA); err != nil {
		t.Fatal(err)
	}
	q2 := &syncQueuer{}
	sweeper.Bind(q2)
	res, err = sweeper.Sweep(ctx)
	if err != nil || res.Skipped != 1 || res.Queued != 2 || res.Held != 3 {
		t.Fatalf("second sweep = %+v (%v), want October skipped", res, err)
	}
}

func TestClosedSyncPeriodsMSP2(t *testing.T) {
	asOf := time.Date(2026, time.March, 2, 1, 0, 0, 0, time.UTC)
	monthly := billing.ClosedSyncPeriods("monthly", asOf, 3)
	if len(monthly) != 3 || !monthly[0].Start.Equal(time.Date(2025, time.December, 1, 0, 0, 0, 0, time.UTC)) ||
		!monthly[2].End.Equal(time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("monthly = %+v", monthly)
	}
	daily := billing.ClosedSyncPeriods("daily", asOf, 2)
	if len(daily) != 2 || !daily[1].Start.Equal(time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)) ||
		!daily[1].End.Equal(time.Date(2026, time.March, 2, 0, 0, 0, 0, time.UTC)) || !daily[0].End.Equal(daily[1].Start) {
		t.Fatalf("daily = %+v", daily)
	}
}
