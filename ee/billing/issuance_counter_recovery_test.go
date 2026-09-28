// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/usage"
)

func TestDurableIssuanceCountersRecoverWithoutProcessDeltas(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_counter_recovery")
	_, _, orch := billingHistory(t, cs)
	hour := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	billingRecordAt(t, orch, quotaTenant, hour.Add(time.Minute))
	billingRecordAt(t, orch, quotaTenant, hour.Add(2*time.Minute), "protocol:acme")
	billingRecordAt(t, orch, quotaTenant, hour.Add(time.Hour+time.Minute), "external-ca:owned-authority")
	billingRecordAt(t, orch, otherTenant, hour.Add(time.Minute))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	inst := billing.InstallDurable(ctx, nil, nil, cs)
	t.Cleanup(func() { cancel(); <-inst.Stopped })
	// Only some serving paths used to record a process delta, at response time.
	// It must neither replace durable source facts nor add them a second time.
	inst.Recorder.Record(quotaTenant, usage.MeterCertificatesIssued, 2)
	if err := inst.Recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	check := func(tenant string, start time.Time, want int64) {
		t.Helper()
		rows, err := pg.Query(ctx, start, start.Add(time.Hour), tenant)
		if err != nil {
			t.Fatal(err)
		}
		var got int64
		for _, row := range rows {
			if row.TenantID != tenant {
				t.Fatalf("counter read crossed customer boundary: %s", row.TenantID)
			}
			if row.Meter == usage.MeterCertificatesIssued {
				got += row.Value
			}
		}
		if got != want {
			t.Errorf("customer %s hour %s: issued=%d, want %d durable mints", tenant, start, got, want)
		}
	}
	check(quotaTenant, hour, 2)
	check(quotaTenant, hour.Add(time.Hour), 1)
	check(otherTenant, hour, 1)
	check(quotaTenant, time.Now().UTC().Truncate(time.Hour), 0)
	coverage, err := pg.CoverageFor(ctx, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	if !coverage.ObservedFrom.IsZero() || !coverage.ObservedTo.IsZero() {
		t.Error("recovering past mint facts invented continuous observation coverage")
	}

	// A new durable recorder has no old in-memory buffer. Even a retry after a
	// canceled database attempt must recover the additional source event once.
	billingRecordAt(t, orch, quotaTenant, hour.Add(3*time.Minute), "ephemeral:kubernetes")
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := inst.Recorder.Flush(canceled); err == nil {
		t.Error("canceled source synchronization was reported successful")
	}
	restarted := billing.InstallDurable(ctx, nil, nil, cs)
	t.Cleanup(func() { cancel(); <-restarted.Stopped })
	for range 2 {
		if err := restarted.Recorder.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	check(quotaTenant, hour, 3)
	check(quotaTenant, hour.Add(time.Hour), 1)
	check(otherTenant, hour, 1)
}
