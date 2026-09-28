// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

func TestCollectorInterruptionLeavesGapAndLaterQuietHourRecovers(t *testing.T) {
	for _, mode := range []string{"restart", "registry_failure", "missed_ticks", "reused_uuid"} {
		t.Run(mode, func(t *testing.T) {
			pg, cs := newBillingStoreOn(t, "billing_collector_"+mode)
			seedBillingRegistration(t, cs, quotaTenant)
			start := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
			now := start
			unavailable := false
			newCollector := func() *billing.Collector {
				return billing.NewCollector(pg, func(context.Context) ([]string, error) {
					if unavailable {
						return nil, errors.New("controlled registry read failure")
					}
					return []string{quotaTenant}, nil
				}, billing.StoreTenantCounter(cs), nil).WithClock(func() time.Time { return now })
			}
			collector := newCollector()
			snapshot := func(at time.Time) {
				t.Helper()
				now = at
				if err := collector.Snapshot(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			snapshot(start)
			snapshot(start.Add(15 * time.Minute))
			switch mode {
			case "restart":
				collector = newCollector()
			case "registry_failure":
				unavailable = true
				now = start.Add(30 * time.Minute)
				if err := collector.Snapshot(t.Context()); err == nil {
					t.Fatal("registry failure was hidden")
				}
				unavailable = false
			case "reused_uuid":
				if _, err := cs.OffboardTenant(t.Context(), quotaTenant); err != nil {
					t.Fatal(err)
				}
				if err := cs.UpsertTenant(t.Context(), corestore.Tenant{TenantID: quotaTenant, Name: "replacement", EventSeq: 2, CreatedAt: start.Add(30 * time.Minute)}); err != nil {
					t.Fatal(err)
				}
			}
			// A missed sweep exceeds the collector's maximum heartbeat gap.
			resume := start.Add(45 * time.Minute)
			if mode == "missed_ticks" {
				resume = start.Add(46 * time.Minute)
			}
			snapshot(resume)
			for i := 4; i <= 8; i++ {
				snapshot(start.Add(time.Duration(i) * 15 * time.Minute))
			}
			coverage, err := pg.CoverageFor(t.Context(), quotaTenant)
			if err != nil {
				t.Fatal(err)
			}
			period := billing.EvidencePeriod{CustomerID: quotaTenant, Start: start, End: start.Add(time.Hour)}
			if billing.MaySign(period, coverage, now).Signable {
				t.Fatalf("%s was bridged as continuous observation: %+v", mode, coverage)
			}
			period.Start, period.End = start.Add(time.Hour), now
			if verdict := billing.MaySign(period, coverage, now); !verdict.Signable {
				t.Fatalf("later fully observed hour did not recover: %+v", verdict)
			}
		})
	}
}

func TestCollectorFailureRollsBackGaugesAndDoesNotClaimTheMissedInterval(t *testing.T) {
	const database = "billing_collector_atomic"
	pg, cs := newBillingStoreOn(t, database)
	_, _, orch := billingHistory(t, cs)
	start := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	now := start
	collector := billing.NewCollector(pg, func(context.Context) ([]string, error) {
		return []string{quotaTenant, otherTenant}, nil
	}, billing.StoreTenantCounter(cs), nil).WithClock(func() time.Time { return now })
	if err := collector.Snapshot(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RecordCertificate(t.Context(), quotaTenant, billingMintedCertificate(t, "imported", "")); err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(t.Context(), strings.TrimSuffix(billingTestDSN, "/postgres")+"/"+database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	_, err = admin.Exec(t.Context(), `
		CREATE SEQUENCE billing_test_snapshot_attempt;
		GRANT USAGE ON SEQUENCE billing_test_snapshot_attempt TO trstctl_app;
		CREATE FUNCTION billing_test_snapshot_failure() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.tenant_id='33333333-3333-3333-3333-333333333333' AND nextval('billing_test_snapshot_attempt')=1 THEN
				RAISE EXCEPTION 'controlled resource coverage write failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER billing_test_snapshot_failure BEFORE INSERT ON provider_usage_coverage
		FOR EACH ROW EXECUTE FUNCTION billing_test_snapshot_failure();`)
	if err != nil {
		t.Fatal(err)
	}
	now = start.Add(15 * time.Minute)
	if err := collector.Snapshot(t.Context()); err == nil || !strings.Contains(err.Error(), "controlled resource coverage write failure") {
		t.Fatalf("expected coverage persistence failure: %v", err)
	}
	rows, err := pg.Query(t.Context(), start, start.Add(time.Hour), quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.Meter == usage.MeterCertificatesStored {
			found = true
			if row.Value != 0 {
				t.Fatalf("gauge escaped rolled-back observation transaction: %+v", row)
			}
		}
	}
	if !found {
		t.Fatal("previous successful zero gauge disappeared")
	}
	neighbor, err := pg.CoverageFor(t.Context(), otherTenant)
	if err != nil || len(neighbor.Intervals) != 1 {
		t.Fatalf("one customer's failure starved its healthy neighbor: %+v, %v", neighbor, err)
	}
	for i := 2; i <= 4; i++ {
		now = start.Add(time.Duration(i) * 15 * time.Minute)
		if err := collector.Snapshot(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	coverage, err := pg.CoverageFor(t.Context(), quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	if billing.MaySign(billing.EvidencePeriod{CustomerID: quotaTenant, Start: start, End: now}, coverage, now).Signable {
		t.Fatal("retry filled a failed resource observation interval")
	}
	rows, err = pg.Query(t.Context(), start, now, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Meter == usage.MeterCertificatesStored && row.Value != 1 {
			t.Fatalf("successful retry did not publish current resource count: %+v", row)
		}
	}
}
