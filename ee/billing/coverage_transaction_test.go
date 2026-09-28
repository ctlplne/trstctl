// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/usage"
)

func TestObservationFailureRollsBackCountersAndRetryRetainsExactUsage(t *testing.T) {
	const database = "billing_coverage_atomicity"
	store, connection := newBillingStoreOn(t, database)
	seedBillingRegistration(t, connection, quotaTenant)
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, strings.TrimSuffix(billingTestDSN, "/postgres")+"/"+database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	_, err = admin.Exec(ctx, `
		CREATE SEQUENCE billing_test_coverage_attempt;
		GRANT USAGE ON SEQUENCE billing_test_coverage_attempt TO trstctl_app;
		CREATE FUNCTION billing_test_fail_first_coverage() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF nextval('billing_test_coverage_attempt') = 1 THEN
				RAISE EXCEPTION 'QA controlled observation write failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER billing_test_coverage_failure BEFORE INSERT ON provider_usage_coverage
		FOR EACH ROW EXECUTE FUNCTION billing_test_fail_first_coverage();`)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
	now := start
	recorder := billing.NewRecorder(store, nil).WithClock(func() time.Time { return now })
	recorder.Record(quotaTenant, usage.MeterCertificatesIssued, 2)
	now = start.Add(time.Hour)
	if err := recorder.Flush(ctx); err == nil || !strings.Contains(err.Error(), "QA controlled observation write failure") {
		t.Fatalf("expected controlled failure after counter write: %v", err)
	}
	rows, err := store.Query(ctx, start, now, quotaTenant)
	if err != nil || len(rows) != 0 {
		t.Fatalf("counter escaped failed observation transaction: rows=%+v err=%v", rows, err)
	}
	coverage, err := store.CoverageFor(ctx, quotaTenant)
	period := billing.EvidencePeriod{CustomerID: quotaTenant, Start: start, End: now}
	if err != nil || billing.MaySign(period, coverage, now).Signable {
		t.Fatalf("failed transaction claimed coverage: coverage=%+v err=%v", coverage, err)
	}
	if err := recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = store.Query(ctx, start, now, quotaTenant)
	if err != nil || len(rows) != 1 || rows[0].Value != 2 {
		t.Fatalf("retry lost or duplicated usage: rows=%+v err=%v", rows, err)
	}
	coverage, err = store.CoverageFor(ctx, quotaTenant)
	if err != nil || !billing.MaySign(period, coverage, now).Signable {
		t.Fatalf("successful atomic retry did not record coverage: coverage=%+v err=%v", coverage, err)
	}
}
