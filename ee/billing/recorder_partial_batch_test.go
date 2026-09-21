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

// A real PostgreSQL fault on the second tenant transaction makes this probe
// independent of Go map order. The first tenant has already committed; retrying
// the batch must neither lose the second tenant nor count the first one twice.
func TestRecorderRetriesPartialTenantCommitWithoutDuplicatingUsage(t *testing.T) {
	const database = "billing_partial_tenant_retry"
	store, _ := newBillingStoreOn(t, database)
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, strings.TrimSuffix(billingTestDSN, "/postgres")+"/"+database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	// The sequence is deliberate fault injection, not a substitute for the
	// production store or tenant transactions. nextval survives rollback, so
	// only the second attempted insert fails, and the subsequent retry can run.
	_, err = admin.Exec(ctx, `
		CREATE SEQUENCE billing_test_counter_attempt;
		GRANT USAGE ON SEQUENCE billing_test_counter_attempt TO trstctl_app;
		CREATE FUNCTION billing_test_fail_second_counter() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF nextval('billing_test_counter_attempt') = 2 THEN
				RAISE EXCEPTION 'QA controlled second tenant counter failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER billing_test_counter_failure
		BEFORE INSERT ON provider_usage_meters
		FOR EACH ROW EXECUTE FUNCTION billing_test_fail_second_counter();`)
	if err != nil {
		t.Fatal(err)
	}
	period := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	recorder := billing.NewRecorder(store, nil).WithClock(func() time.Time { return period })
	recorder.Record(quotaTenant, usage.MeterCertificatesIssued, 2)
	recorder.Record(otherTenant, usage.MeterCertificatesIssued, 3)
	if err := recorder.Flush(ctx); err == nil || !strings.Contains(err.Error(), "QA controlled second tenant counter failure") {
		t.Fatalf("first flush must encounter the controlled second-tenant failure: %v", err)
	}
	read := func(tenant string) int64 {
		t.Helper()
		rows, err := store.Query(ctx, period, period.Add(time.Hour), tenant)
		if err != nil {
			t.Fatal(err)
		}
		var count int64
		for _, row := range rows {
			if row.TenantID != tenant {
				t.Fatalf("counter query crossed tenant boundary: %s", row.TenantID)
			}
			if row.Meter == usage.MeterCertificatesIssued {
				count += row.Value
			}
		}
		return count
	}
	first, second := read(quotaTenant), read(otherTenant)
	t.Logf("after partial failure: tenant A=%d, tenant B=%d", first, second)
	// A future all-or-nothing store is also valid. A partial commit may only
	// retain an exact original tenant total; neither tenant may be duplicated.
	if (first != 0 && first != 2) || (second != 0 && second != 3) || (first == 2 && second == 3) {
		t.Fatalf("unexpected failed-flush state A=%d B=%d", first, second)
	}
	if err := recorder.Flush(ctx); err != nil {
		t.Fatalf("retry after the one-shot database fault: %v", err)
	}
	if got := read(quotaTenant); got != 2 {
		t.Errorf("tenant A after retry=%d, want exactly 2", got)
	}
	if got := read(otherTenant); got != 3 {
		t.Errorf("tenant B after retry=%d, want exactly 3", got)
	}
	if err := recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := read(quotaTenant) + read(otherTenant); got != 5 {
		t.Errorf("empty follow-up flush changed total: got %d, want 5", got)
	}
}
