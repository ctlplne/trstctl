// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

func assertIssuedHour(t *testing.T, pg *billing.PGStore, tenant string, hour time.Time, want int64) {
	t.Helper()
	rows, err := pg.Query(t.Context(), hour, hour.Add(time.Hour), tenant)
	if err != nil {
		t.Fatal(err)
	}
	var got int64
	for _, row := range rows {
		if row.TenantID != tenant {
			t.Fatalf("usage query crossed customer boundary: %s", row.TenantID)
		}
		if row.Meter == usage.MeterCertificatesIssued {
			got += row.Value
		}
	}
	if got != want {
		t.Fatalf("customer %s hour %s: issued=%d, want %d", tenant, hour, got, want)
	}
}

func TestDurableIssuanceCountersRollbackAndRetryAcrossReplicas(t *testing.T) {
	const database = "billing_issuance_retry"
	pg, cs := newBillingStoreOn(t, database)
	_, _, orch := billingHistory(t, cs)
	ctx := t.Context()
	hour := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	billingRecordAt(t, orch, quotaTenant, hour.Add(time.Minute))
	billingRecordAt(t, orch, otherTenant, hour.Add(time.Minute))
	if err := pg.RefreshIssuedCounters(ctx); err != nil {
		t.Fatal(err)
	}
	billingRecordAt(t, orch, quotaTenant, hour.Add(2*time.Minute))
	billingRecordAt(t, orch, otherTenant, hour.Add(2*time.Minute))
	dsn := strings.TrimSuffix(billingTestDSN, "/postgres") + "/" + database
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	// nextval survives rollback. Fail the first replacement insert after its
	// DELETE, so a missing transaction would erase the previous measured total.
	_, err = admin.Exec(ctx, `
		CREATE SEQUENCE billing_issuance_attempt;
		GRANT USAGE ON SEQUENCE billing_issuance_attempt TO trstctl_app;
		CREATE FUNCTION billing_issuance_fault() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF nextval('billing_issuance_attempt') = 1 THEN
				RAISE EXCEPTION 'controlled issuance replacement failure';
			END IF;
			RETURN NEW;
		END; $$;
		CREATE TRIGGER billing_issuance_fault BEFORE INSERT ON provider_usage_meters
		FOR EACH ROW EXECUTE FUNCTION billing_issuance_fault();`)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.RefreshIssuedCounters(ctx); err == nil || !strings.Contains(err.Error(), "controlled issuance replacement failure") {
		t.Fatalf("expected injected SQL failure, got %v", err)
	}
	assertIssuedHour(t, pg, quotaTenant, hour, 1)
	assertIssuedHour(t, pg, otherTenant, hour, 2)
	// An independently opened pool represents another replica, with no shared
	// Go mutex or process deltas. Both refresh the same durable facts together.
	secondStore, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secondStore.Close)
	replica := billing.NewPGStore(secondStore)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, meter := range []*billing.PGStore{pg, replica} {
		go func() { <-start; results <- meter.RefreshIssuedCounters(ctx) }()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	assertIssuedHour(t, pg, quotaTenant, hour, 2)
	assertIssuedHour(t, pg, otherTenant, hour, 2)
}

func TestDurableIssuanceCountersKeepMeasuredRowsWhenHistoryUnknown(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_issuance_unknown")
	_, _, orch := billingHistory(t, cs)
	ctx := t.Context()
	hour := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	billingRecordAt(t, orch, quotaTenant, hour.Add(time.Minute))
	if err := pg.RefreshIssuedCounters(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cs.WithTenant(ctx, quotaTenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificate_metadata_receipts SET issuance_status=NULL,
			issuance_fingerprint=NULL,issuance_time=NULL WHERE tenant_id=$1`, quotaTenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := pg.RefreshIssuedCounters(ctx); !errors.Is(err, billing.ErrIssuanceHistoryUnknown) {
		t.Fatalf("unknown source was accepted: %v", err)
	}
	assertIssuedHour(t, pg, quotaTenant, hour, 1)
	if _, known, err := pg.IssuedInPeriod(ctx, quotaTenant, hour, hour.Add(time.Hour)); err != nil || known {
		t.Fatalf("preserved aggregate became signing proof: known=%t error=%v", known, err)
	}
}

func TestDurableIssuanceCountersDoNotTransferAcrossCustomerLifetimes(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_issuance_lifecycle")
	log, projector, orch := billingHistory(t, cs)
	ctx := t.Context()
	hour := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	billingRecordAt(t, orch, quotaTenant, hour.Add(time.Minute))
	billingRecordAt(t, orch, otherTenant, hour.Add(time.Minute))
	if err := pg.RefreshIssuedCounters(ctx); err != nil {
		t.Fatal(err)
	}
	// Leave a process hint pending through the real offboard and re-registration.
	runCtx, cancel := context.WithCancel(ctx)
	inst := billing.InstallDurable(runCtx, nil, nil, cs)
	t.Cleanup(func() { cancel(); <-inst.Stopped })
	inst.Recorder.Record(quotaTenant, usage.MeterCertificatesIssued, 99)
	proof, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, cs, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{
		TenantID: quotaTenant, RegistrationIdentity: proof.EventID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := inst.Recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	assertIssuedHour(t, pg, quotaTenant, hour, 0)
	_, err = orchestrator.ExecuteTenantRegistration(ctx, log, cs, projector,
		orchestrator.NewIdempotency(cs), orchestrator.TenantRegistrationCommand{
			TenantID: quotaTenant, Name: "replacement-customer", IdempotencyKey: "replacement-registration",
			RequestMaterial: []byte("replacement-customer"),
			PayloadAt: func(time.Time) ([]byte, error) {
				return json.Marshal(map[string]string{"name": "replacement-customer"})
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	assertIssuedHour(t, pg, quotaTenant, hour, 0)
	assertIssuedHour(t, pg, quotaTenant, time.Now().UTC().Truncate(time.Hour), 0)
	billingRecordAt(t, orch, quotaTenant, hour.Add(2*time.Minute))
	if err := inst.Recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	assertIssuedHour(t, pg, quotaTenant, hour, 1)
	assertIssuedHour(t, pg, otherTenant, hour, 1)
	// The old envelopes still exist in NATS. SQL deletion did not erase the
	// causal history, and the current customer must not inherit its old mints.
	var offboards int
	if err := log.Replay(ctx, 1, func(e events.Event) error {
		if e.TenantID == quotaTenant && e.Type == projections.EventTenantOffboarded {
			offboards++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if offboards != 1 {
		t.Fatalf("retained offboard events=%d, want 1", offboards)
	}
}
