// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

// These observations simulate probes. Real PG/NATS and a forced outbox failure
// exercise crash recovery; this test does not qualify a database listener.
func TestEndpointAlertReconciliationUsesTheRetainedIncident(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	ctx := t.Context()
	firstGood := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	good := projections.EndpointVerificationObserved{
		EndpointID: "alert-reconcile-db", Address: "db.example.test:5432", Vantage: "relay",
		Reached: true, ExpectedFingerprint: strings.Repeat("a", 64), ObservedFingerprint: strings.Repeat("a", 64),
		NotBefore: firstGood.Add(-time.Hour), NotAfter: firstGood.Add(time.Hour), ObservedAt: firstGood,
	}
	eventID := func(key string) string { return orchestrator.DiscoveryRelayEventID(h.tenant, key, good.EndpointID) }
	if err := h.srv.orch.RecordEndpointVerificationWithEventID(ctx, h.tenant, eventID("initial-good"), good); err != nil {
		t.Fatal(err)
	}
	stop := rejectEndpointAlertInsert(t, h)
	failed := good
	failed.Reached, failed.ObservedFingerprint = false, ""
	failed.NotBefore, failed.NotAfter = time.Time{}, time.Time{}
	failed.ObservedAt, failed.Detail = firstGood.Add(20*time.Second), "controlled connection refusal"
	failedID := eventID("lost-alert")
	if err := h.srv.orch.RecordEndpointVerificationWithEventID(ctx, h.tenant, failedID, failed); err == nil {
		t.Fatal("failed notification intent was acknowledged")
	}
	retained, found, err := h.log.EventByID(ctx, failedID)
	if err != nil || !found {
		t.Fatalf("NATS did not retain the failed SQL operation: found=%v err=%v", found, err)
	}
	current, err := h.store.GetEndpointVerification(ctx, h.tenant, good.EndpointID, good.Vantage)
	if err != nil || !current.Verified() || !current.LastGoodAt.Equal(firstGood) {
		t.Fatalf("failed alert transaction changed current observation: %+v %v", current, err)
	}
	stop()
	// Boot may catch up projections before outbox reconciliation. A newer
	// healthy probe must not rewrite the retained outage's last-good snapshot.
	if err := projections.New(h.store).Apply(ctx, retained); err != nil {
		t.Fatal(err)
	}
	good.ObservedAt = firstGood.Add(40 * time.Second)
	if err := h.srv.orch.RecordEndpointVerificationWithEventID(ctx, h.tenant, eventID("recovered"), good); err != nil {
		t.Fatal(err)
	}
	if healed, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || healed != 1 {
		t.Fatalf("log-only alert recovery: healed=%d err=%v", healed, err)
	}
	alerts := endpointAlertPayloads(t, h)
	if len(alerts) != 1 || !alerts[0].LastGoodAt.Equal(firstGood) {
		t.Fatalf("recovery substituted mutable current history: %+v", alerts)
	}
	if healed, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil || healed != 0 {
		t.Fatalf("repeat reconciliation duplicated alert: healed=%d err=%v", healed, err)
	}
	failed.ObservedAt = firstGood.Add(50 * time.Second)
	if err := h.srv.orch.RecordEndpointVerificationWithEventID(ctx, h.tenant, eventID("second-outage"), failed); err != nil {
		t.Fatal(err)
	}
	failed.Detail = "different text on another probe of the same outage"
	failed.ObservedAt = failed.ObservedAt.Add(time.Second)
	if err := h.srv.orch.RecordEndpointVerificationWithEventID(ctx, h.tenant, eventID("same-outage-next-probe"), failed); err != nil {
		t.Fatalf("repeated failure conflicted with its earlier alert payload: %v", err)
	}
	if alerts := endpointAlertPayloads(t, h); len(alerts) != 2 || alerts[0].OperationID == alerts[1].OperationID || !alerts[1].LastGoodAt.Equal(good.ObservedAt) {
		t.Fatalf("recovery did not delimit a new incident: %+v", alerts)
	}
	legacy, err := json.Marshal(failed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(ctx, events.Event{ID: eventID("legacy"), Type: projections.EventEndpointVerified, SchemaVersion: 1, TenantID: h.tenant, Data: legacy}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.ReconcileOutbox(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	if len(endpointAlertPayloads(t, h)) != 2 {
		t.Fatal("legacy observation invented a notification during reconciliation")
	}
}

func rejectEndpointAlertInsert(t *testing.T, h *roleHarness) func() {
	t.Helper()
	_, err := h.store.SystemPool().Exec(t.Context(), `CREATE FUNCTION qa_alert_reconcile_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.destination='notification.verification' THEN RAISE EXCEPTION 'controlled alert insert failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER qa_alert_reconcile_failure BEFORE INSERT OR UPDATE ON outbox FOR EACH ROW EXECUTE FUNCTION qa_alert_reconcile_failure()`)
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := h.store.SystemPool().Exec(ctx, `DROP TRIGGER IF EXISTS qa_alert_reconcile_failure ON outbox; DROP FUNCTION IF EXISTS qa_alert_reconcile_failure()`); err != nil {
			t.Error(err)
			return
		}
		stopped = true
	}
	t.Cleanup(stop)
	return stop
}

func endpointAlertPayloads(t *testing.T, h *roleHarness) []notify.Alert {
	t.Helper()
	var alerts []notify.Alert
	err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(t.Context(), `SELECT payload FROM outbox WHERE tenant_id=$1 AND destination='notification.verification' ORDER BY id`, h.tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var alert notify.Alert
			if err := json.Unmarshal(raw, &alert); err != nil {
				return err
			}
			alerts = append(alerts, alert)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return alerts
}
