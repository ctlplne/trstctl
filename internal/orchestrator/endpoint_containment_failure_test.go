// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

func TestAllSignedNonStoppedContainmentResultsPageExactOperator(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	identityID := "33333333-3333-4333-8333-333333333333"
	for i, status := range []string{
		servedstatus.ConnectorContainmentFailed,
		servedstatus.ConnectorContainmentUnverified,
		servedstatus.ConnectorContainmentDifferentLeaf,
	} {
		t.Run(status, func(t *testing.T) {
			outboxID := int64(80 + i)
			receipt := store.ConnectorDeliveryReceipt{
				ID: uuid.NewString(), OutboxID: &outboxID, IdentityID: &identityID,
				Destination: orchestrator.DestinationEndpointContainment,
				Connector:   "apache", Target: "qa-compromised-host",
				Fingerprint: "public-leaf-fingerprint", Status: status, Attempts: 1,
				Reason: status, Detail: `{"signed_report":"present"}`,
				IdempotencyKey: "contain:" + status,
			}
			if _, err := orch.RecordEndpointContainmentFailure(ctx, tenantA, uuid.NewString(), receipt); err != nil {
				t.Fatal(err)
			}
			read, err := st.GetConnectorDeliveryReceipt(ctx, tenantA, receipt.ID)
			if err != nil || read.Status != status {
				t.Fatalf("non-stopped result lost its exact receipt: %+v %v", read, err)
			}
			var payload []byte
			if err := st.SystemPool().QueryRow(ctx,
				`SELECT payload FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3`,
				tenantA, notify.DestinationContainment, "containment-failed:"+receipt.ID).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			var alert notify.Alert
			if err := json.Unmarshal(payload, &alert); err != nil || alert.Kind != notify.KindEndpointContainmentFailed ||
				alert.IdentityID != identityID || alert.DeploymentReceiptID != receipt.ID ||
				alert.CertificateFingerprint != receipt.Fingerprint || alert.Severity != notify.AlertSeverityCritical {
				t.Fatalf("non-stopped result lost its incident scope: %+v %v", alert, err)
			}
		})
	}
}

func TestContainmentFailureReceiptAndAlertShareTransactionAndReconcile(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	outboxID := int64(73)
	identityID := "33333333-3333-4333-8333-333333333333"
	r := store.ConnectorDeliveryReceipt{
		ID: "44444444-4444-4444-8444-444444444473", OutboxID: &outboxID,
		IdentityID: &identityID, Destination: orchestrator.DestinationEndpointContainment,
		Connector: "apache", Target: "qa-compromised-host", Fingerprint: "public-leaf-fingerprint",
		Status: servedstatus.ConnectorContainmentFailed, Attempts: 1,
		Reason: "host action refused", Detail: `{"reason":"missing host profile"}`,
		IdempotencyKey: "contain:qa-host",
	}
	const eventID = "55555555-5555-4555-8555-555555555573"
	if _, err := st.SystemPool().Exec(ctx, `CREATE FUNCTION qa_reject_containment_alert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.destination = 'notification.containment' THEN RAISE EXCEPTION 'injected containment alert failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER qa_reject_containment_alert BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION qa_reject_containment_alert()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := st.SystemPool().Exec(ctx,
			`DROP TRIGGER IF EXISTS qa_reject_containment_alert ON outbox; DROP FUNCTION IF EXISTS qa_reject_containment_alert()`); err != nil {
			t.Error(err)
		}
	}()
	if _, err := orch.RecordEndpointContainmentFailure(ctx, tenantA, eventID, r); err == nil {
		t.Fatal("containment failure receipt committed without its operator alert")
	}
	if got, err := st.GetConnectorDeliveryReceipt(ctx, tenantA, r.ID); err == nil {
		t.Fatalf("receipt survived rejected alert transaction: %+v", got)
	}
	if _, err := st.SystemPool().Exec(ctx, `DROP TRIGGER qa_reject_containment_alert ON outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RecordEndpointContainmentFailure(ctx, tenantA, eventID, r); err != nil {
		t.Fatalf("retained event did not repair SQL state: %v", err)
	}
	if got, err := st.GetConnectorDeliveryReceipt(ctx, tenantA, r.ID); err != nil ||
		got.Status != servedstatus.ConnectorContainmentFailed {
		t.Fatalf("terminal receipt not recovered: %+v %v", got, err)
	}
	var payload []byte
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT payload FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3`,
		tenantA, notify.DestinationContainment, "containment-failed:"+r.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var alert notify.Alert
	if err := json.Unmarshal(payload, &alert); err != nil || alert.Kind != notify.KindEndpointContainmentFailed ||
		alert.IdentityID != identityID || alert.DeploymentReceiptID != r.ID {
		t.Fatalf("alert lost exact failed host identity: %+v %v", alert, err)
	}
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM outbox WHERE tenant_id=$1 AND destination=$2 AND idempotency_key=$3`,
		tenantA, notify.DestinationContainment, "containment-failed:"+r.ID); err != nil {
		t.Fatal(err)
	}
	if healed, err := orch.ReconcileOutbox(ctx, log); err != nil || healed != 1 {
		t.Fatalf("retained failure did not restore lost alert: healed=%d err=%v", healed, err)
	}
	if healed, err := orch.ReconcileOutbox(ctx, log); err != nil || healed != 0 {
		t.Fatalf("reconciliation created duplicate alert: healed=%d err=%v", healed, err)
	}
}
