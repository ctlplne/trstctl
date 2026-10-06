// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestEndpointContainmentExactBindingAndDisabledTargetClaim(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	mustRegisterTenant(t, st, tenantA)
	mustRegisterTenant(t, st, tenantB)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	agentID, otherAgentID := uuid.NewString(), uuid.NewString()
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "containment owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{Kind: store.KindX509Certificate,
		Name: "compromised.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	const issueKey = "containment-fixture-issue"
	if err := orch.TransitionWithIdempotency(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, "fixture issued", issueKey); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("a", 64)
	if _, err := orch.RecordCertificate(ctx, tenantA, store.Certificate{
		Fingerprint: fingerprint, Serial: "01", Source: "issued",
		IssuanceIdempotencyKey: "issue:transition:" + issueKey,
	}); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{"executor": "agent", "required_agent_id": agentID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{
		Name: "compromised-apache", Type: "apache", Config: config,
		Enabled: false, EnabledSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := orchestrator.EndpointContainmentRequest{
		TargetID: target.ID, TargetRevision: target.RevisionID, IdentityID: identity.ID,
		ExpectedFingerprint: fingerprint, RequiredAgentID: agentID,
		Connector: target.Type, Target: target.Name, Reason: "key compromise",
		RequestedBy: "incident-commander", IdempotencyKey: "contain-exact-leaf",
	}
	assertNoEvent := func(name string, candidate orchestrator.EndpointContainmentRequest, tenant string) {
		t.Helper()
		before, err := log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := orch.RequestEndpointContainment(ctx, tenant, candidate); err == nil {
			t.Fatalf("%s: unsafe containment accepted", name)
		}
		after, err := log.LastSequence(ctx)
		if err != nil || after != before {
			t.Fatalf("%s: refusal appended events: %d -> %d: %v", name, before, after, err)
		}
	}
	stale := request
	stale.TargetRevision = uuid.NewString()
	assertNoEvent("stale target", stale, tenantA)
	wrongAgent := request
	wrongAgent.RequiredAgentID = otherAgentID
	assertNoEvent("wrong agent", wrongAgent, tenantA)
	wrongLeaf := request
	wrongLeaf.ExpectedFingerprint = strings.Repeat("b", 64)
	assertNoEvent("wrong certificate", wrongLeaf, tenantA)
	assertNoEvent("other tenant", request, tenantB)

	receipt, err := orch.RequestEndpointContainment(ctx, tenantA, request)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "containment_queued" || receipt.Destination != "endpoint.contain" ||
		receipt.OutboxID == nil || receipt.IdentityID == nil || *receipt.IdentityID != identity.ID {
		t.Fatalf("missing canonical queued receipt: %+v", receipt)
	}
	repeat, err := orch.RequestEndpointContainment(ctx, tenantA, request)
	if err != nil || repeat.ID != receipt.ID || *repeat.OutboxID != *receipt.OutboxID {
		t.Fatalf("idempotent request made a second job: %+v %v", repeat, err)
	}
	if got, err := st.GetConnectorDeliveryReceipt(ctx, tenantB, receipt.ID); err == nil {
		t.Fatalf("other tenant read containment receipt: %+v", got)
	}
	if jobs, err := st.ClaimAgentJobs(ctx, tenantA, otherAgentID,
		[]string{"endpoint.contain"}, []string{"host"}, 1, time.Minute, time.Now()); err != nil || len(jobs) != 0 {
		t.Fatalf("other agent claimed targeted job: %+v %v", jobs, err)
	}
	if jobs, err := st.ClaimAgentJobs(ctx, tenantA, agentID,
		[]string{"endpoint.contain"}, nil, 1, time.Minute, time.Now()); err != nil || len(jobs) != 0 {
		t.Fatalf("agent without host role claimed job: %+v %v", jobs, err)
	}
	jobs, err := st.ClaimAgentJobs(ctx, tenantA, agentID,
		[]string{"endpoint.contain"}, []string{"host"}, 1, time.Minute, time.Now())
	if err != nil || len(jobs) != 1 || jobs[0].ID != *receipt.OutboxID {
		t.Fatalf("disabled target stranded emergency containment: %+v %v", jobs, err)
	}
	var payload struct {
		TargetID            string `json:"target_id"`
		IdentityID          string `json:"identity_id"`
		ExpectedFingerprint string `json:"expected_fingerprint"`
		RequiredAgentID     string `json:"required_agent_id"`
	}
	if err := json.Unmarshal(jobs[0].Payload, &payload); err != nil ||
		payload.TargetID != target.ID || payload.IdentityID != identity.ID ||
		payload.ExpectedFingerprint != fingerprint || payload.RequiredAgentID != agentID {
		t.Fatalf("claim altered exact public intent: %+v %v", payload, err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("containment request catch-up: %v", err)
	}
	read, err := st.GetConnectorDeliveryReceipt(ctx, tenantA, receipt.ID)
	if err != nil || read.Status != "containment_queued" {
		t.Fatalf("catch-up lost queued result: %+v %v", read, err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("containment receipt event replay: %v", err)
	}
	read, err = st.GetConnectorDeliveryReceipt(ctx, tenantA, receipt.ID)
	if err != nil || read.Status != "containment_queued" || read.Fingerprint != fingerprint {
		t.Fatalf("replay lost exact queued receipt: %+v %v", read, err)
	}
}

func TestEndpointContainmentRecoversAppendBeforeSQLRollback(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	mustRegisterTenant(t, st, tenantA)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	agentID := uuid.NewString()
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "containment recovery owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "rollback.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	const issueKey = "containment-rollback-fixture"
	if err := orch.TransitionWithIdempotency(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, "fixture issued", issueKey); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("c", 64)
	if _, err := orch.RecordCertificate(ctx, tenantA, store.Certificate{
		Fingerprint: fingerprint, Serial: "02", Source: "issued",
		IssuanceIdempotencyKey: "issue:transition:" + issueKey,
	}); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{"executor": "agent", "required_agent_id": agentID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{
		Name: "rollback-apache", Type: "apache", Config: config,
		Enabled: false, EnabledSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := orchestrator.EndpointContainmentRequest{
		TargetID: target.ID, TargetRevision: target.RevisionID, IdentityID: identity.ID,
		ExpectedFingerprint: fingerprint, RequiredAgentID: agentID,
		Connector: target.Type, Target: target.Name, Reason: "key compromise",
		RequestedBy: "incident-commander", IdempotencyKey: "contain-after-sql-rollback",
	}
	if _, err := st.SystemPool().Exec(ctx, `CREATE FUNCTION qa_reject_queued_containment() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.destination = 'endpoint.contain' AND NEW.status = 'containment_queued'
		THEN RAISE EXCEPTION 'injected queued receipt rollback'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER qa_reject_queued_containment BEFORE INSERT ON connector_delivery_receipts
		FOR EACH ROW EXECUTE FUNCTION qa_reject_queued_containment()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := st.SystemPool().Exec(ctx, `DROP TRIGGER IF EXISTS qa_reject_queued_containment ON connector_delivery_receipts;
			DROP FUNCTION IF EXISTS qa_reject_queued_containment()`); err != nil {
			t.Error(err)
		}
	}()
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.RequestEndpointContainment(ctx, tenantA, request); err == nil {
		t.Fatal("containment command committed despite rejected queued receipt")
	}
	after, err := log.LastSequence(ctx)
	if err != nil || after <= before {
		t.Fatalf("did not reproduce retained append before SQL rollback: %d -> %d: %v", before, after, err)
	}
	const outboxKey = "endpoint-contain:"
	if count := countOutbox(t, ctx, st.SystemPool(), tenantA, outboxKey+target.ID+":"+request.IdempotencyKey); count != 0 {
		t.Fatalf("rolled-back outbox has %d rows", count)
	}
	if _, err := st.SystemPool().Exec(ctx, `DROP TRIGGER qa_reject_queued_containment ON connector_delivery_receipts`); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("retained containment event stopped projector: %v", err)
	}
	healed, err := orch.ReconcileOutbox(ctx, log)
	if err != nil || healed != 1 {
		t.Fatalf("retained containment intent failed to restore host job: healed=%d err=%v", healed, err)
	}
	if count := countOutbox(t, ctx, st.SystemPool(), tenantA, outboxKey+target.ID+":"+request.IdempotencyKey); count != 1 {
		t.Fatalf("recovered containment has %d host jobs, want one", count)
	}
	var restoredID int64
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT id FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`,
		tenantA, outboxKey+target.ID+":"+request.IdempotencyKey).Scan(&restoredID); err != nil {
		t.Fatal(err)
	}
	beforeRetry, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := orch.RequestEndpointContainment(ctx, tenantA, request)
	if err != nil || receipt.OutboxID == nil || *receipt.OutboxID != restoredID {
		t.Fatalf("retry did not reuse the retained job identity: %+v %v", receipt, err)
	}
	afterRetry, err := log.LastSequence(ctx)
	if err != nil || afterRetry != beforeRetry {
		t.Fatalf("retry appended another containment event: %d -> %d: %v", beforeRetry, afterRetry, err)
	}
	jobs, err := st.ClaimAgentJobs(ctx, tenantA, agentID,
		[]string{"endpoint.contain"}, []string{"host"}, 1, time.Minute, time.Now())
	if err != nil || len(jobs) != 1 || jobs[0].ID != restoredID {
		t.Fatalf("restored exact host job was not claimable: %+v %v", jobs, err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("cold projection replay lost restored containment: %v", err)
	}
	replayed, err := st.GetConnectorDeliveryReceipt(ctx, tenantA, receipt.ID)
	if err != nil || replayed.OutboxID == nil || *replayed.OutboxID != restoredID ||
		replayed.Status != "containment_queued" {
		t.Fatalf("cold replay changed exact queued host job: %+v %v", replayed, err)
	}
}

func TestEndpointContainmentRecoversRequestBeforeQueuedReceiptAppend(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	mustRegisterTenant(t, st, tenantA)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	targetID, revision, identityID, agentID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	const key = "contain-before-receipt-append"
	receiptID := uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("endpoint-containment-receipt\x00"+tenantA+"\x00"+targetID+"\x00"+key)).String()
	eventID := uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("endpoint-containment-request\x00"+tenantA+"\x00"+targetID+"\x00"+key)).String()
	var outboxID int64
	if err := st.SystemPool().QueryRow(ctx,
		`SELECT nextval(pg_get_serial_sequence('outbox', 'id'))`).Scan(&outboxID); err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(map[string]any{
		"target_id": targetID, "target_revision": revision, "identity_id": identityID,
		"expected_fingerprint": strings.Repeat("d", 64), "required_agent_id": agentID,
		"connector": "apache", "target": "recovery-apache", "reason": "key compromise",
		"requested_by": "incident-commander", "idempotency_key": key,
		"outbox_id": outboxID, "receipt_id": receiptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{ID: eventID, Type: orchestrator.EventEndpointContainmentRequested,
		SchemaVersion: 2, TenantID: tenantA, Data: request}); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if healed, err := orch.ReconcileOutbox(ctx, log); err != nil || healed != 1 {
		t.Fatalf("request-only append did not restore job and queued receipt: healed=%d err=%v", healed, err)
	}
	receipt, err := st.GetConnectorDeliveryReceipt(ctx, tenantA, receiptID)
	if err != nil || receipt.OutboxID == nil || *receipt.OutboxID != outboxID ||
		receipt.Status != "containment_queued" {
		t.Fatalf("request-only append did not restore exact receipt: %+v %v", receipt, err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("request-only recovery failed cold replay: %v", err)
	}
	if count := countOutbox(t, ctx, st.SystemPool(), tenantA,
		"endpoint-contain:"+targetID+":"+key); count != 1 {
		t.Fatalf("request-only recovery has %d host jobs, want one", count)
	}
}
