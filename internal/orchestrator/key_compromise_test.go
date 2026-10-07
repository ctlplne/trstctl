// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A reviewed key compromise is one command with two independently executable
// effects. A successful CA queue must never be mistaken for a stopped listener.
func TestKeyCompromiseQueuesCAAndExactHostFromOneLifecycleEvent(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	mustRegisterTenant(t, st, tenantA)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "compromise owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "compromised.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	const issueKey = "compromise-fixture-issue"
	if err := orch.TransitionWithIdempotency(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, "fixture issue", issueKey); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("e", 64)
	if _, err := orch.RecordCertificate(ctx, tenantA, store.Certificate{
		Fingerprint: fingerprint, Serial: "08", Source: "issued",
		IssuanceIdempotencyKey: "issue:transition:" + issueKey,
	}); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
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
	if err := orch.Transition(ctx, tenantA, identity.ID, orchestrator.StateDeployed,
		"fixture host served the recorded leaf"); err != nil {
		t.Fatal(err)
	}
	_, version, err := st.IdentityApprovalTarget(ctx, tenantA, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	const key = "one-reviewed-compromise"
	receipt, err := orch.TransitionKeyCompromise(ctx, tenantA, identity.ID, key, &version,
		orchestrator.EndpointContainmentRequest{
			TargetID: target.ID, TargetRevision: target.RevisionID,
			IdentityID: identity.ID, ExpectedFingerprint: fingerprint,
			RequiredAgentID: agentID, Connector: target.Type, Target: target.Name,
			Reason: "keyCompromise", RequestedBy: "incident-commander", IdempotencyKey: key,
		})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "containment_queued" || receipt.OutboxID == nil ||
		receipt.IdentityID == nil || *receipt.IdentityID != identity.ID {
		t.Fatalf("missing distinct pending host effect: %+v", receipt)
	}
	if count := countOutbox(t, ctx, st.SystemPool(), tenantA, "transition:"+key); count != 1 {
		t.Fatalf("CA publication jobs = %d, want one", count)
	}
	if count := countOutbox(t, ctx, st.SystemPool(), tenantA, "compromise-contain:"+identity.ID+":"+key); count != 1 {
		t.Fatalf("host containment jobs = %d, want one", count)
	}
	caAttempt, hostStatus, err := orch.KeyCompromiseStatus(ctx, tenantA, identity.ID, key)
	if err != nil || caAttempt.Destination != "revocation.publish" || caAttempt.Status != "pending" ||
		hostStatus.ID != receipt.ID || hostStatus.Status != "containment_queued" {
		t.Fatalf("separate compound status = ca:%+v host:%+v err:%v", caAttempt, hostStatus, err)
	}
	if _, _, err := orch.KeyCompromiseStatus(ctx, tenantA, identity.ID, key+"-different"); err == nil {
		t.Fatal("a different request key read another command's effects")
	}
	read, err := st.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || read.Status != "revoked" {
		t.Fatalf("lifecycle state = %+v, %v", read, err)
	}
	jobs, err := st.ClaimAgentJobs(ctx, tenantA, agentID,
		[]string{"endpoint.contain"}, []string{"host"}, 1, time.Minute, time.Now())
	if err != nil || len(jobs) != 1 || jobs[0].ID != *receipt.OutboxID {
		t.Fatalf("exact host job not independently claimable: %+v %v", jobs, err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("cold replay of compound event: %v", err)
	}
	replayed, err := st.GetConnectorDeliveryReceipt(ctx, tenantA, receipt.ID)
	if err != nil || replayed.OutboxID == nil || *replayed.OutboxID != *receipt.OutboxID {
		t.Fatalf("cold replay lost exact host receipt: %+v %v", replayed, err)
	}
}

// An ordinary revocation only queues CA publication. For a serving X.509
// identity, reporting key-compromise success from that path is unsafe because
// the same compromised leaf can remain live on the host.
func TestOrdinaryKeyCompromiseRefusesServingX509BeforeEventAndOutbox(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	mustRegisterTenant(t, st, tenantA)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "serving compromise owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "serving.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []orchestrator.State{orchestrator.StateIssued, orchestrator.StateDeployed} {
		if err := orch.Transition(ctx, tenantA, identity.ID, to, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	before := countOutboxDestination(t, st, tenantA, "revocation.publish")
	err = orch.TransitionWithIdempotency(ctx, tenantA, identity.ID,
		orchestrator.StateRevoked, "keyCompromise", "ordinary-compromise")
	if !errors.Is(err, orchestrator.ErrKeyCompromiseContainmentRequired) {
		t.Fatalf("ordinary serving-key compromise = %v, want containment refusal", err)
	}
	read, err := st.GetIdentity(ctx, tenantA, identity.ID)
	if err != nil || read.Status != string(orchestrator.StateDeployed) {
		t.Fatalf("refused transition changed identity: %+v %v", read, err)
	}
	if after := countOutboxDestination(t, st, tenantA, "revocation.publish"); after != before {
		t.Fatalf("refused transition added %d CA jobs", after-before)
	}
}

func TestKeyCompromiseContainmentPolicyCoversEveryServingState(t *testing.T) {
	for _, status := range []string{"deployed", "renewing", "renewal_failed"} {
		identity := store.Identity{Kind: store.KindX509Certificate, Status: status}
		if !orchestrator.KeyCompromiseNeedsContainment(identity, orchestrator.StateRevoked, "keyCompromise") {
			t.Fatalf("serving state %s allowed a CA-only compromise", status)
		}
		identity.Kind = "x509"
		if !orchestrator.KeyCompromiseNeedsContainment(identity, orchestrator.StateRevoked, "keyCompromise") {
			t.Fatalf("legacy X.509 kind in %s allowed a CA-only compromise", status)
		}
	}
	for _, identity := range []store.Identity{
		{Kind: store.KindX509Certificate, Status: "issued"},
		{Kind: store.KindSSHCertificate, Status: "deployed"},
	} {
		if orchestrator.KeyCompromiseNeedsContainment(identity, orchestrator.StateRevoked, "keyCompromise") {
			t.Fatalf("non-serving or non-X.509 identity needs host containment: %+v", identity)
		}
	}
	if orchestrator.KeyCompromiseNeedsContainment(store.Identity{Kind: store.KindX509Certificate, Status: "deployed"},
		orchestrator.StateRevoked, "superseded") {
		t.Fatal("factual superseded revocation was routed to key-compromise containment")
	}
}

func TestKeyCompromiseConsumesDistinctApprovalAndReplaysOnlyExactHostIntent(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	mustRegisterTenant(t, st, tenantA)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	owner, err := orch.CreateOwner(ctx, tenantA, "service", "approved compromise owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "approved-compromise.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := orch.TransitionWithIdempotency(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, "fixture issue", "approved-compromise-issue"); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("a", 64)
	if _, err := orch.RecordCertificate(ctx, tenantA, store.Certificate{
		Fingerprint: fingerprint, Serial: "aa", Source: "issued",
		IssuanceIdempotencyKey: "issue:transition:approved-compromise-issue",
	}); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	config, _ := json.Marshal(map[string]any{"executor": "agent", "required_agent_id": agentID})
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{
		Name: "approved-compromise-apache", Type: "apache", Config: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, version, err := st.IdentityApprovalTarget(ctx, tenantA, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	const key = "approved-compromise-command"
	request := orchestrator.EndpointContainmentRequest{
		TargetID: target.ID, TargetRevision: target.RevisionID,
		IdentityID: identity.ID, ExpectedFingerprint: fingerprint,
		RequiredAgentID: agentID, Connector: target.Type, Target: target.Name,
		Reason: "keyCompromise", RequestedBy: "requester@example.test", IdempotencyKey: key,
	}
	intentBytes, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest, err := orch.EnsureOperationApprovalRequest(ctx, tenantA, orchestrator.OperationApprovalIntent{
		ResourceKind: "identity", ResourceID: identity.ID, ResourceName: identity.Name,
		Action: "revoke", Requester: request.RequestedBy,
		FromState: "issued", ToState: "revoked", TargetVersion: version,
		Reason: "keyCompromise", RequiredApprovals: 1, TTL: time.Hour,
		EvidenceRefs: []string{
			"idempotency-key-sha256:" + crypto.SHA256Hex([]byte(key)),
			"key_compromise_host_intent_sha256:" + crypto.SHA256Hex(intentBytes),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	approvalRequest, err = orch.RecordOperationApprovalDecision(ctx, tenantA, orchestrator.OperationApprovalDecision{
		RequestID: approvalRequest.ID, IntentDigest: approvalRequest.IntentDigest,
		Approver: "distinct-reviewer@example.test", Decision: store.ApprovalDecisionApprove,
	})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := store.OperationApprovalUseFromRequest(approvalRequest)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := orch.TransitionKeyCompromiseWithApproval(ctx, tenantA, identity.ID, key, &version, request, authority)
	if err != nil || receipt.Status != "containment_queued" {
		t.Fatalf("approved compound command: %+v %v", receipt, err)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := orch.TransitionKeyCompromiseWithApproval(ctx, tenantA, identity.ID, key, &version, request, authority)
	if err != nil || replayed.ID != receipt.ID {
		t.Fatalf("exact approved replay: %+v %v", replayed, err)
	}
	changed := request
	changed.Target = "different-host"
	if _, err := orch.TransitionKeyCompromiseWithApproval(ctx, tenantA, identity.ID, key, &version, changed, authority); err == nil {
		t.Fatal("consumed approval authorized a changed host")
	}
	if after, err := log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("approved replays appended new event: %d -> %d: %v", before, after, err)
	}
}

func TestKeyCompromiseRecoversBothEffectsAfterEventSQLGap(t *testing.T) {
	ctx := t.Context()
	st, log := newStore(t), openLog(t)
	mustRegisterTenant(t, st, tenantA)
	orch := orchestrator.NewOrchestrator(log, st, orchestrator.NewOutbox(st))
	owner, err := orch.CreateOwner(ctx, tenantA, "workload", "crash-window owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := orch.CreateIdentity(ctx, tenantA, store.Identity{
		Kind: store.KindX509Certificate, Name: "crash.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	const issueKey = "compromise-gap-issue"
	if err := orch.TransitionWithIdempotency(ctx, tenantA, identity.ID,
		orchestrator.StateIssued, "fixture issue", issueKey); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("f", 64)
	if _, err := orch.RecordCertificate(ctx, tenantA, store.Certificate{
		Fingerprint: fingerprint, Serial: "09", Source: "issued",
		IssuanceIdempotencyKey: "issue:transition:" + issueKey,
	}); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	config, err := json.Marshal(map[string]any{"executor": "agent", "required_agent_id": agentID})
	if err != nil {
		t.Fatal(err)
	}
	target, err := orch.UpsertDeploymentTarget(ctx, tenantA, store.DeploymentTarget{
		Name: "gap-apache", Type: "apache", Config: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, version, err := st.IdentityApprovalTarget(ctx, tenantA, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	const key = "compromise-event-sql-gap"
	request := orchestrator.EndpointContainmentRequest{
		TargetID: target.ID, TargetRevision: target.RevisionID,
		IdentityID: identity.ID, ExpectedFingerprint: fingerprint,
		RequiredAgentID: agentID, Connector: target.Type, Target: target.Name,
		Reason: "keyCompromise", RequestedBy: "incident-commander", IdempotencyKey: key,
	}
	if _, err := st.SystemPool().Exec(ctx, `CREATE FUNCTION qa_reject_compromise_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.destination = 'endpoint.contain' AND NEW.status = 'containment_queued'
		THEN RAISE EXCEPTION 'injected compound receipt rollback'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER qa_reject_compromise_receipt BEFORE INSERT ON connector_delivery_receipts
		FOR EACH ROW EXECUTE FUNCTION qa_reject_compromise_receipt()`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := st.SystemPool().Exec(ctx, `DROP TRIGGER IF EXISTS qa_reject_compromise_receipt ON connector_delivery_receipts;
			DROP FUNCTION IF EXISTS qa_reject_compromise_receipt()`); err != nil {
			t.Error(err)
		}
	}()
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orch.TransitionKeyCompromise(ctx, tenantA, identity.ID, key, &version, request); err == nil {
		t.Fatal("compound command committed despite rejected receipt projection")
	}
	after, err := log.LastSequence(ctx)
	if err != nil || after != before+1 {
		t.Fatalf("one immutable command was not retained after SQL rollback: %d -> %d: %v", before, after, err)
	}
	if countOutbox(t, ctx, st.SystemPool(), tenantA, "transition:"+key) != 0 ||
		countOutbox(t, ctx, st.SystemPool(), tenantA, "compromise-contain:"+identity.ID+":"+key) != 0 {
		t.Fatal("SQL rollback retained a partial CA or host outbox row")
	}
	if _, err := st.SystemPool().Exec(ctx,
		`DROP TRIGGER qa_reject_compromise_receipt ON connector_delivery_receipts`); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("retained compound event could not rebuild identity and queued receipt: %v", err)
	}
	if healed, err := orch.ReconcileOutbox(ctx, log); err != nil || healed < 2 {
		t.Fatalf("one retained event did not heal both CA and host intents: healed=%d err=%v", healed, err)
	}
	if countOutbox(t, ctx, st.SystemPool(), tenantA, "transition:"+key) != 1 ||
		countOutbox(t, ctx, st.SystemPool(), tenantA, "compromise-contain:"+identity.ID+":"+key) != 1 {
		t.Fatal("reconciliation did not restore both exact jobs")
	}
	seq, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := orch.TransitionKeyCompromise(ctx, tenantA, identity.ID, key, &version, request)
	if err != nil || receipt.Status != "containment_queued" {
		t.Fatalf("same-key retry did not recover the original receipt: %+v %v", receipt, err)
	}
	if current, err := log.LastSequence(ctx); err != nil || current != seq {
		t.Fatalf("retry appended another event: %d -> %d: %v", seq, current, err)
	}
}
