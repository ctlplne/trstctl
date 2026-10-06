// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

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
