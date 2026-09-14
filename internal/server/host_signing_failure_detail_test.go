// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func TestServedHostSigningStageSurvivesCredentialRedemption(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	ctx := t.Context()
	agentID := registeredRoleAgentID(t, h)
	beforeCredential, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	config := json.RawMessage(`{"executor":"agent","required_agent_id":"` + agentID + `","keystore_password_ref":"secret://signing-stage-password"}`)
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "signing-stage-java", Type: "java-keystore", Config: config, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, "signing-stage-password", []byte(canaryPassword))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, "signing-stage-password", sealed)
	payload, err := json.Marshal(RelayDeployIntent{Connector: target.Type, Target: target.Name, TargetID: target.ID, Revision: target.RevisionID, TargetConfig: config})
	if err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO outbox(tenant_id,destination,payload,idempotency_key,required_agent_id,required_agent_role) VALUES($1,'endpoint.renew',$2,'host-signing-stage',$3,'host') RETURNING id`, h.tenant, payload, agentID).Scan(&jobID)
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != jobID {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	job := claimed.Jobs[0]
	material, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: job.Attempt})
	if err != nil {
		t.Fatal(err)
	}
	if len(material.Items) != 1 || !bytes.Equal(material.Items[0].Value, []byte(canaryPassword)) {
		t.Fatal("the claimed host did not receive its reviewed management credential")
	}
	for _, item := range material.Items {
		secret.Wipe(item.Value)
	}
	const source = "the control plane did not sign this host's request"
	const want = "signing: this host did not receive a signed certificate from the control plane; inspect this attempt's issuance job before retrying"
	svc, ok := h.srv.agentServiceForTest()
	if !ok {
		t.Fatal("missing agent service")
	}
	// A prefix, suffix, whitespace or secret can never turn arbitrary text into
	// the public marker, even if it closely resembles the known agent phrase.
	for _, detail := range []string{source + ": " + canaryPassword, " " + source, source + "\n", canaryPassword} {
		got := svc.agentDetailForHistory(ctx, h.tenant, agentID, &transport.ReportJobResultRequest{JobID: jobID, Attempt: job.Attempt, Outcome: transport.JobOutcomeFailed, Detail: detail})
		if got != agentDetailCredentialBearing {
			t.Fatalf("non-exact credential-bearing detail was retained: %q", got)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	got := svc.agentDetailForHistory(cancelled, h.tenant, agentID, &transport.ReportJobResultRequest{JobID: jobID, Outcome: transport.JobOutcomeFailed, Detail: source})
	if got != agentDetailCredentialBearing {
		t.Fatalf("failed custody/job lookup was not closed: %q", got)
	}
	report := h.report(t, jobID, job.Attempt, transport.JobOutcomeFailed, source, "")
	if _, err := h.client.ReportJobResult(ctx, report); err != nil {
		t.Fatal(err)
	}
	receipts, err := h.store.ListConnectorDeliveryReceiptsPage(ctx, h.tenant, "", "00000000-0000-0000-0000-000000000000", 10)
	if err != nil || len(receipts) != 1 || receipts[0].Status != "failed" || !bytes.Contains([]byte(receipts[0].Detail), []byte(want)) || receipts[0].Fingerprint != "" || receipts[0].RollbackRef != "" {
		t.Fatalf("signing failure lost its safe stage or invented delivery: %+v err=%v", receipts, err)
	}
	preserved := false
	if err := h.log.Replay(ctx, 1, func(e events.Event) error {
		if e.Type == "agent.job.failed" && bytes.Contains(e.Data, []byte(want)) {
			preserved = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !preserved {
		t.Fatal("permanent job history lost the safe signing stage")
	}
	assertNoCanaryInJobRows(t, ctx, h)
	// Check named raw/base64/hex canaries in every event, including the public
	// certificate serial in the registration heartbeat. That heartbeat predates
	// all credential creation/custody in this test; its random public serial
	// is not free-text secret leakage. Keep the entropy check on every event
	// generated after registration, including redemption and the signed failure.
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != h.tenant {
			return nil
		}
		assertNoCanaryBytes(t, "event "+e.Type, e.Data)
		if e.Sequence > beforeCredential {
			assertNoCanary(t, "event "+e.Type, withoutReceiptFields(t, e.Data))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
