// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A122 end to end on the control plane: a NetScaler destination whose
// appliance generates its key, pinned to a network relay. First issuance mints
// nothing; it queues endpoint.renew for exactly that relay. The relay's CSR is
// signed and recorded as appliance custody, a report claiming host custody is
// refused, the signed appliance report deploys the identity, and revocation of
// the identity finds the certificate.
func TestServedApplianceGeneratedKeyIsIssuedThroughThePinnedRelay(t *testing.T) {
	ctx := t.Context()
	h, _, ident := queueApplianceFirstIssuance(t)
	job := claimOneRenewal(t, ctx, h)
	key, err := crypto.GenerateHostSubjectKey("vip.example.test", []string{"vip.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER})
	if err != nil {
		t.Fatalf("sign the appliance's CSR: %v", err)
	}
	cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, issued.Fingerprint)
	if err != nil || cert.KeyOrigin != string(custody.OriginAppliance) {
		t.Fatalf("recorded certificate origin = %q (%v), want appliance", cert.KeyOrigin, err)
	}

	id := h.identity.Identity()
	signed := func(record custody.Record) *transport.ReportJobResultRequest {
		t.Helper()
		req, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
			transport.JobOutcomeExecuted, "installed against the appliance key", "", issued.Fingerprint, record, time.Now().UTC().Unix())
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	hostClaim := custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable, GeneratedBy: id.CommonName()}
	if _, err := h.client.ReportJobResult(ctx, signed(hostClaim)); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("an appliance renewal reported as host custody = %v, want a custody refusal", err)
	}
	if accepted, err := h.client.ReportJobResult(ctx, signed(relay.ApplianceRenewCustody(id.CommonName()))); err != nil || !accepted.Accepted {
		t.Fatalf("appliance custody report = %+v, %v", accepted, err)
	}
	if state, err := h.srv.orch.State(ctx, h.tenant, ident.ID); err != nil || state != orchestrator.StateDeployed {
		t.Fatalf("identity after the appliance report = %s (%v), want deployed", state, err)
	}
	cert, err = h.store.GetCertificateByFingerprint(ctx, h.tenant, issued.Fingerprint)
	if err != nil || cert.KeyOrigin != string(custody.OriginAppliance) || cert.KeyStorage != string(custody.StorageAppliance) ||
		cert.KeyExportable != string(custody.Exportable) || cert.KeyGeneratedBy != id.CommonName() {
		t.Fatalf("certificate custody = origin %q storage %q exportable %q by %q (%v)",
			cert.KeyOrigin, cert.KeyStorage, cert.KeyExportable, cert.KeyGeneratedBy, err)
	}
	revocable, err := h.store.IdentityRevocationCertificates(ctx, h.tenant, ident.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(revocable, func(c store.Certificate) bool { return c.Fingerprint == issued.Fingerprint }) {
		t.Fatalf("revoking the identity would miss its appliance-generated certificate: %d candidates", len(revocable))
	}
}

// queueApplianceFirstIssuance builds a NetScaler destination whose appliance
// generates its key, pinned to the harness's network relay, and runs an
// identity's first issuance: it checks that the relay's renewal was queued for
// exactly that relay and that nothing was minted.
func queueApplianceFirstIssuance(t *testing.T) (*roleHarness, store.DeploymentTarget, store.Identity) {
	t.Helper()
	ctx := t.Context()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, agentJobKindEndpointRenew)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "relay-test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	relayID := agentRowID(h.tenant, h.agent)
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read")
	cfg := map[string]any{"endpoint": "https://ns.example.test", "username": "nsroot",
		"password_ref": "secret://connectors/ns", "key_generation": "appliance"}
	create := func() (int, []byte) {
		return secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
			"name": "web-prod", "connector": "netscaler", "config": cfg, "enabled": true,
		})
	}
	if status, body := create(); status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "relay") {
		t.Fatalf("appliance-key destination without a pinned relay = %d %s, want 422 naming the relay", status, body)
	}
	cfg["required_agent_id"] = relayID
	status, body := create()
	if status != http.StatusCreated {
		t.Fatalf("appliance-key destination pinned to the relay = %d %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	target, err := h.store.GetDeploymentTarget(ctx, h.tenant, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, string(store.OwnerTeam), "Edge Team", "edge@example.test")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "vip.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.BindIdentityDeploymentTarget(ctx, h.tenant, ident.ID, target); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.TransitionWithIdempotency(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "first issuance", "appliance-first-issuance"); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	var role, agent string
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT required_agent_role, coalesce(required_agent_id::text, '') FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, agentJobKindEndpointRenew).Scan(&role, &agent); err != nil {
		t.Fatalf("no appliance renewal was queued: %v", err)
	}
	if role != mtls.AgentRoleNetwork || agent != relayID {
		t.Fatalf("queued renewal role %q agent %q, want the network relay %s", role, agent, relayID)
	}
	var minted int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM certificates WHERE tenant_id = $1`, h.tenant).Scan(&minted); err != nil || minted != 0 {
		t.Fatalf("certificates before the relay's CSR = %d (%v), want none", minted, err)
	}

	return h, target, ident
}

// Cancelling a destination's work withdraws its queued appliance renewal, as
// it does a host's: the relay is never asked to generate a key for a
// destination an operator stopped.
func TestServedCancellingAnApplianceDestinationWithdrawsItsRenewal(t *testing.T) {
	ctx := t.Context()
	h, target, _ := queueApplianceFirstIssuance(t)
	var jobID int64
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT id FROM outbox WHERE tenant_id = $1 AND destination = $2`, h.tenant, agentJobKindEndpointRenew).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	cancelled, err := h.srv.orch.CancelConnectorTargetWork(ctx, h.tenant, orchestrator.CancelConnectorWorkRequest{
		TargetID: target.ID, Reason: "appliance replaced", RequestedBy: "operator@example.test",
	})
	if err != nil {
		t.Fatalf("cancel the destination's work: %v", err)
	}
	if !slices.Contains(cancelled.Withdrawn, jobID) {
		t.Fatalf("cancel withdrew %v, want the queued appliance renewal %d", cancelled.Withdrawn, jobID)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 5, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 0 {
		t.Fatalf("the relay could still claim %d renewals after the cancel (%v)", len(claimed.Jobs), err)
	}
}
