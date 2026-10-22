// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/verify"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/store"
)

// A33: a network appliance joins a CA migration. The operator names the network
// relay that fronts it; the appliance has no trust stage of its own, so the
// cohort opens at the leaf gate; the control plane issues the successor under
// the new authority with the predecessor's exact identifiers and queues its
// sealed deploy for that relay alone; the relay claims it, redeems the
// material, installs it and reports the signed listener handshake, which
// closes the run's live gate. The control plane never deploys to the
// appliance itself. A host agent, or a trust path, is refused by name.
func TestServedMigrationCarriesANetworkApplianceThroughItsRelay(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork},
		[]string{"connector.deploy", agentrelay.KindConnectorRollback},
		func(d *Deps) { d.DefaultProfile = "a33-api" })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a33-relay", Status: "active"}); err != nil {
		t.Fatalf("register network relay: %v", err)
	}
	spec, _ := json.Marshal(map[string]any{"name": "a33-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "a33-api", spec); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "A33 owner", "")
	if err != nil {
		t.Fatal(err)
	}

	// The appliance's listener: bound now so the target can name it. It serves
	// the predecessor pair until the relay installs the successor (the
	// appliance double is a file-reloading TLS listener behind the crypto
	// boundary, as the AUD40 journey uses).
	const dnsName = "a33-lb.example.test"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "appliance.crt"), filepath.Join(root, "appliance.key")
	targetConfig, _ := json.Marshal(map[string]any{
		"executor": "agent", "endpoint": "https://f5.example.internal", "required_agent_role": mtls.AgentRoleNetwork,
		"required_agent_id": agentRowID(h.tenant, h.agent),
		"verify_address":    listener.Addr().String(), "verify_server_name": dnsName,
	})
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "/Common/a33-lb", Type: "f5", Config: targetConfig, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	attrs, _ := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name, "profile_name": "a33-api"})
	ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: dnsName, OwnerID: owner.ID, Attributes: attrs})
	if err != nil {
		t.Fatal(err)
	}
	ident.Status = "deployed"
	if err := h.store.UpsertIdentity(ctx, ident); err != nil {
		t.Fatal(err)
	}
	// The predecessor the appliance serves today, recorded with the receipt of
	// the deploy that put it there.
	predKey, err := crypto.GenerateHostSubjectKey(dnsName, []string{dnsName})
	if err != nil {
		t.Fatal(err)
	}
	defer predKey.Destroy()
	predPEM, err := h.srv.IssueLeaf(ctx, predKey.CSRDER, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	predInfo, err := certinfo.Inspect(predPEM)
	if err != nil {
		t.Fatal(err)
	}
	predKeyPEM, err := predKey.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, predPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, predKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	tlsServer, err := mtls.ServerCertFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer.SetReloadCheckInterval(time.Millisecond)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })} // #nosec G112 -- loopback fixture closed below (CWE-400)
	serveDone := make(chan error, 1)
	go func() { serveDone <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("appliance listener: %v", serveErr)
		}
	})
	predDER, err := certinfo.LeafDER(predPEM)
	if err != nil {
		t.Fatal(err)
	}
	predecessor, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		OwnerID: &owner.ID, Subject: predInfo.Subject, SANs: predInfo.DNSNames, Issuer: predInfo.Issuer, Serial: predInfo.SerialNumber,
		Fingerprint: predInfo.SHA256Fingerprint, KeyAlgorithm: predInfo.KeyAlgorithm, Source: "issued", CertificateDER: predDER,
		NotBefore: &predInfo.NotBefore, NotAfter: &predInfo.NotAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
		IdentityID: &ident.ID, Destination: "connector.deploy", Connector: target.Type, Target: target.Name,
		Fingerprint: predecessor.Fingerprint, Status: "verified", Reason: "a33 fixture", IdempotencyKey: "a33-deploy-predecessor",
	}); err != nil {
		t.Fatal(err)
	}

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "a33-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "a33-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "A33 successor root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{dnsName}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, caOperator, "create_root", "", rootSpec, 1, "a33-root-ceremony")
	approveCACeremony(t, h.servedHarness, caApprover, ceremony.ID, 1, "a33-root-approval")
	successorCA := createRootCA(t, h.servedHarness, caOperator, ceremony.ID, rootSpec, "a33-root-create")
	token := seedScopedTokenSubject(t, h.store, h.tenant, "a33-migration-operator", "keys:read", "keys:write", "certs:issue")
	start := func(planID, agentID, trustPath, key string) (int, []byte) {
		member := map[string]any{"identity_id": ident.ID, "agent_id": agentID}
		if trustPath != "" {
			member["trust_anchor_path"] = trustPath
		}
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, key, map[string]any{
			"plan_id": planID, "new_authority_id": successorCA.ID,
			"waves": []any{map[string]any{"id": "edge", "ordinal": 1, "members": []any{member}}},
		})
	}

	// Refused by name: a trust path on an appliance, and a host agent for it.
	status, body := start("plan-a33-path", agentRowID(h.tenant, h.agent), "/etc/ssl/next.pem", "a33-start-path")
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("an appliance member takes no trust_anchor_path")) {
		t.Fatalf("appliance member with a trust path: %d %s", status, body)
	}
	const hostAgentID = "33333333-3333-4333-8333-333333333333"
	if err := h.store.UpsertAgent(ctx, store.Agent{ID: hostAgentID, TenantID: h.tenant, Name: "a33-host", Status: "active", Roles: []string{mtls.AgentRoleHost}}); err != nil {
		t.Fatal(err)
	}
	status, body = start("plan-a33-host", hostAgentID, "", "a33-start-host")
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("must match the network relay the target names")) {
		t.Fatalf("appliance member with a host agent: %d %s", status, body)
	}

	status, body = start("plan-a33", agentRowID(h.tenant, h.agent), "", "a33-start")
	if status != http.StatusCreated {
		t.Fatalf("start appliance migration = %d %s", status, body)
	}
	var started migration.Run
	if err := json.Unmarshal(body, &started); err != nil {
		t.Fatal(err)
	}
	member := started.Waves[0].Members[0]
	if started.Status != migration.RunRunning || started.Waves[0].Phase != migration.PhaseVerifyingLive ||
		member.TrustVerdict != migration.VerdictNotApplicable || member.Binding.ExecutionModel != migration.ExecutionAppliance ||
		member.Binding.TrustAnchorPath != "" || member.Binding.RequiredAgentID != agentRowID(h.tenant, h.agent) ||
		member.Binding.PredecessorCertificateID != predecessor.ID {
		t.Fatalf("started run = %+v", started)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "distribute_trust", 0)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "issue_successor", 1)

	// The control plane issues the successor and queues the sealed deploy for
	// the exact relay; it does not touch the appliance.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	bound, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	issuedFingerprint := bound.Run.Waves[0].Members[0].Binding.SuccessorFingerprint
	if issuedFingerprint == "" || bound.Run.Waves[0].Members[0].SuccessorVerdict != "" {
		t.Fatalf("after issuance: binding %+v", bound.Run.Waves[0].Members[0])
	}
	successor, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, issuedFingerprint)
	if err != nil || successor.Status != "active" || successor.ReplacesID == nil || *successor.ReplacesID != predecessor.ID ||
		len(successor.SANs) != 1 || successor.SANs[0] != dnsName {
		t.Fatalf("successor = %+v %v, want an active leaf replacing the predecessor with the exact name", successor, err)
	}
	var role, requiredAgent, outboxStatus string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT required_agent_role, COALESCE(required_agent_id::text,''), status FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`,
			h.tenant, "migration:"+started.ID+":edge:"+ident.ID+":appliance_deploy").Scan(&role, &requiredAgent, &outboxStatus)
	}); err != nil {
		t.Fatalf("appliance deploy row: %v", err)
	}
	if role != mtls.AgentRoleNetwork || requiredAgent != agentRowID(h.tenant, h.agent) || outboxStatus != "pending" {
		t.Fatalf("appliance deploy row = role %q agent %q status %q", role, requiredAgent, outboxStatus)
	}

	// The relay claims exactly that deploy, redeems the material, installs it
	// on the appliance (here: the listener), handshakes it and reports.
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 5, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("relay claim: jobs=%d err=%v", len(claimed.Jobs), err)
	}
	job := claimed.Jobs[0]
	var intent agentrelay.DeployIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || intent.MigrationRunID != started.ID || intent.Connector != "f5" ||
		intent.Fingerprint != issuedFingerprint || intent.VerifyAddress != listener.Addr().String() {
		t.Fatalf("claimed intent = %+v %v", intent, err)
	}
	redeemed, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	var certPEM, keyPEM []byte
	for _, item := range redeemed.Items {
		switch item.Name {
		case "credential.cert_pem":
			certPEM = append([]byte(nil), item.Value...)
		case "credential.key_pem":
			keyPEM = append([]byte(nil), item.Value...)
		}
	}
	// Install on the appliance double, then handshake it the way the relay's
	// post-deploy verification does, inside its reload convergence window.
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	expect, err := certinfo.ExpectationFromChain(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	var probed verify.Result
	deadline := time.Now().Add(5 * time.Second)
	for {
		probed, err = verify.Endpoint(ctx, verify.Request{Address: intent.VerifyAddress, ServerName: intent.VerifyServerName, Vantage: transport.VantageLocal, Expect: expect, Timeout: 2 * time.Second})
		if (err == nil && probed.OK()) || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || !probed.OK() {
		t.Fatalf("relay handshake = %+v %v", probed, err)
	}
	report, _ := json.Marshal(agentrelay.EndpointVerifyReport{Results: []agentrelay.EndpointVerifyResult{{EndpointID: target.ID, Transcript: probed.Transcript, Detail: probed.Verdict.Detail}}})
	if _, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt, transport.JobOutcomeVerified, string(report), probed.Transcript.Digest())); err != nil {
		t.Fatalf("report verified deploy: %v", err)
	}

	finished, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	done := finished.Run.Waves[0].Members[0]
	if finished.Run.Status != migration.RunComplete || finished.Run.Waves[0].Phase != migration.PhaseComplete ||
		done.SuccessorVerdict != migration.VerdictVerified || done.Binding.SuccessorFingerprint != issuedFingerprint {
		t.Fatalf("after the relay's verified receipt: %+v", finished.Run)
	}
	superseded, err := h.store.GetCertificate(ctx, h.tenant, predecessor.ID)
	if err != nil || superseded.Status != "superseded" {
		t.Fatalf("predecessor after migration = %+v %v, want superseded", superseded, err)
	}
	// The relay's verified handshake is the identity's newest served
	// certificate receipt: the next migration would resolve this leaf as the
	// predecessor (A34).
	receipt, found, err := h.store.LatestServedCertificateReceipt(ctx, h.tenant, ident.ID)
	if err != nil || !found || receipt.Fingerprint != issuedFingerprint || receipt.Status != "verified" ||
		!strings.HasPrefix(receipt.IdempotencyKey, "migration:"+started.ID+":edge:") {
		t.Fatalf("latest receipt = %+v found=%v err=%v", receipt, found, err)
	}
}
