// SPDX-License-Identifier: BUSL-1.1

package server

import (
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

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// X3: an endpoint an observer saw serving an expiring certificate is
// reissued through the existing migration path. The live receipt alone does
// not move the wave: with no new connections observed in its window the run
// pauses, and the observer's finding stays open. Once the observer reports new
// connections presenting the successor, a resume lets the gate pass, the run
// completes, and the finding is marked remediated naming both proofs.
func TestServedClosedLoopVerificationX3(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) { d.DefaultProfile = "x3-api" })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "x3-test", Status: "active"}); err != nil {
		t.Fatal(err)
	}

	// The endpoint: a real TLS listener whose files the host agent manages.
	root := t.TempDir()
	fixture, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.Close() })
	certPath, keyPath := filepath.Join(root, "listener.crt"), filepath.Join(root, "listener.key")
	trustPath := filepath.Join(root, "next-root.pem")
	const dnsName = "closed-loop-x3.test"
	oldCert, oldKey := issueHostPair(t, h, dnsName)
	if err := fixture.WriteFile("listener.crt", oldCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.WriteFile("listener.key", oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	secret.Wipe(oldKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, err := mtls.ServerCertFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer.SetReloadCheckInterval(time.Millisecond)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})} // #nosec G112 -- loopback fixture closed below (CWE-400)
	serveDone := make(chan error, 1)
	go func() { serveDone <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("x3 listener: %v", serveErr)
		}
	})
	address := listener.Addr().String()

	targetConfig, err := json.Marshal(map[string]any{
		"executor": "agent", "cert_path": certPath, "key_path": keyPath,
		"required_agent_id": agentRowID(h.tenant, h.agent), "required_agent_role": mtls.AgentRoleHost,
		"verify_address": address, "verify_server_name": dnsName,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "host/x3", Type: "nginx", Config: targetConfig, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "X3 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(map[string]any{"name": "x3-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "x3-api", spec); err != nil {
		t.Fatal(err)
	}
	attrs, err := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name, "profile_name": "x3-api"})
	if err != nil {
		t.Fatal(err)
	}
	identityID := "40400000-0000-4000-8000-0000000000a3"
	if _, err := h.srv.orch.EnsureIdentity(ctx, h.tenant, identityID, store.Identity{
		Kind: store.KindX509Certificate, Name: dnsName, OwnerID: owner.ID, Attributes: attrs,
	}); err != nil {
		t.Fatal(err)
	}
	state, err := agentrelay.NewHostRollbackStore(filepath.Join(root, "rollback"), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions:      []connector.LocalAction{{LogicalName: "nginx", Command: "/usr/bin/true", Timeout: 5 * time.Second}},
	}
	channel := &servedHostRelayChannel{client: h.client, identity: h.identity}
	if err := h.srv.orch.Transition(ctx, h.tenant, identityID, orchestrator.StateIssued, "issue the expiring predecessor"); err != nil {
		t.Fatal(err)
	}
	if dispatched, err := h.srv.DispatchIssuanceOnce(ctx); err != nil || !dispatched {
		t.Fatalf("dispatch predecessor: %v %v", dispatched, err)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified)
	served, err := fixture.ReadFile("listener.crt")
	if err != nil {
		t.Fatal(err)
	}
	predecessor, err := certinfo.Inspect(served)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(predecessor.NotAfter) > assurance.ExpiringWithin {
		t.Fatalf("the predecessor is not inside the expiring window: not after %s", predecessor.NotAfter)
	}

	// An observer agent saw the endpoint serving it.
	observerAgent := enrollAgentWithRoles(t, h.servedHarness, "edge-observer-x3", h.serverName, []string{mtls.AgentRoleObserver})
	creds, err := observerAgent.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	observer := transport.NewAgentClient(conn)
	registerInventoryAgent(t, observer)
	observe := func(fingerprint string, at time.Time) string {
		t.Helper()
		inv, err := observer.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "network-observer", Findings: []transport.InventoryFinding{{
			Kind: "tls_handshake", Ref: "tls " + address + " TLSv1.2 x25519 " + fingerprint[:16], Provenance: "network-observer:eth1",
			Fingerprint: fingerprint, RiskScore: 60,
			Metadata: map[string]string{"protocol": "tls", "server": address, "server_name": dnsName, "tls_version": "TLSv1.2",
				"group": "x25519", "certificate_visible": "true", "last_seen": at.UTC().Format(time.RFC3339), "payload_stored": "false"},
		}}})
		if err != nil || inv.Recorded != 1 {
			t.Fatalf("observer report: %+v %v", inv, err)
		}
		findings, err := h.store.ListDiscoveryFindingsPage(ctx, h.tenant, inv.RunID, store.ZeroUUID, 10)
		if err != nil || len(findings) != 1 {
			t.Fatalf("observer finding: %+v %v", findings, err)
		}
		return findings[0].ID
	}
	expiringFinding := observe(predecessor.SHA256Fingerprint, time.Now())

	// Reissue through the existing migration path, requiring observed traffic.
	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "x3-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "x3-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "X3 successor root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{dnsName}, "extended_key_usages": []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, caOperator, "create_root", "", rootSpec, 1, "x3-root-ceremony")
	approveCACeremony(t, h.servedHarness, caApprover, ceremony.ID, 1, "x3-root-approval")
	successorAuthority := createRootCA(t, h.servedHarness, caOperator, ceremony.ID, rootSpec, "x3-root-create")
	token := seedScopedTokenSubject(t, h.store, h.tenant, "x3-migration-operator", "keys:read", "keys:write", "certs:issue")
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, "x3-start", map[string]any{
		"plan_id": "plan-x3", "new_authority_id": successorAuthority.ID,
		"require_observed_traffic": true, "observed_traffic_window_seconds": 1,
		"waves": []any{map[string]any{"id": "canary", "ordinal": 1, "members": []any{map[string]any{
			"identity_id": identityID, "agent_id": agentRowID(h.tenant, h.agent), "trust_anchor_path": trustPath,
		}}}},
	})
	var started migration.Run
	if status != http.StatusCreated || json.Unmarshal(body, &started) != nil || !started.RequireObservedTraffic {
		t.Fatalf("start migration: HTTP %d %s", status, body)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeExecuted) // trust readback
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified) // signer + deploy + live probe

	// The probe saw the successor; the wave still waits for the wire.
	row, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	member := row.Run.Waves[0].Members[0]
	if row.Run.Status != migration.RunRunning || row.Run.Waves[0].Phase != migration.PhaseVerifyingLive ||
		member.SuccessorVerdict != migration.VerdictVerified || member.LiveVerifiedAt == nil || member.TrafficVerdict != "" {
		t.Fatalf("after the live receipt: run %s phase %s member %+v", row.Run.Status, row.Run.Waves[0].Phase, member)
	}
	successorPEM, err := fixture.ReadFile("listener.crt")
	if err != nil {
		t.Fatal(err)
	}
	successor, err := certinfo.Inspect(successorPEM)
	if err != nil || successor.SHA256Fingerprint == predecessor.SHA256Fingerprint {
		t.Fatalf("the endpoint does not serve a successor: %v", err)
	}

	// No new connections observed inside the window: the run pauses.
	if err := h.srv.CheckMigrationTrafficOnce(ctx, member.LiveVerifiedAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	row, _ = h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if row.Run.Status != migration.RunPaused || !strings.Contains(row.Run.PauseReason, "no new connections observed at "+address) {
		t.Fatalf("a late wire proof did not pause the run: %s %q", row.Run.Status, row.Run.PauseReason)
	}
	if f, err := h.store.GetDiscoveryFinding(ctx, h.tenant, expiringFinding); err != nil || f.TriageStatus == "remediated" {
		t.Fatalf("the observed finding closed on the probe alone: %+v %v", f, err)
	}

	// New connections present the successor; resume and let the gate pass.
	observe(successor.SHA256Fingerprint, time.Now().Add(time.Second))
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs/"+started.ID+"/resume", token, "x3-resume", nil)
	if status != http.StatusOK {
		t.Fatalf("resume: HTTP %d %s", status, body)
	}
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC().Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	row, _ = h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if row.Run.Status != migration.RunComplete || row.Run.Waves[0].Members[0].TrafficVerdict != migration.VerdictVerified {
		t.Fatalf("wire evidence did not complete the run: %s %+v", row.Run.Status, row.Run.Waves[0].Members[0])
	}
	closed, err := h.store.GetDiscoveryFinding(ctx, h.tenant, expiringFinding)
	if err != nil || closed.TriageStatus != "remediated" || !strings.Contains(closed.TriageEvidenceRef, "live receipt") ||
		!strings.Contains(closed.TriageEvidenceRef, "observed connections") {
		t.Fatalf("the observed finding did not close on both proofs: %+v %v", closed, err)
	}
}
