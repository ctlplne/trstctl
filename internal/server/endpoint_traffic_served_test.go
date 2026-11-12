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

// X3-L1: a plain renewal — no migration run — deploys its successor to a real
// listener and the host agent verifies it; the verification records the
// replacement, and the endpoint waits for wire evidence like a migration
// run's member: nothing closes on the probe alone, the window passing without
// new connections is recorded as unobserved, and new connections presenting
// the successor record the evidence and close the observer's finding for the
// replaced certificate, naming both proofs. The endpoint verification API
// says where each endpoint stands.
func TestServedPlainRenewalWaitsForWireEvidenceX3L1(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) { d.DefaultProfile = "x3l1-api" })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "x3l1-test", Status: "active"}); err != nil {
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
	const dnsName = "renewal-x3l1.test"
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
			t.Errorf("x3l1 listener: %v", serveErr)
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
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "host/x3l1", Type: "nginx", Config: targetConfig, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "X3-L1 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(map[string]any{"name": "x3l1-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "x3l1-api", spec); err != nil {
		t.Fatal(err)
	}
	attrs, err := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name, "profile_name": "x3l1-api"})
	if err != nil {
		t.Fatal(err)
	}
	identityID := "40400000-0000-4000-8000-0000000000b4"
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
	observerAgent := enrollAgentWithRoles(t, h.servedHarness, "edge-observer-x3l1", h.serverName, []string{mtls.AgentRoleObserver})
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

	// A plain renewal, no migration run.
	if err := h.srv.orch.Transition(ctx, h.tenant, identityID, orchestrator.StateRenewing, "renew before expiry"); err != nil {
		t.Fatal(err)
	}
	// The renewal intent becomes the host agent's endpoint.renew job: the
	// agent generates the key, the control plane signs its request, the agent
	// deploys and verifies.
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("dispatch the renewal: %v", err)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified)
	successorPEM, err := fixture.ReadFile("listener.crt")
	if err != nil {
		t.Fatal(err)
	}
	successor, err := certinfo.Inspect(successorPEM)
	if err != nil || successor.SHA256Fingerprint == predecessor.SHA256Fingerprint {
		t.Fatalf("the endpoint does not serve a successor: %v", err)
	}

	listed := func() map[string]any {
		t.Helper()
		token := seedScopedTokenSubject(t, h.store, h.tenant, "x3l1-reader-"+time.Now().Format("150405.000000"), "certs:read")
		status, body := secretsReqKey(t, h.servedHarness, http.MethodGet, "/api/v1/endpoints/verifications", token, "", nil)
		if status != http.StatusOK {
			t.Fatalf("endpoint verifications: HTTP %d %s", status, body)
		}
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		for _, item := range list.Items {
			if item["address"] == address && item["vantage"] == "local" {
				return item
			}
		}
		t.Fatalf("the API lists no local verification of %s: %s", address, body)
		return nil
	}
	sameFingerprint := func(a any, b string) bool {
		s, _ := a.(string)
		norm := func(v string) string { return strings.ToLower(strings.ReplaceAll(v, ":", "")) }
		return s != "" && norm(s) == norm(b)
	}

	// The verification saw the replacement; the endpoint waits for the wire.
	item := listed()
	if item["traffic"] != "awaiting" || !sameFingerprint(item["replaced_fingerprint"], predecessor.SHA256Fingerprint) ||
		!sameFingerprint(item["observed_fingerprint"], successor.SHA256Fingerprint) {
		t.Fatalf("after the renewal's verification the API shows %v, want traffic awaiting with the predecessor replaced", item)
	}
	replacedAt, err := time.Parse(time.RFC3339, item["replaced_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.CheckMigrationTrafficOnce(ctx, replacedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if f, err := h.store.GetDiscoveryFinding(ctx, h.tenant, expiringFinding); err != nil || f.TriageStatus == "remediated" {
		t.Fatalf("the observed finding closed on the probe alone: %+v %v", f, err)
	}

	// The window passes without new connections: recorded, nothing closed.
	window := migration.ObservedTrafficWindow(migration.Run{})
	if err := h.srv.CheckMigrationTrafficOnce(ctx, replacedAt.Add(window+time.Second)); err != nil {
		t.Fatal(err)
	}
	if item := listed(); item["traffic"] != "unobserved" || item["traffic_unobserved_since"] == nil {
		t.Fatalf("a quiet window shows %v, want traffic unobserved", item)
	}
	if f, err := h.store.GetDiscoveryFinding(ctx, h.tenant, expiringFinding); err != nil || f.TriageStatus == "remediated" {
		t.Fatalf("the observed finding closed without wire evidence: %+v %v", f, err)
	}

	// New connections present the successor: the evidence closes it.
	newConnections := observe(successor.SHA256Fingerprint, time.Now().Add(time.Second))
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	observed := listed()
	if observed["traffic"] != "observed" || observed["traffic_finding_id"] != newConnections || observed["traffic_observed_at"] == nil ||
		observed["traffic_unobserved_since"] != nil {
		t.Fatalf("after new connections the API shows %v, want traffic observed with finding %s", observed, newConnections)
	}
	closed, err := h.store.GetDiscoveryFinding(ctx, h.tenant, expiringFinding)
	if err != nil || closed.TriageStatus != "remediated" || !strings.Contains(closed.TriageEvidenceRef, "serving") ||
		!strings.Contains(closed.TriageEvidenceRef, "observed connections finding "+newConnections) {
		t.Fatalf("the replaced certificate's finding did not close on both proofs: %+v %v", closed, err)
	}
	// Another pass changes nothing.
	if err := h.srv.CheckMigrationTrafficOnce(ctx, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if again := listed(); again["traffic_observed_at"] != observed["traffic_observed_at"] || again["traffic_finding_id"] != newConnections {
		t.Fatalf("a later pass changed the evidence: %v", again)
	}
}
