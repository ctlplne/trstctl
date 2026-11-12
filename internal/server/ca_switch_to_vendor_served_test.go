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
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// P3-L2 part 2: a planned switch to a vendor CA. The endpoint serves a leaf
// trstctl's platform CA issued; the switch names a DigiCert stand-in from the
// external CA registry as the new issuer with its root as the anchor. The
// host trusts that root first, then generates its key and the vendor signs
// its CSR; once the endpoint serves the vendor's chain, the predecessor is
// revoked (superseded) through the platform CA. A start that names no
// available external CA, no vendor root, or both kinds of issuer is refused.
func TestServedPlannedSwitchToAVendorCAP3L2(t *testing.T) {
	ctx := context.Background()
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	const vendorID = "p3l2b-digicert"
	vendor := digicert.New("digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) {
			d.DefaultProfile = "p3l2b-api"
			d.ExternalCAs = append(d.ExternalCAs, ExternalCA{ID: vendorID, Type: "digicert", Name: "DigiCert (stand-in)", CA: vendor})
		})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "p3l2b-test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fixture, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.Close() })
	certPath, keyPath := filepath.Join(root, "listener.crt"), filepath.Join(root, "listener.key")
	trustPath := filepath.Join(root, "next-root.pem")
	const dnsName = "to-vendor-p3l2.test"
	oldCert, oldKey := issueHostPair(t, h, dnsName)
	if err := fixture.WriteFile("listener.crt", oldCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.WriteFile("listener.key", oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	secret.Wipe(oldKey)

	// The endpoint: a real TLS listener over the files the host agent manages,
	// which the test can take down and bring back on the same address.
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := first.Addr().String()
	serve := func(listener net.Listener) func() {
		t.Helper()
		tlsServer, err := mtls.ServerCertFromFiles(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		tlsServer.SetReloadCheckInterval(time.Millisecond)
		httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})} // #nosec G112 -- loopback fixture closed by its stop func (CWE-400)
		done := make(chan error, 1)
		go func() { done <- tlsServer.ServeHTTPS(httpServer, listener) }()
		return func() {
			_ = httpServer.Close()
			if serveErr := <-done; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("p3l2b listener: %v", serveErr)
			}
		}
	}
	t.Cleanup(serve(first))

	targetConfig, err := json.Marshal(map[string]any{
		"executor": "agent", "cert_path": certPath, "key_path": keyPath,
		"required_agent_id": agentRowID(h.tenant, h.agent), "required_agent_role": mtls.AgentRoleHost,
		"verify_address": address, "verify_server_name": dnsName,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "host/p3l2b", Type: "nginx", Config: targetConfig, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "P3-L2 to-vendor owner", "")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(map[string]any{"name": "p3l2b-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "p3l2b-api", spec); err != nil {
		t.Fatal(err)
	}
	attrs, err := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name, "profile_name": "p3l2b-api"})
	if err != nil {
		t.Fatal(err)
	}
	identityID := "40400000-0000-4000-8000-0000000000f6"
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
	if err := h.srv.orch.Transition(ctx, h.tenant, identityID, orchestrator.StateIssued, "issue the certificate the switch replaces"); err != nil {
		t.Fatal(err)
	}
	if dispatched, err := h.srv.DispatchIssuanceOnce(ctx); err != nil || !dispatched {
		t.Fatalf("dispatch predecessor: %v %v", dispatched, err)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified)
	predecessor, err := h.store.ListActiveIssuedCertificatesForIdentity(ctx, h.tenant, owner.ID, dnsName)
	if err != nil || len(predecessor) != 1 {
		t.Fatalf("predecessor: %+v %v", predecessor, err)
	}
	old := predecessor[0]

	// The switch to the vendor: its root first, then its leaf.
	startServedExternalCADispatcher(t, h.servedHarness)
	token := seedScopedTokenSubject(t, h.store, h.tenant, "p3l2b-switch-operator", "keys:read", "keys:write", "certs:issue")
	members := []any{map[string]any{"id": "canary", "ordinal": 1, "members": []any{map[string]any{
		"identity_id": identityID, "agent_id": agentRowID(h.tenant, h.agent), "trust_anchor_path": trustPath,
	}}}}
	for name, body := range map[string]map[string]any{
		"unknown vendor": {"plan_id": "to-vendor", "new_external_ca_id": "no-such-ca", "new_trust_anchor_pem": string(dc.RootPEM()), "waves": members},
		"no vendor root": {"plan_id": "to-vendor", "new_external_ca_id": vendorID, "waves": members},
		"not a CA root":  {"plan_id": "to-vendor", "new_external_ca_id": vendorID, "new_trust_anchor_pem": string(old.CertificatePEM), "waves": members},
		"both issuers":   {"plan_id": "to-vendor", "new_external_ca_id": vendorID, "new_authority_id": "40400000-0000-4000-8000-0000000000aa", "new_trust_anchor_pem": string(dc.RootPEM()), "waves": members},
	} {
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, "p3l2b-refused-"+strings.ReplaceAll(name, " ", "-"), body); status != http.StatusBadRequest {
			t.Fatalf("%s: HTTP %d %s, want 400", name, status, body)
		}
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, "p3l2b-start", map[string]any{
		"plan_id": "to-vendor", "new_external_ca_id": vendorID, "new_trust_anchor_pem": string(dc.RootPEM()),
		"revoke_predecessors": true, "waves": members,
	})
	var started migration.Run
	if status != http.StatusCreated || json.Unmarshal(body, &started) != nil {
		t.Fatalf("start the switch to the vendor: HTTP %d %s", status, body)
	}
	if b := started.Waves[0].Members[0].Binding; b.IssuingAuthoritySource != "external" || b.IssuingAuthorityID != vendorID ||
		string(b.TrustAnchorPEM) != strings.TrimSpace(string(dc.RootPEM())) || b.PredecessorCAID != IssuingCAID() {
		t.Fatalf("member binding = %+v; want the vendor as issuer, its root as anchor and the platform CA revoking", b)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeExecuted) // the vendor root is trusted first
	if installed, err := fixture.ReadFile("next-root.pem"); err != nil || strings.TrimSpace(string(installed)) != strings.TrimSpace(string(dc.RootPEM())) {
		t.Fatalf("the host does not trust the vendor root: %v", err)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified) // the vendor signs the host's CSR; deployed and served
	served, err := fixture.ReadFile("listener.crt")
	if err != nil {
		t.Fatal(err)
	}
	successor, err := certinfo.Inspect(served)
	if err != nil || successor.SHA256Fingerprint == old.Fingerprint || !strings.Contains(successor.Issuer, "DigiCert CertCentral Test CA") {
		t.Fatalf("the endpoint serves %+v (%v); want the vendor-issued successor", successor, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		row, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
		if err != nil {
			t.Fatal(err)
		}
		if row.Run.Status == migration.RunComplete {
			member := row.Run.Waves[0].Members[0]
			if member.Binding.SuccessorFingerprint != cleanFingerprint(successor.SHA256Fingerprint) || member.RevocationVerdict != migration.VerdictVerified {
				t.Fatalf("completed member = %+v", member)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the switch to the vendor is %s/%s: %q", row.Run.Status, row.Run.Waves[0].Phase, row.Run.PauseReason)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), old.Serial); err != nil || !found || !ledger.Revoked() {
		t.Fatalf("the platform-issued predecessor is not revoked at its CA: %+v %v %v", ledger, found, err)
	}
}
