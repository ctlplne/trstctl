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
	"slices"
	"strings"
	"testing"
	"time"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// P3: a planned CA switch moves an endpoint from the platform CA to a new
// root's issuer. The canary's first live check fails (the endpoint is down):
// the run pauses with nothing revoked. Once the endpoint is back, resuming
// retries exactly that member; the endpoint serves the new chain, and only
// then is the old certificate revoked (superseded) through the CA that issued
// it. Starting the same switch again changes nothing.
func TestServedPlannedCASwitchP3(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) { d.DefaultProfile = "p3-api" })
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "p3-test", Status: "active"}); err != nil {
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
	const dnsName = "ca-switch-p3.test"
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
				t.Errorf("p3 listener: %v", serveErr)
			}
		}
	}
	stop := serve(first)

	targetConfig, err := json.Marshal(map[string]any{
		"executor": "agent", "cert_path": certPath, "key_path": keyPath,
		"required_agent_id": agentRowID(h.tenant, h.agent), "required_agent_role": mtls.AgentRoleHost,
		"verify_address": address, "verify_server_name": dnsName,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "host/p3", Type: "nginx", Config: targetConfig, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "P3 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(map[string]any{"name": "p3-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "p3-api", spec); err != nil {
		t.Fatal(err)
	}
	attrs, err := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name, "profile_name": "p3-api"})
	if err != nil {
		t.Fatal(err)
	}
	identityID := "40400000-0000-4000-8000-0000000000f3"
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

	// The new issuer: a root through the reviewed ceremony.
	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "p3-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "p3-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "P3 new root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{dnsName}, "extended_key_usages": []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, caOperator, "create_root", "", rootSpec, 1, "p3-root-ceremony")
	approveCACeremony(t, h.servedHarness, caApprover, ceremony.ID, 1, "p3-root-approval")
	newRoot := createRootCA(t, h.servedHarness, caOperator, ceremony.ID, rootSpec, "p3-root-create")

	// P3-L4: assessing the switch first says which certificate it would
	// revoke and through which CA. A member no trstctl CA issued a
	// certificate to blocks it, and a plain assessment lists none.
	assessor := seedScopedTokenSubject(t, h.store, h.tenant, "p3l4-assessor", "graph:read")
	noCertID := "40400000-0000-4000-8000-0000000000f4"
	if _, err := h.srv.orch.EnsureIdentity(ctx, h.tenant, noCertID, store.Identity{
		Kind: store.KindX509Certificate, Name: "ca-switch-p3-none.test", OwnerID: owner.ID, Attributes: attrs,
	}); err != nil {
		t.Fatal(err)
	}
	assessBody := map[string]any{
		"plan_id": "switch-p3", "require_full_trust": true, "revoke_predecessors": true,
		"waves": []any{map[string]any{"id": "canary", "ordinal": 1, "members": []any{identityID, noCertID}}},
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/assess", assessor, "p3l4-assess", assessBody)
	var assessed migration.Assessment
	if status != http.StatusOK || json.Unmarshal(body, &assessed) != nil || !assessed.RevokePredecessors || len(assessed.Predecessors) != 2 {
		t.Fatalf("assess the switch: HTTP %d %s", status, body)
	}
	want := migration.Predecessor{Member: identityID, CertificateID: old.ID, Serial: old.Serial,
		Fingerprint: cleanFingerprint(old.Fingerprint), CAID: IssuingCAID(), CAName: "trstctl platform CA", Revocable: true}
	if assessed.Predecessors[0] != want {
		t.Fatalf("the switch would revoke %+v, want %+v", assessed.Predecessors[0], want)
	}
	if none := assessed.Predecessors[1]; none.Member != noCertID || none.Revocable || !strings.Contains(none.Problem, "exactly one active predecessor certificate") {
		t.Fatalf("a member with no certificate: %+v", none)
	}
	var predecessorUnknowns []string
	for _, u := range assessed.Unknowns {
		if u.Kind == migration.UnknownPredecessorNotRevocable {
			predecessorUnknowns = append(predecessorUnknowns, u.Member)
		}
	}
	if len(predecessorUnknowns) != 1 || predecessorUnknowns[0] != noCertID || !slices.Contains(assessed.Waves[0].Blocked, noCertID) {
		t.Fatalf("only the member a switch cannot revoke is blocked for it: %v %+v", predecessorUnknowns, assessed.Waves)
	}
	delete(assessBody, "revoke_predecessors")
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/assess", assessor, "p3l4-assess-plain", assessBody)
	var plain migration.Assessment
	if status != http.StatusOK || json.Unmarshal(body, &plain) != nil || plain.RevokePredecessors || plain.Predecessors != nil {
		t.Fatalf("a plain assessment: HTTP %d %s", status, body)
	}
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), old.Serial); err != nil || !found || ledger.Revoked() {
		t.Fatalf("assessing touched the old certificate: %+v %v %v", ledger, found, err)
	}

	// The endpoint goes down before the switch reaches it.
	stop()
	token := seedScopedTokenSubject(t, h.store, h.tenant, "p3-switch-operator", "keys:read", "keys:write", "certs:issue")
	start := map[string]any{
		"plan_id": "switch-p3", "new_authority_id": newRoot.ID, "revoke_predecessors": true,
		"waves": []any{map[string]any{"id": "canary", "ordinal": 1, "members": []any{map[string]any{
			"identity_id": identityID, "agent_id": agentRowID(h.tenant, h.agent), "trust_anchor_path": trustPath,
		}}}},
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, "p3-start", start)
	var started migration.Run
	if status != http.StatusCreated || json.Unmarshal(body, &started) != nil || !started.RevokePredecessors {
		t.Fatalf("start the switch: HTTP %d %s", status, body)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeExecuted)     // the new root is trusted first
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerifyFailed) // deployed, but the live check fails

	row, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Run.Status != migration.RunPaused || !strings.Contains(row.Run.PauseReason, identityID) {
		t.Fatalf("a failed canary: run %s %q", row.Run.Status, row.Run.PauseReason)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "revoke_predecessor", 0)
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), old.Serial); err != nil || !found || ledger.Revoked() {
		t.Fatalf("the old certificate was touched by a failed canary: %+v %v %v", ledger, found, err)
	}

	// The endpoint is back; resuming retries exactly the failed member.
	again, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	stop = serve(again)
	t.Cleanup(stop)
	if conn, err := net.DialTimeout("tcp", address, 2*time.Second); err != nil {
		t.Fatalf("the endpoint did not come back on %s: %v", address, err)
	} else {
		_ = conn.Close()
	}
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs/"+started.ID+"/resume", token, "p3-resume", nil)
	if status != http.StatusOK {
		t.Fatalf("resume: HTTP %d %s", status, body)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "issue_successor", 1)
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified)

	// The endpoint serves the new chain (the signed live receipt); the old
	// certificate is superseded but not yet revoked.
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunRunning, migration.PhaseRevokingPredecessor)
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), old.Serial); err != nil || !found || ledger.Revoked() {
		t.Fatalf("the old certificate was revoked before the revocation step: %+v %v %v", ledger, found, err)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "revoke_predecessor", 1)
	revoke := incidentRevocationMessageAUD41(t, h, started.ID)
	if err := h.srv.obHandler.Deliver(ctx, revoke); err != nil {
		t.Fatalf("revoke the old certificate: %v", err)
	}
	event, found, err := h.log.EventByID(ctx, orchestrator.MigrationEventID(h.tenant, started.ID, "predecessor-revoked:"+revoke.IdempotencyKey))
	if err != nil || !found || event.Type != projections.EventCertificateRevoked {
		t.Fatalf("revocation event = %+v found %t err %v", event, found, err)
	}
	var revoked projections.CertificateRevoked
	if err := json.Unmarshal(event.Data, &revoked); err != nil {
		t.Fatal(err)
	}
	if revoked.Reason != string(crypto.RevocationReasonSuperseded) || revoked.Fingerprint != old.Fingerprint {
		t.Fatalf("revocation = %+v, want superseded for the old certificate", revoked)
	}
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunComplete, migration.PhaseComplete)
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), old.Serial); err != nil || !found || !ledger.Revoked() {
		t.Fatalf("the old certificate is not revoked at its CA: %+v %v %v", ledger, found, err)
	}

	// Starting the same switch again changes nothing.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, "p3-start", start)
	var replayed migration.Run
	if (status != http.StatusCreated && status != http.StatusOK) || json.Unmarshal(body, &replayed) != nil || replayed.ID != started.ID {
		t.Fatalf("a repeated start: HTTP %d %s", status, body)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "issue_successor", 1)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "revoke_predecessor", 1)
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunComplete, migration.PhaseComplete)
}
