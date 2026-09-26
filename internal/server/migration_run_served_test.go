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
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// SignJobCSR completes the shipping relay adapter used by the assembled host
// tests. The request carries a public CSR; the response carries only public
// certificate material. The private key never leaves runHostRenew.
func (c *servedHostRelayChannel) SignJobCSR(ctx context.Context, jobID int64, attempt int, csrDER []byte) ([]byte, []byte, string, error) {
	resp, err := c.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: jobID, Attempt: attempt, CSRDER: csrDER,
	})
	if err != nil {
		return nil, nil, "", err
	}
	return resp.CertificatePEM, resp.ChainPEM, resp.Fingerprint, nil
}

// TestServedMigrationTrustBeforeLeafAndRollbackAUD40 is H2's assembled proof.
// The run is started through the authenticated API, survives a projection-loss
// replay, and is then executed by an enrolled host agent over the real mTLS
// channel. The signer uses real UDS transport in the fixture; separate address
// spaces are qualified independently. PostgreSQL and NATS are real, and the
// listener is handshaked after both deploy and rollback.
func TestServedMigrationTrustBeforeLeafAndRollbackAUD40(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost},
		agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "aud40-test", Status: "active",
	}); err != nil {
		t.Fatalf("register active migration agent: %v", err)
	}

	root := t.TempDir()
	fixture, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.Close() })
	certPath := filepath.Join(root, "listener.crt")
	keyPath := filepath.Join(root, "listener.key")
	trustPath := filepath.Join(root, "next-root.pem")
	rollbackDir := filepath.Join(root, "rollback")
	const dnsName = "migration-aud40.test"

	oldCert, oldKey := issueHostPair(t, h, dnsName)
	defer secret.Wipe(oldCert)
	defer secret.Wipe(oldKey)
	if err := fixture.WriteFile("listener.crt", oldCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.WriteFile("listener.key", oldKey, 0o600); err != nil {
		t.Fatal(err)
	}

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
	})} // #nosec G112 -- loopback fixture is closed below (CWE-400)
	serveDone := make(chan error, 1)
	go func() { serveDone <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("migration listener: %v", serveErr)
		}
	})

	targetConfig, err := json.Marshal(map[string]any{
		"executor": "agent", "cert_path": certPath, "key_path": keyPath,
		"required_agent_id": agentRowID(h.tenant, h.agent), "required_agent_role": mtls.AgentRoleHost,
		"verify_address": listener.Addr().String(), "verify_server_name": dnsName,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "host/aud40", Type: "nginx", Config: targetConfig, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "AUD40 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := json.Marshal(map[string]string{
		"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	identityID := "40400000-0000-4000-8000-000000000040"
	// The already-installed source fixture has retained identity history, so a
	// real complete rebuild must reconstruct it together with the migration.
	if _, err := h.srv.orch.EnsureIdentity(ctx, h.tenant, identityID, store.Identity{
		Kind: store.KindX509Certificate, Name: dnsName, OwnerID: owner.ID, Attributes: attrs,
	}); err != nil {
		t.Fatal(err)
	}

	// Establish the predecessor through actual queued issuance and the enrolled
	// host executor. This supplies complete retained history for a cold rebuild.
	state, err := agentrelay.NewHostRollbackStore(rollbackDir, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions:      []connector.LocalAction{{LogicalName: "nginx", Command: "/usr/bin/true", Timeout: 5 * time.Second}},
	}
	channel := &servedHostRelayChannel{client: h.client, identity: h.identity}
	if err := h.srv.orch.Transition(ctx, h.tenant, identityID, orchestrator.StateIssued, "issue migration predecessor"); err != nil {
		t.Fatal(err)
	}
	if dispatched, err := h.srv.DispatchIssuanceOnce(ctx); err != nil || !dispatched {
		t.Fatalf("dispatch migration predecessor: dispatched=%v err=%v", dispatched, err)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified)
	secret.Wipe(oldCert)
	secret.Wipe(oldKey)
	oldCert, err = fixture.ReadFile("listener.crt")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(oldCert)
	oldKey, err = fixture.ReadFile("listener.key")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(oldKey)
	oldInfo, err := certinfo.Inspect(oldCert)
	if err != nil {
		t.Fatal(err)
	}
	predecessor, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, oldInfo.SHA256Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if identity, err := h.store.GetIdentity(ctx, h.tenant, identityID); err != nil || identity.Status != "deployed" {
		t.Fatalf("predecessor was not deployed through the host path: identity=%+v err=%v", identity, err)
	}

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "aud40-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "aud40-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "AUD40 successor root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{dnsName}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, caOperator, "create_root", "", rootSpec, 1, "aud40-root-ceremony")
	approveCACeremony(t, h.servedHarness, caApprover, ceremony.ID, 1, "aud40-root-approval")
	successorAuthority := createRootCA(t, h.servedHarness, caOperator, ceremony.ID, rootSpec, "aud40-root-create")

	trustOnlyToken := seedScopedTokenSubject(t, h.store, h.tenant, "aud40-trust-only", "keys:read", "keys:write")
	token := seedScopedTokenSubject(t, h.store, h.tenant, "aud40-migration-operator", "keys:read", "keys:write", "certs:issue")
	startBody := map[string]any{
		"plan_id": "plan-aud40", "new_authority_id": successorAuthority.ID,
		"waves": []any{map[string]any{
			"id": "canary", "ordinal": 1,
			"members": []any{map[string]any{
				"identity_id": identityID, "agent_id": agentRowID(h.tenant, h.agent),
				"trust_anchor_path": trustPath,
			}},
		}},
	}
	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs", trustOnlyToken, "aud40-start-forbidden", startBody)
	if statusCode != http.StatusForbidden {
		t.Fatalf("start migration without certs:issue = %d %s, want 403", statusCode, body)
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs", token, "aud40-start", startBody)
	if statusCode != http.StatusCreated {
		t.Fatalf("start migration = %d %s", statusCode, body)
	}
	var started migration.Run
	if err := json.Unmarshal(body, &started); err != nil {
		t.Fatalf("decode started run: %v (%s)", err, body)
	}
	if started.Status != migration.RunRunning || started.Waves[0].Phase != migration.PhaseVerifyingTrust {
		t.Fatalf("started run = %+v", started)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "distribute_trust", 1)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "issue_successor", 0)

	// Pause/resume is durable and cannot duplicate the already-published trust
	// effect. Work already leased could still finish; nothing is leased here.
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs/"+started.ID+"/pause", trustOnlyToken, "aud40-pause", map[string]string{"reason": "operator gate"})
	if statusCode != http.StatusOK || !bytes.Contains(body, []byte(`"status":"paused"`)) {
		t.Fatalf("pause migration = %d %s", statusCode, body)
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs/"+started.ID+"/resume", trustOnlyToken, "aud40-resume-forbidden", nil)
	if statusCode != http.StatusForbidden {
		t.Fatalf("resume migration without certs:issue = %d %s, want 403", statusCode, body)
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs/"+started.ID+"/resume", token, "aud40-resume", nil)
	if statusCode != http.StatusOK || !bytes.Contains(body, []byte(`"status":"running"`)) {
		t.Fatalf("resume migration = %d %s", statusCode, body)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "distribute_trust", 1)

	// Confirm the migration projection is missing, then use the supported
	// complete rebuild. Incremental Apply must not ignore retained completion
	// receipts just because one table was manually truncated. Outbox survives.
	if _, err := h.store.SystemPool().Exec(ctx, `TRUNCATE migration_runs`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("migration projection was not absent before rebuild: %v", err)
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("complete migration rebuild: %v", err)
	}
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunRunning, migration.PhaseVerifyingTrust)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "distribute_trust", 1)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "issue_successor", 0)

	const tenantB = "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h.servedHarness, tenantB, "Migration isolation customer")
	tokenB := seedScopedToken(t, h.store, tenantB, "keys:read")
	statusCode, _ = secretsReq(t, h.servedHarness, http.MethodGet,
		"/api/v1/migrations/runs/"+started.ID, tokenB, nil)
	if statusCode != http.StatusNotFound {
		t.Fatalf("tenant B read tenant A migration = %d, want 404", statusCode)
	}

	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeExecuted) // trust readback
	installedTrust, err := fixture.ReadFile("next-root.pem")
	if err != nil || !bytes.Equal(bytes.TrimSpace(installedTrust), bytes.TrimSpace([]byte(successorAuthority.CertificatePEM))) {
		t.Fatalf("installed trust is not the manifest authority certificate: err=%v", err)
	}
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunRunning, migration.PhaseVerifyingLive)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "issue_successor", 1)
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified) // signer + deploy + live probe
	assertHostRenewCustodyReceiptAUD25(t, channel)
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunComplete, migration.PhaseComplete)
	successorPEM, err := fixture.ReadFile("listener.crt")
	if err != nil {
		t.Fatal(err)
	}
	successorDER, err := mtls.FirstCertDER(successorPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyLeafSignedByCA(successorDER, caCertDER(t, []byte(successorAuthority.CertificatePEM))); err != nil {
		t.Fatalf("successor leaf was not minted by the manifest authority: %v", err)
	}
	active, err := h.store.ListActiveIssuedCertificatesForIdentity(ctx, h.tenant, owner.ID, dnsName)
	if err != nil || len(active) != 1 {
		t.Fatalf("active successor inventory = %+v err=%v; want one certificate", active, err)
	}
	if issued, found, err := h.store.LookupIssuedCert(ctx, h.tenant, successorAuthority.ID, active[0].Serial); err != nil || !found || issued.Revoked() {
		t.Fatalf("successor responder authority = %+v found=%v err=%v; want active authority %s", issued, found, err, successorAuthority.ID)
	}

	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs/"+started.ID+"/rollback", token, "aud40-rollback", nil)
	if statusCode != http.StatusOK || !bytes.Contains(body, []byte(`"status":"rolling_back"`)) {
		t.Fatalf("start rollback = %d %s", statusCode, body)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified) // restore predecessor + live probe
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeExecuted) // remove successor trust
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunRolledBack, migration.PhaseRolledBack)

	if _, err := os.Stat(trustPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successor trust remains after rollback: %v", err)
	}
	servedCert, err := fixture.ReadFile("listener.crt")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(servedCert)
	if !bytes.Equal(servedCert, oldCert) {
		t.Fatal("newest-first inverse did not restore the predecessor certificate")
	}
	restored, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, predecessor.Fingerprint)
	if err != nil || restored.Status != "active" {
		t.Fatalf("rollback predecessor inventory = %+v err=%v; want active", restored, err)
	}
	rolledBackSuccessor, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, active[0].Fingerprint)
	if err != nil || rolledBackSuccessor.Status != "superseded" {
		t.Fatalf("rollback successor inventory = %+v err=%v; want superseded", rolledBackSuccessor, err)
	}

	// A signed failed cohort is not left waiting for an operator to notice it.
	// Point verification at a second listener that deliberately keeps serving
	// the predecessor. The successor deploy therefore lands but fails its live
	// gate; the signed mismatch must automatically restore that predecessor and
	// remove successor trust.
	staticCertPath := filepath.Join(root, "static-predecessor.crt")
	staticKeyPath := filepath.Join(root, "static-predecessor.key")
	if err := fixture.WriteFile("static-predecessor.crt", oldCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.WriteFile("static-predecessor.key", oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	staticListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	staticTLS, err := mtls.ServerCertFromFiles(staticCertPath, staticKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	staticHTTP := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})} // #nosec G112 -- loopback fixture is closed below (CWE-400)
	staticDone := make(chan error, 1)
	go func() { staticDone <- staticTLS.ServeHTTPS(staticHTTP, staticListener) }()
	t.Cleanup(func() {
		_ = staticHTTP.Close()
		if serveErr := <-staticDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("static migration listener: %v", serveErr)
		}
	})
	failureConfig, err := json.Marshal(map[string]any{
		"executor": "agent", "cert_path": certPath, "key_path": keyPath,
		"verify_address": staticListener.Addr().String(), "verify_server_name": dnsName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		ID: target.ID, Name: target.Name, Type: target.Type, Config: failureConfig, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs", token, "aud40-failed-start", startBody)
	if statusCode != http.StatusCreated {
		t.Fatalf("start failure-path migration = %d %s", statusCode, body)
	}
	var failedRun migration.Run
	if err := json.Unmarshal(body, &failedRun); err != nil {
		t.Fatal(err)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeExecuted)
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerifyFailed)
	assertHostRenewCustodyReceiptAUD25(t, channel)
	assertMigrationStatusAUD40(t, h, failedRun.ID, migration.RunRollingBack, migration.PhaseVerifyingLive)
	assertMigrationOutboxCountAUD40(t, h, failedRun.ID, "issue_successor", 1)
	assertMigrationOutboxCountAUD40(t, h, failedRun.ID, "rollback_successor", 1)
	assertMigrationOutboxCountAUD40(t, h, failedRun.ID, "remove_trust", 0)
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified)
	assertMigrationOutboxCountAUD40(t, h, failedRun.ID, "remove_trust", 1)
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeExecuted)
	assertMigrationStatusAUD40(t, h, failedRun.ID, migration.RunRolledBack, migration.PhaseRolledBack)
}

func runAgentPassAUD40(t *testing.T, channel *servedHostRelayChannel, profile connector.LocalOpsConfig, state *agentrelay.HostRollbackStore, wantOutcome string) {
	t.Helper()
	executed, err := agentrelay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), channel,
		http.DefaultClient, profile, nil, nil, state, 1, 120)
	if err != nil || executed != 1 || channel.lastOutcome != wantOutcome || !channel.lastAccepted || channel.lastReportErr != nil {
		t.Fatalf("agent pass = executed %d outcome %q accepted %v reportErr %v detail %q err %v; want 1/%q",
			executed, channel.lastOutcome, channel.lastAccepted, channel.lastReportErr,
			channel.lastDetail, err, wantOutcome)
	}
}

func assertHostRenewCustodyReceiptAUD25(t *testing.T, channel *servedHostRelayChannel) {
	t.Helper()
	if channel.lastCredentialFingerprint == "" || channel.lastCustody == nil || !channel.lastCustody.Complete() ||
		channel.lastCustody.Origin != custody.OriginHostAgent || channel.lastCustody.Storage != custody.StorageFile ||
		channel.lastCustody.Exportable != custody.Exportable ||
		channel.lastCustody.GeneratedBy != channel.identity.Identity().CommonName() {
		t.Fatalf("host-renew custody receipt = fingerprint %q record %+v", channel.lastCredentialFingerprint, channel.lastCustody)
	}
}

func assertMigrationStatusAUD40(t *testing.T, h *roleHarness, runID string, status migration.RunStatus, phase migration.Phase) {
	t.Helper()
	row, err := h.store.GetMigrationRun(t.Context(), h.tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Run.Status != status || row.Run.Waves[0].Phase != phase {
		t.Fatalf("migration state = %s/%s, want %s/%s", row.Run.Status, row.Run.Waves[0].Phase, status, phase)
	}
}

func assertMigrationOutboxCountAUD40(t *testing.T, h *roleHarness, runID, action string, want int) {
	t.Helper()
	var got int
	pattern := "migration:" + runID + ":%:" + action + "%"
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key LIKE $2`,
		h.tenant, pattern).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("outbox %s count = %d, want %d", action, got, want)
	}
}
