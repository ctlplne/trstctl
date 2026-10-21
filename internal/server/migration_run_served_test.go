// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	c.lastSignErr = err
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
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) { d.DefaultProfile = "migration-acme-only-default" })
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
	for _, item := range []struct {
		name, protocol string
	}{
		{"migration-acme-only-default", "acme"},
		{"migration-api", "api"},
	} {
		spec, err := json.Marshal(map[string]any{
			"name": item.name, "max_validity": "720h", "allowed_protocols": []string{item.protocol},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, item.name, spec); err != nil {
			t.Fatalf("create %s profile: %v", item.name, err)
		}
	}
	attrs, err := json.Marshal(map[string]string{
		"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name,
		"profile_name": "migration-api",
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
	// The predecessor was installed while API issuance was the served default.
	// Change that default after deployment; the migration must preserve the
	// identity's explicit API profile rather than inheriting an ACME-only one.
	h.srv.obHandler.(*issuanceDispatcher).defaultProfile = "migration-api"
	if err := h.srv.orch.Transition(ctx, h.tenant, identityID, orchestrator.StateIssued, "issue migration predecessor"); err != nil {
		t.Fatal(err)
	}
	if dispatched, err := h.srv.DispatchIssuanceOnce(ctx); err != nil || !dispatched {
		t.Fatalf("dispatch migration predecessor: dispatched=%v err=%v", dispatched, err)
	}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified)
	h.srv.obHandler.(*issuanceDispatcher).defaultProfile = "migration-acme-only-default"
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
	// A second enrolled host in this tenant is still the wrong machine for the
	// immutable deployment target. Reject before any migration action is queued.
	const otherHostID = "44444444-4444-4444-8444-44444444a040"
	if err := h.store.UpsertAgent(ctx, store.Agent{
		ID: otherHostID, TenantID: h.tenant, Name: "other-migration-host",
		Status: "active", Roles: []string{mtls.AgentRoleHost},
	}); err != nil {
		t.Fatal(err)
	}
	wrongHostBody := map[string]any{
		"plan_id": "plan-aud40-wrong-host", "new_authority_id": successorAuthority.ID,
		"waves": []any{map[string]any{
			"id": "canary", "ordinal": 1,
			"members": []any{map[string]any{
				"identity_id": identityID, "agent_id": otherHostID,
				"trust_anchor_path": trustPath,
			}},
		}},
	}
	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs", token, "aud40-start-wrong-host", wrongHostBody)
	if statusCode != http.StatusBadRequest || !bytes.Contains(body, []byte("assigned host agent")) {
		t.Fatalf("wrong same-tenant host started migration: %d %s", statusCode, body)
	}
	var wrongHostOutbox int
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE tenant_id=$1 AND idempotency_key LIKE 'migration:%' AND required_agent_id=$2`,
		h.tenant, otherHostID).Scan(&wrongHostOutbox); err != nil || wrongHostOutbox != 0 {
		t.Fatalf("wrong host migration outbox = %d, err=%v", wrongHostOutbox, err)
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
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
	issuance := started.Waves[0].Members[0].Binding.Issuance
	if issuance == nil || issuance.ProfileName != "migration-api" || issuance.ProfileID == "" ||
		issuance.ProfileVersion != 1 || issuance.ProfileSpecDigest == "" {
		t.Fatalf("migration lost identity profile revision before queued issuance: %+v", issuance)
	}
	assertMigrationOutboxCountAUD40(t, h, started.ID, "distribute_trust", 1)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "issue_successor", 0)

	// Pause/resume is durable and cannot duplicate the already-published trust
	// effect. A32: the host agent has already leased the trust job when the
	// operator pauses; the pause recalls it — the lease cannot be extended, a
	// fresh claim finds nothing, and the row says why — and resume lifts the
	// recall so the same required agent claims it afresh below.
	leased, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{agentrelay.KindTrustDistribute}, Limit: 1})
	if err != nil || len(leased.Jobs) != 1 {
		t.Fatalf("lease the published trust job before the pause: jobs=%d err=%v", len(leased.Jobs), err)
	}
	trustJob := leased.Jobs[0]
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs/"+started.ID+"/pause", trustOnlyToken, "aud40-pause", map[string]string{"reason": "operator gate"})
	if statusCode != http.StatusOK || !bytes.Contains(body, []byte(`"status":"paused"`)) {
		t.Fatalf("pause migration = %d %s", statusCode, body)
	}
	if extended, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: trustJob.JobID, Attempt: trustJob.Attempt, Outcome: transport.JobOutcomeExtend,
	}); err != nil || extended.Accepted {
		t.Fatalf("a paused run must refuse the leased job's lease extension: accepted=%v err=%v", extended != nil && extended.Accepted, err)
	}
	if again, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{agentrelay.KindTrustDistribute}, Limit: 1}); err != nil || len(again.Jobs) != 0 {
		t.Fatalf("a recalled job must not be claimable while the run is paused: jobs=%d err=%v", len(again.Jobs), err)
	}
	var recalled bool
	var lastError string
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT agent_recalled_at IS NOT NULL, last_error FROM outbox WHERE tenant_id = $1 AND id = $2`,
		h.tenant, trustJob.JobID).Scan(&recalled, &lastError); err != nil || !recalled || lastError != "migration_paused" {
		t.Fatalf("recalled row: recalled=%t last_error=%q err=%v", recalled, lastError, err)
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
	var claimable bool
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT agent_recalled_at IS NULL AND claimed_by_agent_id IS NULL AND last_error = '' FROM outbox WHERE tenant_id = $1 AND id = $2`,
		h.tenant, trustJob.JobID).Scan(&claimable); err != nil || !claimable {
		t.Fatalf("resume must lift the recall and drop the cut lease: claimable=%t err=%v", claimable, err)
	}

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
	rebuilt, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil || rebuilt.Run.Waves[0].Members[0].Binding.Issuance == nil ||
		*rebuilt.Run.Waves[0].Members[0].Binding.Issuance != *issuance {
		t.Fatalf("projection rebuild lost exact issuance profile: %+v err=%v", rebuilt.Run, err)
	}

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
	var renewalPayload []byte
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		h.tenant, "migration:"+started.ID+":canary:"+identityID+":issue_successor").Scan(&renewalPayload); err != nil {
		t.Fatal(err)
	}
	var renewal RelayDeployIntent
	if err := json.Unmarshal(renewalPayload, &renewal); err != nil || !sameMigrationIssuance(renewal.Issuance, issuance) {
		t.Fatalf("queued successor lost reviewed profile revision: %+v err=%v", renewal.Issuance, err)
	}
	tampered := renewal
	tampered.Issuance = nil
	if err := validateMigrationClaimBinding(started.Waves[0].Members[0].Binding,
		agentRowID(h.tenant, h.agent), migrationReceiptClaim{renew: &tampered}); err == nil {
		t.Fatal("renewal receipt accepted a job with its issuance profile removed")
	}
	if err := h.srv.obHandler.(*issuanceDispatcher).authorizeAgentCSRMigrationBinding(ctx, h.tenant,
		agentRowID(h.tenant, h.agent), tampered); err == nil {
		t.Fatal("signer preflight accepted a job with its issuance profile removed")
	}
	if err := h.srv.obHandler.(*issuanceDispatcher).authorizeAgentCSRMigrationBinding(ctx, h.tenant,
		agentRowID(h.tenant, h.agent), renewal); err != nil {
		t.Fatalf("signer preflight rejected immutable successor job: %v", err)
	}
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
		"required_agent_id": agentRowID(h.tenant, h.agent),
		"verify_address":    staticListener.Addr().String(), "verify_server_name": dnsName,
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

	runOfflineRootMigrationAUD40(t, h, offlineRootMigrationFixture{
		caOperator: caOperator, caApprover: caApprover, token: token, identityID: identityID,
		trustPath: trustPath, dnsName: dnsName, fixture: fixture, channel: channel, profile: profile, state: state,
	})
	runApprovalGatedMigrationAUD40(t, h, token, successorAuthority.ID, identityID, trustPath, offlineRootMigrationFixture{
		channel: channel, profile: profile, state: state,
	})
}

// A40: members under an approval-required profile no longer refuse the run.
// The start becomes the approved operation: the first post records the exact
// request and answers 202, reviewers approve it by intent digest, the same
// start posted again consumes that single-use authority with the run record.
func runApprovalGatedMigrationAUD40(t *testing.T, h *roleHarness, token, authorityID, identityID, trustPath string, f offlineRootMigrationFixture) {
	t.Helper()
	ctx := context.Background()
	profileWriter := seedScopedTokenSubject(t, h.store, h.tenant, "aud40-profile-writer", "profiles:write")
	profileReviewer := seedScopedTokenSubject(t, h.store, h.tenant, "aud40-profile-reviewer", "profiles:write")
	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/profiles", profileWriter, "aud40-profile-approval-version", map[string]any{
		"name": "migration-api", "spec": map[string]any{
			"max_validity": "720h", "allowed_protocols": []string{"api"}, "requires_approval": true,
		},
	})
	if statusCode != http.StatusAccepted {
		t.Fatalf("approval-required profile version = %d %s; want a parked 202", statusCode, body)
	}
	var parked struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(body, &parked); err != nil || parked.ApprovalID == "" {
		t.Fatalf("decode parked profile approval: %v %s", err, body)
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/profiles/approvals/"+parked.ApprovalID+"/approvals",
		profileReviewer, "aud40-profile-approval-review", map[string]string{"reason": "gate migration issuance"})
	if statusCode != http.StatusOK || !bytes.Contains(body, []byte(`"state":"issued"`)) {
		t.Fatalf("approve profile version = %d %s", statusCode, body)
	}

	startBody := map[string]any{
		"plan_id": "plan-aud40-approval", "new_authority_id": authorityID,
		"waves": []any{map[string]any{
			"id": "canary", "ordinal": 1,
			"members": []any{map[string]any{
				"identity_id": identityID, "agent_id": agentRowID(h.tenant, h.agent), "trust_anchor_path": trustPath,
			}},
		}},
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, "aud40-approval-start-1", startBody)
	if statusCode != http.StatusAccepted {
		t.Fatalf("gated start = %d %s; want 202 pending approval", statusCode, body)
	}
	var pending struct {
		Status            string `json:"status"`
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		RequiredApprovals int    `json:"required_approvals"`
	}
	if err := json.Unmarshal(body, &pending); err != nil || pending.Status != "pending_approval" || pending.ApprovalRequestID == "" || pending.IntentDigest == "" {
		t.Fatalf("pending start body = %s (%v)", body, err)
	}
	if runs, err := h.store.SystemPool().Query(ctx, `SELECT 1 FROM outbox WHERE tenant_id=$1 AND idempotency_key LIKE 'migration:%' AND payload::text LIKE '%plan-aud40-approval%'`, h.tenant); err == nil {
		defer runs.Close()
		if runs.Next() {
			t.Fatal("a pending-approval start queued migration work")
		}
	}
	request, err := h.store.GetOperationApproval(ctx, h.tenant, pending.ApprovalRequestID)
	if err != nil || request.ResourceKind != "migration_run" || request.Action != "start" || request.ResourceID != "plan-aud40-approval" {
		t.Fatalf("approval request = %+v err=%v; want migration_run/plan/start", request, err)
	}
	if !strings.Contains(strings.Join(request.EvidenceRefs, "\n"), "member:"+identityID+":profile:migration-api:") {
		t.Fatalf("approval evidence does not freeze the gated member's profile: %v", request.EvidenceRefs)
	}
	for index := 0; index < pending.RequiredApprovals; index++ {
		approver := seedScopedTokenSubject(t, h.store, h.tenant, fmt.Sprintf("aud40-migration-approver-%d", index), "certs:issue")
		statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals",
			approver, fmt.Sprintf("aud40-approval-decision-%d", index), map[string]string{"intent_digest": pending.IntentDigest})
		if statusCode != http.StatusOK && statusCode != http.StatusCreated {
			t.Fatalf("approve migration start (%d) = %d %s", index, statusCode, body)
		}
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, "aud40-approval-start-2", startBody)
	if statusCode != http.StatusCreated {
		t.Fatalf("approved start = %d %s; want 201", statusCode, body)
	}
	var run migration.Run
	if err := json.Unmarshal(body, &run); err != nil || run.Approval == nil || run.Approval.RequestID != pending.ApprovalRequestID {
		t.Fatalf("started run does not carry the consumed approval: %s (%v)", body, err)
	}
	if issuance := run.Waves[0].Members[0].Binding.Issuance; issuance == nil || issuance.ProfileName != "migration-api" || issuance.ProfileVersion < 2 {
		t.Fatalf("member issuance binding = %+v; want the approval-required profile revision frozen in the run", issuance)
	}
	consumed, err := h.store.GetOperationApproval(ctx, h.tenant, pending.ApprovalRequestID)
	if err != nil || consumed.Status != store.ApprovalStatusConsumed {
		t.Fatalf("approval after start = %+v err=%v; want consumed", consumed, err)
	}
	// The same authority cannot start a second run.
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, "aud40-approval-start-3", startBody)
	if statusCode != http.StatusConflict || !bytes.Contains(body, []byte("consumed")) {
		t.Fatalf("a consumed approval started another run: %d %s", statusCode, body)
	}
	// The approved run must keep advancing: every later run record carries the
	// consumed approval as evidence, and the projector must not spend it again
	// (the lab replay found the trust report rejected and the projection tail
	// wedged on exactly that). Trust lands, then the successor is issued and
	// verified against the static listener's failure path as before.
	runAgentPassAUD40(t, f.channel, f.profile, f.state, transport.JobOutcomeExecuted)
	assertMigrationStatusAUD40(t, h, run.ID, migration.RunRunning, migration.PhaseVerifyingLive)
	assertMigrationOutboxCountAUD40(t, h, run.ID, "issue_successor", 1)
}

type offlineRootMigrationFixture struct {
	caOperator, caApprover, token, identityID, trustPath, dnsName string
	fixture                                                       *os.Root
	channel                                                       *servedHostRelayChannel
	profile                                                       connector.LocalOpsConfig
	state                                                         *agentrelay.HostRollbackStore
}

// A migration to an imported offline root (A36): the root cannot sign, so the
// run is refused until a signer-backed intermediate hangs under it; then the
// successor is minted by that intermediate while the host receives the ROOT
// certificate as its trust anchor.
func runOfflineRootMigrationAUD40(t *testing.T, h *roleHarness, f offlineRootMigrationFixture) {
	t.Helper()
	ctx := context.Background()
	offlineRootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(offlineRootKey.Destroy)
	rootProfile := crypto.HierarchyCAProfile{
		CommonName: "AUD40 offline root", MaxPathLen: 1, TTL: 365 * 24 * time.Hour,
		PermittedDNSDomains: []string{f.dnsName}, EKUs: []string{"serverAuth"},
	}
	offlineRoot, err := crypto.SelfSignedHierarchyCA(offlineRootKey, rootProfile)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := string(offlineRoot.CertificatePEM)
	rootSpec := map[string]any{
		"common_name": rootProfile.CommonName, "max_path_len": 1,
		"ttl_seconds":           int64(rootProfile.TTL.Seconds()),
		"permitted_dns_domains": rootProfile.PermittedDNSDomains, "extended_key_usages": rootProfile.EKUs,
		"signature_algorithm": "ecdsa-p256",
	}
	rootCeremony := createCACeremonyWithCertificate(t, h.servedHarness, f.caOperator, "import_offline_root", rootPEM, rootSpec, 1, "aud40-offline-root-ceremony")
	approveCACeremony(t, h.servedHarness, f.caApprover, rootCeremony.ID, 1, "aud40-offline-root-approval")
	root := importOfflineRootCA(t, h.servedHarness, f.caOperator, rootCeremony.ID, rootPEM, rootSpec, "aud40-offline-root-import")
	if root.SignerHandle != "" {
		t.Fatalf("offline root = %+v; want no signer handle", root)
	}

	startBody := map[string]any{
		"plan_id": "plan-aud40-offline", "new_authority_id": root.ID,
		"waves": []any{map[string]any{
			"id": "canary", "ordinal": 1,
			"members": []any{map[string]any{
				"identity_id": f.identityID, "agent_id": agentRowID(h.tenant, h.agent),
				"trust_anchor_path": f.trustPath,
			}},
		}},
	}
	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs", f.token, "aud40-offline-start-no-intermediate", startBody)
	if statusCode != http.StatusBadRequest || !bytes.Contains(body, []byte("signer-backed intermediate")) {
		t.Fatalf("offline root without an issuing intermediate started a migration: %d %s", statusCode, body)
	}

	interSpec := map[string]any{
		"common_name": "AUD40 offline issuing intermediate", "max_path_len": 0,
		"ttl_seconds":           int64((30 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{f.dnsName}, "extended_key_usages": []string{"serverAuth"},
		"signature_algorithm": "ecdsa-p256",
	}
	interCeremony := createCACeremony(t, h.servedHarness, f.caOperator, "create_offline_intermediate", root.ID, interSpec, 1, "aud40-offline-intermediate-ceremony")
	approveCACeremony(t, h.servedHarness, f.caApprover, interCeremony.ID, 1, "aud40-offline-intermediate-approval")
	csr := createOfflineIntermediateCSR(t, h.servedHarness, f.caOperator, root.ID, interCeremony.ID, interSpec, "aud40-offline-intermediate-csr")
	signed, err := crypto.SignIntermediateHierarchyCAFromCSR(offlineRoot.CertificateDER, offlineRootKey, csrDERFromPEMForTest(t, csr.CSRPem), crypto.HierarchyCAProfile{
		CommonName: "AUD40 offline issuing intermediate", MaxPathLen: 0, TTL: 30 * 24 * time.Hour,
		PermittedDNSDomains: []string{f.dnsName}, EKUs: []string{"serverAuth"},
	})
	if err != nil {
		t.Fatal(err)
	}
	inter := importOfflineIntermediateCA(t, h.servedHarness, f.caOperator, root.ID, interCeremony.ID, string(signed.CertificatePEM), interSpec, "aud40-offline-intermediate-import")

	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/migrations/runs", f.token, "aud40-offline-start", startBody)
	if statusCode != http.StatusCreated {
		t.Fatalf("start migration to offline root = %d %s", statusCode, body)
	}
	var run migration.Run
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatal(err)
	}
	binding := run.Waves[0].Members[0].Binding
	if binding.IssuingAuthorityID != inter.ID || !bytes.Equal(bytes.TrimSpace(binding.TrustAnchorPEM), bytes.TrimSpace([]byte(rootPEM))) {
		t.Fatalf("offline-root member binding issuer=%s anchor matches root=%v; want the intermediate to issue and the root as anchor",
			binding.IssuingAuthorityID, bytes.Equal(bytes.TrimSpace(binding.TrustAnchorPEM), bytes.TrimSpace([]byte(rootPEM))))
	}

	// Trust first, then the successor: the host installs the root anchor and
	// the intermediate-signed leaf; the static listener still serves the
	// predecessor, so the live gate fails and the run rolls back as before.
	runAgentPassAUD40(t, f.channel, f.profile, f.state, transport.JobOutcomeExecuted)
	installedTrust, err := f.fixture.ReadFile(filepath.Base(f.trustPath))
	if err != nil || !bytes.Equal(bytes.TrimSpace(installedTrust), bytes.TrimSpace([]byte(rootPEM))) {
		t.Fatalf("installed trust is not the offline root certificate: err=%v", err)
	}
	runAgentPassAUD40(t, f.channel, f.profile, f.state, transport.JobOutcomeVerifyFailed)
	successorPEM, err := f.fixture.ReadFile("listener.crt")
	if err != nil {
		t.Fatal(err)
	}
	successorDER, err := mtls.FirstCertDER(successorPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyLeafSignedByCA(successorDER, caCertDER(t, []byte(signed.CertificatePEM))); err != nil {
		t.Fatalf("successor leaf was not minted by the offline root's intermediate: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(successorDER, caCertDER(t, []byte(rootPEM))); err == nil {
		t.Fatal("successor leaf claims to be signed by the offline root, whose key the control plane never held")
	}
	successorInfo, err := certinfo.Inspect(successorDER)
	if err != nil {
		t.Fatal(err)
	}
	if issued, found, err := h.store.LookupIssuedCert(ctx, h.tenant, inter.ID, successorInfo.SerialNumber); err != nil || !found || issued.Revoked() {
		t.Fatalf("successor responder authority = %+v found=%v err=%v; want the intermediate %s", issued, found, err, inter.ID)
	}
	assertMigrationStatusAUD40(t, h, run.ID, migration.RunRollingBack, migration.PhaseVerifyingLive)
	runAgentPassAUD40(t, f.channel, f.profile, f.state, transport.JobOutcomeVerified)
	runAgentPassAUD40(t, f.channel, f.profile, f.state, transport.JobOutcomeExecuted)
	assertMigrationStatusAUD40(t, h, run.ID, migration.RunRolledBack, migration.PhaseRolledBack)
}

func runAgentPassAUD40(t *testing.T, channel *servedHostRelayChannel, profile connector.LocalOpsConfig, state *agentrelay.HostRollbackStore, wantOutcome string) {
	t.Helper()
	executed, err := agentrelay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), channel,
		http.DefaultClient, profile, nil, nil, state, 1, 120)
	if err != nil || executed != 1 || channel.lastOutcome != wantOutcome || !channel.lastAccepted || channel.lastReportErr != nil {
		t.Fatalf("agent pass = executed %d outcome %q accepted %v reportErr %v signErr %v detail %q err %v; want 1/%q",
			executed, channel.lastOutcome, channel.lastAccepted, channel.lastReportErr,
			channel.lastSignErr, channel.lastDetail, err, wantOutcome)
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
