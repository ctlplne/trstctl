// SPDX-License-Identifier: MPL-2.0

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

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedIncidentMigrationGatesRevocationAndRollsBackAUD41 is H3's assembled
// proof. It crosses the authenticated incident API, exact H1 graph edges, H2's
// durable wave aggregate, signer-backed leaf issuance, a real enrolled host
// agent, live TLS readback, the internal revocation worker, and signed audit
// export. No display-only batch state is allowed to authorize an estate effect.
func TestServedIncidentMigrationGatesRevocationAndRollsBackAUD41(t *testing.T) {
	ctx := context.Background()
	auditKey, err := jose.GenerateRSASigningKey("aud41-incident-evidence")
	if err != nil {
		t.Fatalf("generate incident evidence key: %v", err)
	}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) {
			d.EnableRemediation = true
			d.AuditSigningKey = auditKey
		})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: h.agent, Version: "aud41-test", Status: "active",
	}); err != nil {
		t.Fatalf("register active incident agent: %v", err)
	}

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "aud41-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "aud41-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "AUD41 incident replacement root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"success-aud41.test", "failure-aud41.test"},
		"extended_key_usages":   []string{"serverAuth"},
		"signature_algorithm":   "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, caOperator, "create_root", "", rootSpec, 1, "aud41-root-ceremony")
	approveCACeremony(t, h.servedHarness, caApprover, ceremony.ID, 1, "aud41-root-approval")
	replacementAuthority := createRootCA(t, h.servedHarness, caOperator, ceremony.ID, rootSpec, "aud41-root-create")

	ordinaryToken := seedScopedTokenSubject(t, h.store, h.tenant, "aud41-incident-operator",
		string(authz.IncidentsRead), string(authz.IncidentsWrite), string(authz.CertsIssue))
	gameDayToken := seedScopedTokenSubject(t, h.store, h.tenant, "aud41-game-day-commander",
		string(authz.IncidentsRead), string(authz.IncidentsWrite), string(authz.CertsIssue), string(authz.IncidentsGameDay))

	success := newIncidentMigrationFixtureAUD41(t, h, "success", "41410000-0000-4000-8000-000000000041", "production", false)
	failure := newIncidentMigrationFixtureAUD41(t, h, "failure", "41410000-0000-4000-8000-000000000042", "production", true)
	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{success.root, failure.root},
		Actions:      []connector.LocalAction{{LogicalName: "nginx", Command: "/usr/bin/true", Timeout: 5 * time.Second}},
	}
	channel := &servedHostRelayChannel{client: h.client, identity: h.identity}

	gameDayBody := success.startBody(replacementAuthority.ID, migration.IncidentModeGameDay)
	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/incidents/fleet-reissuance-runs", ordinaryToken, "aud41-game-day-no-grant", gameDayBody)
	if statusCode != http.StatusForbidden {
		t.Fatalf("game-day without dedicated grant = %d %s, want 403", statusCode, body)
	}
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/incidents/fleet-reissuance-runs", gameDayToken, "aud41-game-day-production", gameDayBody)
	if statusCode != http.StatusBadRequest || !bytes.Contains(body, []byte("not explicitly non-production")) {
		t.Fatalf("game-day production binding = %d %s, want structural refusal", statusCode, body)
	}

	// The same frozen member is safe only after BOTH ownership and target
	// classifications say test. This is not a UI flag: H2 validates the copied
	// environment inside the aggregate before StartRun can emit any action.
	success.setEnvironment(t, h, "test")
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/incidents/fleet-reissuance-runs", gameDayToken, "aud41-game-day-start", gameDayBody)
	if statusCode != http.StatusCreated {
		t.Fatalf("start safe game-day = %d %s", statusCode, body)
	}
	var rehearsed incidentRunResponseAUD41
	if err := json.Unmarshal(body, &rehearsed); err != nil {
		t.Fatalf("decode game-day run: %v (%s)", err, body)
	}
	if rehearsed.MigrationRunID != rehearsed.ID || rehearsed.Mode != string(migration.IncidentModeGameDay) || rehearsed.PlanDigest == "" {
		t.Fatalf("game-day execution binding = migration %q mode %q digest %q", rehearsed.MigrationRunID, rehearsed.Mode, rehearsed.PlanDigest)
	}
	if len(rehearsed.ExactTrustStoreIDs) != 1 || !sameMembers(rehearsed.ExactTrustHosts, []string{h.agent}) ||
		len(rehearsed.CandidateTrustStoreIDs) == 0 || len(rehearsed.CandidateTrustHosts) == 0 {
		t.Fatalf("H1 plan exact stores/hosts=%v/%v candidates=%v/%v",
			rehearsed.ExactTrustStoreIDs, rehearsed.ExactTrustHosts,
			rehearsed.CandidateTrustStoreIDs, rehearsed.CandidateTrustHosts)
	}
	assertIncidentPlanBeforeMigrationAUD41(t, h, rehearsed.ID)
	assertMigrationOutboxCountAUD40(t, h, rehearsed.ID, "distribute_trust", 1)
	assertMigrationOutboxCountAUD40(t, h, rehearsed.ID, "revoke_predecessor", 0)
	statusCode, _ = secretsReq(t, h.servedHarness, http.MethodGet,
		"/api/v1/incidents/fleet-reissuance-runs/"+rehearsed.ID+"/evidence", gameDayToken, nil)
	if statusCode != http.StatusConflict {
		t.Fatalf("non-terminal evidence = %d, want 409", statusCode)
	}

	runAgentPassAUD40(t, channel, profile, success.rollback, transport.JobOutcomeExecuted)
	assertMigrationStatusAUD40(t, h, rehearsed.ID, migration.RunRunning, migration.PhaseVerifyingLive)
	assertMigrationOutboxCountAUD40(t, h, rehearsed.ID, "revoke_predecessor", 0)
	runAgentPassAUD40(t, channel, profile, success.rollback, transport.JobOutcomeVerified)
	assertMigrationStatusAUD40(t, h, rehearsed.ID, migration.RunRunning, migration.PhaseRevokingPredecessor)
	preRevocation, err := h.store.GetCertificate(ctx, h.tenant, success.predecessor.ID)
	if err != nil || preRevocation.Status != "superseded" {
		t.Fatalf("predecessor before revocation = %+v err=%v; want superseded only", preRevocation, err)
	}
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), success.predecessor.Serial); err != nil || !found || ledger.Revoked() {
		t.Fatalf("ledger mutated before signed live gate worker = %+v found=%v err=%v", ledger, found, err)
	}
	assertMigrationOutboxCountAUD40(t, h, rehearsed.ID, "revoke_predecessor", 1)
	revokeMessage := incidentRevocationMessageAUD41(t, h, rehearsed.ID)
	if err := h.srv.obHandler.Deliver(ctx, revokeMessage); err != nil {
		t.Fatalf("deliver exact predecessor revocation: %v", err)
	}
	assertMigrationStatusAUD40(t, h, rehearsed.ID, migration.RunComplete, migration.PhaseComplete)
	assertIncidentTerminalAUD41(t, h, gameDayToken, rehearsed.ID, success.identityID, "executed")
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), success.predecessor.Serial); err != nil || !found || !ledger.Revoked() {
		t.Fatalf("verified predecessor was not revoked in responder ledger = %+v found=%v err=%v", ledger, found, err)
	}

	// The second, live run deliberately probes a static listener that keeps the
	// predecessor. The agent's signed mismatch must auto-rollback this cohort;
	// no predecessor-revocation intent may ever be published.
	liveBody := failure.startBody(replacementAuthority.ID, migration.IncidentModeLive)
	statusCode, body = secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/incidents/fleet-reissuance-runs", ordinaryToken, "aud41-live-failure-start", liveBody)
	if statusCode != http.StatusCreated {
		t.Fatalf("start live failure path = %d %s", statusCode, body)
	}
	var failed incidentRunResponseAUD41
	if err := json.Unmarshal(body, &failed); err != nil {
		t.Fatalf("decode failed-path run: %v (%s)", err, body)
	}
	runAgentPassAUD40(t, channel, profile, failure.rollback, transport.JobOutcomeExecuted)
	runAgentPassAUD40(t, channel, profile, failure.rollback, transport.JobOutcomeVerifyFailed)
	assertMigrationStatusAUD40(t, h, failed.ID, migration.RunRollingBack, migration.PhaseVerifyingLive)
	assertMigrationOutboxCountAUD40(t, h, failed.ID, "revoke_predecessor", 0)
	assertMigrationOutboxCountAUD40(t, h, failed.ID, "rollback_successor", 1)
	runAgentPassAUD40(t, channel, profile, failure.rollback, transport.JobOutcomeVerified)
	runAgentPassAUD40(t, channel, profile, failure.rollback, transport.JobOutcomeExecuted)
	assertMigrationStatusAUD40(t, h, failed.ID, migration.RunRolledBack, migration.PhaseRolledBack)
	assertMigrationOutboxCountAUD40(t, h, failed.ID, "revoke_predecessor", 0)
	assertIncidentTerminalAUD41(t, h, ordinaryToken, failed.ID, failure.identityID, "rolled_back")
	restored, err := h.store.GetCertificate(ctx, h.tenant, failure.predecessor.ID)
	if err != nil || restored.Status != "active" {
		t.Fatalf("failed cohort predecessor = %+v err=%v; want active after rollback", restored, err)
	}
	if ledger, found, err := h.store.LookupIssuedCert(ctx, h.tenant, IssuingCAID(), failure.predecessor.Serial); err != nil || !found || ledger.Revoked() {
		t.Fatalf("failed cohort predecessor was revoked = %+v found=%v err=%v", ledger, found, err)
	}
}

type incidentMigrationFixtureAUD41 struct {
	root        string
	dnsName     string
	identityID  string
	issuer      store.Issuer
	owner       store.Owner
	target      store.DeploymentTarget
	predecessor store.Certificate
	trustPath   string
	rollback    *agentrelay.HostRollbackStore
}

type incidentRunResponseAUD41 struct {
	ID                     string   `json:"id"`
	MigrationRunID         string   `json:"migration_run_id"`
	Mode                   string   `json:"mode"`
	PlanDigest             string   `json:"plan_digest"`
	ExactTrustStoreIDs     []string `json:"exact_trust_store_ids"`
	ExactTrustHosts        []string `json:"exact_trust_hosts"`
	CandidateTrustStoreIDs []string `json:"candidate_trust_store_ids"`
	CandidateTrustHosts    []string `json:"candidate_trust_hosts"`
}

func newIncidentMigrationFixtureAUD41(
	t *testing.T,
	h *roleHarness,
	label, identityID, environment string,
	failLiveGate bool,
) *incidentMigrationFixtureAUD41 {
	t.Helper()
	ctx := t.Context()
	root := t.TempDir()
	dnsName := label + "-aud41.test"
	certPath := filepath.Join(root, "listener.crt")
	keyPath := filepath.Join(root, "listener.key")
	oldCert, oldKey := issueHostPair(t, h, dnsName)
	t.Cleanup(func() { secret.Wipe(oldCert); secret.Wipe(oldKey) })
	if err := os.WriteFile(certPath, oldCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, oldKey, 0o600); err != nil {
		t.Fatal(err)
	}

	listener := serveReloadingIncidentListenerAUD41(t, certPath, keyPath)
	verifyAddress := listener
	if failLiveGate {
		staticCertPath := filepath.Join(root, "static-predecessor.crt")
		staticKeyPath := filepath.Join(root, "static-predecessor.key")
		if err := os.WriteFile(staticCertPath, oldCert, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(staticKeyPath, oldKey, 0o600); err != nil {
			t.Fatal(err)
		}
		verifyAddress = serveReloadingIncidentListenerAUD41(t, staticCertPath, staticKeyPath)
	}

	targetConfig, err := json.Marshal(map[string]any{
		"executor": "agent", "cert_path": certPath, "key_path": keyPath,
		"verify_address": verifyAddress, "verify_server_name": dnsName,
		"environment": environment,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "host/aud41/" + label, Type: "nginx", Config: targetConfig, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "AUD41 "+label+" owner", "")
	if err != nil {
		t.Fatal(err)
	}
	owner.Environment = environment
	if err := h.store.UpdateOwner(ctx, owner); err != nil {
		t.Fatal(err)
	}
	issuer, err := h.srv.orch.CreateIssuer(ctx, h.tenant, store.Issuer{
		Kind: store.IssuerX509CA, Name: "AUD41 compromised " + label, Chain: []string{string(h.caPEM)}, Internal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := json.Marshal(map[string]string{
		"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuerID := issuer.ID
	if err := h.store.UpsertIdentity(ctx, store.Identity{
		ID: identityID, TenantID: h.tenant, Kind: store.KindX509Certificate,
		Name: dnsName, OwnerID: owner.ID, IssuerID: &issuerID, Status: "deployed", Attributes: attributes,
	}); err != nil {
		t.Fatal(err)
	}
	oldInfo, err := certinfo.Inspect(oldCert)
	if err != nil {
		t.Fatal(err)
	}
	oldDER, err := mtls.FirstCertDER(oldCert)
	if err != nil {
		t.Fatal(err)
	}
	notBefore, notAfter := oldInfo.NotBefore, oldInfo.NotAfter
	predecessor, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{
		OwnerID: &owner.ID, Subject: dnsName, SANs: oldInfo.DNSNames, Issuer: oldInfo.Issuer,
		Serial: oldInfo.SerialNumber, Fingerprint: oldInfo.SHA256Fingerprint,
		KeyAlgorithm: oldInfo.KeyAlgorithm, NotBefore: &notBefore, NotAfter: &notAfter,
		Source: "issued", CertificateDER: oldDER, CertificatePEM: oldCert,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.RecordIssuedCert(ctx, h.tenant, IssuingCAID(), predecessor.Serial, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	caInfo, err := certinfo.Inspect(h.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	exactMeta, _ := json.Marshal(map[string]string{
		"trust_store_kind": "os", "host": h.agent, "platform": "linux",
		"subject": caInfo.Subject, "spki_sha256": caInfo.SPKISHA256,
	})
	candidateHost := "candidate-" + label
	candidateMeta, _ := json.Marshal(map[string]string{
		"trust_store_kind": "java", "host": candidateHost, "profile": "subject-only",
		"subject": caInfo.Subject,
	})
	if _, recorded, rejected, err := h.srv.orch.RecordAgentInventory(ctx, h.tenant, h.agent, "trust-store-"+label,
		[]store.DiscoveryFinding{
			{Kind: "trust-store", Ref: "/etc/ssl/certs/" + label, Fingerprint: caInfo.SHA256Fingerprint, Metadata: exactMeta},
			{Kind: "trust-store", Ref: "/java/cacerts/" + label, Metadata: candidateMeta},
		}); err != nil || recorded != 2 || rejected != 0 {
		t.Fatalf("record H1 inventory = recorded %d rejected %d err=%v", recorded, rejected, err)
	}

	rollback, err := agentrelay.NewHostRollbackStore(filepath.Join(root, "rollback"), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := rollback.RecordDeploy(target.Type, target.ID, predecessor.Fingerprint, oldCert, oldKey); err != nil {
		t.Fatal(err)
	}
	return &incidentMigrationFixtureAUD41{
		root: root, dnsName: dnsName, identityID: identityID, issuer: issuer, owner: owner,
		target: target, predecessor: predecessor, trustPath: filepath.Join(root, "replacement-root.pem"), rollback: rollback,
	}
}

func serveReloadingIncidentListenerAUD41(t *testing.T, certPath, keyPath string) string {
	t.Helper()
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
	})} // #nosec G112 -- loopback test fixture is explicitly closed (CWE-400)
	done := make(chan error, 1)
	go func() { done <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-done; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("incident listener: %v", serveErr)
		}
	})
	return listener.Addr().String()
}

func (f *incidentMigrationFixtureAUD41) setEnvironment(t *testing.T, h *roleHarness, environment string) {
	t.Helper()
	f.owner.Environment = environment
	if err := h.store.UpdateOwner(t.Context(), f.owner); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(f.target.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["environment"] = environment
	updated, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.target.Config = updated
	target, err := h.srv.orch.UpsertDeploymentTarget(t.Context(), h.tenant, f.target)
	if err != nil {
		t.Fatal(err)
	}
	f.target = target
}

func (f *incidentMigrationFixtureAUD41) startBody(authorityID string, mode migration.IncidentMode) map[string]any {
	return map[string]any{
		"issuer_id": f.issuer.ID, "replacement_authority_id": authorityID,
		"mode": mode, "reason": "AUD41 compromised issuer exercise",
		"rollback_ref": "restore the exact predecessor for this cohort",
		"cohorts": []any{map[string]any{
			"id": "canary", "ordinal": 1,
			"members": []any{map[string]any{
				"identity_id": f.identityID, "agent_id": agentRowID(f.owner.TenantID, "role-agent"),
				"trust_anchor_path": f.trustPath,
			}},
		}},
	}
}

func assertIncidentPlanBeforeMigrationAUD41(t *testing.T, h *roleHarness, runID string) {
	t.Helper()
	var planSequence, migrationSequence uint64
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.TenantID != h.tenant || !strings.Contains(string(event.Data), runID) {
			return nil
		}
		switch event.Type {
		case projections.EventIncidentFleetReissuanceRecorded:
			if planSequence == 0 && strings.Contains(string(event.Data), "plan_persisted_before_estate_work") {
				planSequence = event.Sequence
			}
		case projections.EventMigrationRunRecorded:
			if migrationSequence == 0 {
				migrationSequence = event.Sequence
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if planSequence == 0 || migrationSequence == 0 || planSequence >= migrationSequence {
		t.Fatalf("plan/migration event sequence = %d/%d; plan must commit first", planSequence, migrationSequence)
	}
}

func incidentRevocationMessageAUD41(t *testing.T, h *roleHarness, runID string) orchestrator.Message {
	t.Helper()
	var message orchestrator.Message
	pattern := "migration:" + runID + ":%:revoke_predecessor%"
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT id, tenant_id::text, destination, idempotency_key, payload, attempts
		   FROM outbox
		  WHERE tenant_id = $1 AND destination = $2 AND idempotency_key LIKE $3
		  ORDER BY id
		  LIMIT 1`,
		h.tenant, orchestrator.DestinationIncidentMigrationRevoke, pattern).
		Scan(&message.ID, &message.TenantID, &message.Destination, &message.IdempotencyKey, &message.Payload, &message.Attempts); err != nil {
		t.Fatalf("load incident revocation message: %v", err)
	}
	return message
}

func assertIncidentTerminalAUD41(t *testing.T, h *roleHarness, token, runID, identityID, wantStatus string) {
	t.Helper()
	run, err := h.store.GetIncidentFleetReissuanceRun(t.Context(), h.tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != wantStatus || run.EvidenceBundleFormat != "jws" || strings.Count(run.EvidenceBundle, ".") != 2 {
		t.Fatalf("terminal incident = status %q format %q bundle segments %d", run.Status, run.EvidenceBundleFormat, strings.Count(run.EvidenceBundle, "."))
	}
	if _, err := audit.VerifyBundle(run.EvidenceBundle, h.srv.audit.VerificationKeys()); err != nil {
		t.Fatalf("verify incident evidence bundle: %v", err)
	}
	// A delivery may crash after mirroring the terminal H2 state but before its
	// outbox ACK. Replaying that same transition must retain one event and the
	// byte-identical signed bundle; a newly timestamped JWS would make restart
	// evidence depend on where the process died.
	migrationRow, err := h.store.GetMigrationRun(t.Context(), h.tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	mirrorEventID := orchestrator.MigrationEventID(h.tenant, runID,
		fmt.Sprintf("incident-mirror:%d", migrationRow.LastEventSequence))
	if got := countEventIDAUD41(t, h.log, mirrorEventID); got != 1 {
		t.Fatalf("terminal mirror event count before replay = %d, want 1", got)
	}
	sealedBundle := run.EvidenceBundle
	if err := syncIncidentMigrationState(t.Context(), h.store, h.srv.orch, h.srv.audit, h.tenant, migrationRow); err != nil {
		t.Fatalf("replay terminal incident transition: %v", err)
	}
	replayed, err := h.store.GetIncidentFleetReissuanceRun(t.Context(), h.tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.EvidenceBundle != sealedBundle || countEventIDAUD41(t, h.log, mirrorEventID) != 1 {
		t.Fatal("terminal transition replay changed the sealed bundle or appended duplicate evidence")
	}
	tampered := replayed
	tampered.Phase += ":tampered"
	if _, err := h.srv.orch.RecordIncidentFleetReissuanceWithEventID(
		t.Context(), h.tenant, mirrorEventID, tampered,
	); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed terminal evidence under retained event id error = %v, want idempotency conflict", err)
	}
	if wantStatus == "executed" {
		if !sameMembers(run.ReplacementIdentityIDs, []string{identityID}) || !sameMembers(run.RevokedIdentityIDs, []string{identityID}) {
			t.Fatalf("executed identity evidence replacements=%v revoked=%v", run.ReplacementIdentityIDs, run.RevokedIdentityIDs)
		}
	} else if !sameMembers(run.FailedTargets, []string{identityID}) || len(run.RevokedIdentityIDs) != 0 {
		t.Fatalf("rollback evidence failed=%v revoked=%v", run.FailedTargets, run.RevokedIdentityIDs)
	}
	statusCode, body := secretsReq(t, h.servedHarness, http.MethodGet,
		"/api/v1/incidents/fleet-reissuance-runs/"+runID+"/evidence", token, nil)
	if statusCode != http.StatusOK || !bytes.Contains(body, []byte(`"evidence_bundle_format":"jws"`)) {
		t.Fatalf("served terminal evidence = %d %s", statusCode, body)
	}
}

func countEventIDAUD41(t *testing.T, log *events.Log, eventID string) int {
	t.Helper()
	count := 0
	if err := log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.ID == eventID {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func sameMembers(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, value := range got {
		seen[value]++
	}
	for _, value := range want {
		if seen[value] == 0 {
			return false
		}
		seen[value]--
	}
	return true
}
