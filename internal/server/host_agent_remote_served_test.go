// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent"
	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

// servedHostRelayChannel is the shipping agent's transport adapter, kept in
// this assembled test package so the proof crosses the real served gRPC/mTLS
// boundary while executing the same relay runtime as cmd/trstctl-agent.
type servedHostRelayChannel struct {
	client                  *transport.AgentClient
	identity                *agent.Agent
	lastOutcome, lastDetail string
	lastAccepted            bool
	lastReportErr           error
}

func (c servedHostRelayChannel) ClaimJobs(ctx context.Context, kinds []string, limit, leaseSeconds int) ([]agentrelay.Job, error) {
	resp, err := c.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: kinds, Limit: limit, LeaseSeconds: leaseSeconds})
	if err != nil {
		return nil, err
	}
	out := make([]agentrelay.Job, 0, len(resp.Jobs))
	for _, job := range resp.Jobs {
		out = append(out, agentrelay.Job{JobID: job.JobID, Kind: job.Kind, Attempt: job.Attempt, Payload: job.Payload})
	}
	return out, nil
}

func (c servedHostRelayChannel) RedeemJobCredential(ctx context.Context, jobID int64, attempt int) (map[string][]byte, error) {
	resp, err := c.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: attempt})
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(resp.Items))
	for _, item := range resp.Items {
		out[item.Name] = item.Value
	}
	return out, nil
}

func (c *servedHostRelayChannel) ReportJobResult(ctx context.Context, jobID int64, attempt int, outcome, detail, evidenceDigest string) (bool, error) {
	c.lastOutcome, c.lastDetail = outcome, detail
	c.lastAccepted, c.lastReportErr = false, nil
	id := c.identity.Identity()
	req, err := transport.SignedReport(id, id.TenantID(), id.CommonName(), jobID, attempt,
		outcome, detail, evidenceDigest, time.Now().UTC().Unix())
	if err != nil {
		return false, err
	}
	resp, err := c.client.ReportJobResult(ctx, req)
	if err != nil {
		c.lastReportErr = err
		return false, err
	}
	c.lastAccepted = resp.Accepted
	return resp.Accepted, nil
}

const aud30HostAgentProcess = "TRSTCTL_AUD30_HOST_AGENT_PROCESS"
const aud32HostAgentProcess = "TRSTCTL_AUD32_HOST_AGENT_PROCESS"

// TestAUD30HostAgentProcessHelper is intentionally launched by the assembled
// journey below as a second OS process. It reloads the enrolled identity from
// disk, creates its own mTLS connection, and executes the same runtime used by
// trstctl-agent. The parent passes paths and public routing metadata only; no
// credential material is copied through argv or the environment.
func TestAUD30HostAgentProcessHelper(t *testing.T) {
	if os.Getenv(aud30HostAgentProcess) != "1" {
		return
	}
	readRequired := func(name string) string {
		t.Helper()
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			t.Fatalf("helper missing %s", name)
		}
		return value
	}
	caPEM, err := os.ReadFile(readRequired("TRSTCTL_AUD30_AGENT_CA_PATH")) // #nosec G304 -- parent-created test fixture path (CWE-22)
	if err != nil {
		t.Fatalf("read agent CA: %v", err)
	}
	a := agent.New(agent.Config{
		CommonName:  readRequired("TRSTCTL_AUD30_AGENT_COMMON_NAME"),
		KeyPath:     readRequired("TRSTCTL_AUD30_AGENT_KEY_PATH"),
		CertPath:    readRequired("TRSTCTL_AUD30_AGENT_CERT_PATH"),
		ServerName:  readRequired("TRSTCTL_AUD30_AGENT_SERVER_NAME"),
		ServerCAPEM: caPEM,
	}, nil)
	if err := a.Bootstrap(t.Context()); err != nil {
		t.Fatalf("reload persisted identity: %v", err)
	}
	creds, err := a.Credentials()
	if err != nil {
		t.Fatalf("agent credentials: %v", err)
	}
	conn, err := transport.Dial(readRequired("TRSTCTL_AUD30_AGENT_CHANNEL_ADDR"), creds)
	if err != nil {
		t.Fatalf("dial served agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	profile, err := agentrelay.LoadHostProfile(readRequired("TRSTCTL_AUD30_AGENT_HOST_PROFILE"))
	if err != nil {
		t.Fatalf("load host profile: %v", err)
	}
	channel := &servedHostRelayChannel{client: transport.NewAgentClient(conn), identity: a}
	executed, err := agentrelay.RunOnceWithHost(t.Context(), channel, http.DefaultClient, profile, 1, 60)
	if err != nil || executed != 1 {
		t.Fatalf("host pass = (%d, %v), report=%s/%q; want one verified deploy",
			executed, err, channel.lastOutcome, channel.lastDetail)
	}
	if channel.lastOutcome != transport.JobOutcomeVerified {
		t.Fatalf("host agent reported %q detail=%q, want verified", channel.lastOutcome, channel.lastDetail)
	}
}

// TestAUD32HostAgentProcessHelper is one cold-start poll of the shipping host
// runtime. Every parent invocation is a fresh OS process and reopens the same
// encrypted predecessor directory, proving rollback does not depend on memory
// left behind by the deploy process.
func TestAUD32HostAgentProcessHelper(t *testing.T) {
	if os.Getenv(aud32HostAgentProcess) != "1" {
		return
	}
	required := func(name string) string {
		t.Helper()
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			t.Fatalf("helper missing %s", name)
		}
		return value
	}
	caPEM, err := os.ReadFile(required("TRSTCTL_AUD32_AGENT_CA_PATH")) // #nosec G304 -- parent-created public fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	a := agent.New(agent.Config{
		CommonName: required("TRSTCTL_AUD32_AGENT_COMMON_NAME"),
		KeyPath:    required("TRSTCTL_AUD32_AGENT_KEY_PATH"), CertPath: required("TRSTCTL_AUD32_AGENT_CERT_PATH"),
		ServerName: required("TRSTCTL_AUD32_AGENT_SERVER_NAME"), ServerCAPEM: caPEM,
	}, nil)
	if err := a.Bootstrap(t.Context()); err != nil {
		t.Fatalf("reload persisted identity: %v", err)
	}
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(required("TRSTCTL_AUD32_AGENT_CHANNEL_ADDR"), creds)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	profile, err := agentrelay.LoadHostProfile(required("TRSTCTL_AUD32_AGENT_HOST_PROFILE"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := agentrelay.NewHostRollbackStore(required("TRSTCTL_AUD32_AGENT_ROLLBACK_DIR"), a.Identity().TenantID())
	if err != nil {
		t.Fatal(err)
	}
	channel := &servedHostRelayChannel{client: transport.NewAgentClient(conn), identity: a}
	executed, err := agentrelay.RunOnceWithSelfUpgradeAndHostRollback(t.Context(), channel,
		http.DefaultClient, profile, nil, nil, state, 1, 60)
	if err != nil {
		t.Fatalf("cold-start host pass: %v", err)
	}
	wantOutcome := required("TRSTCTL_AUD32_EXPECT_OUTCOME")
	wantExecuted := 1
	if wantOutcome == transport.JobOutcomeVerifyFailed {
		wantExecuted = 0
	}
	if executed != wantExecuted || channel.lastOutcome != wantOutcome {
		t.Fatalf("cold-start host pass executed=%d outcome=%q detail=%q, want %d/%q",
			executed, channel.lastOutcome, channel.lastDetail, wantExecuted, wantOutcome)
	}
}

// TestServedHostAgentOwnsDeployAndReloadsRemoteListenerAUD30 is D1's assembled
// proof. The control-plane worker and host agent see the SAME durable row. The
// worker returns it without opening the seal; the enrolled host agent claims it,
// redeems once, writes a different machine's files, runs its reload action,
// handshakes that machine, and returns a signed verified receipt.
func TestServedHostAgentOwnsDeployAndReloadsRemoteListenerAUD30(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy")

	root := t.TempDir()
	certPath := filepath.Join(root, "listener.crt")
	keyPath := filepath.Join(root, "listener.key")
	reloadMarker := filepath.Join(root, "reload-ran")

	oldCert, oldKey := issueHostPair(t, h, "host-aud30.test")
	defer secret.Wipe(oldCert)
	defer secret.Wipe(oldKey)
	newCert, newKey := issueHostPair(t, h, "host-aud30.test")
	defer secret.Wipe(newCert)
	defer secret.Wipe(newKey)
	if err := os.WriteFile(certPath, oldCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, oldKey, 0o600); err != nil {
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
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })} // #nosec G112 -- loopback fixture is closed below (CWE-400)
	serveDone := make(chan error, 1)
	go func() { serveDone <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("target listener: %v", serveErr)
		}
	})

	targetConfig, err := json.Marshal(map[string]any{
		"cert_path": certPath, "key_path": keyPath,
		"verify_address": listener.Addr().String(), "verify_server_name": "host-aud30.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	const idemKey = "aud30-host-deploy"
	raw, err := json.Marshal(connector.DeployPayload{
		Connector: "nginx", Target: "remote-host-aud30", TargetID: "target-aud30",
		TargetConfig: targetConfig, CertPEM: newCert, KeyPEM: newKey,
		Fingerprint: connector.CertificateFingerprint(newCert),
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := h.srv.sealRelayDeployForTest(ctx, h.tenant, "connector.deploy", idemKey, raw)
	secret.Wipe(raw)
	if err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role)
			 VALUES ($1, 'connector.deploy', $2, $3, 'host') RETURNING id`,
			h.tenant, sealed, idemKey).Scan(&jobID)
	}); err != nil {
		t.Fatal(err)
	}

	// Let the control-plane connector pool get there first. It must refund the
	// attempt and leave the exact row pending for the host rather than touching
	// the local registry or burning retry budget.
	processed, err := h.srv.outbox.DispatchScoped(ctx, h.srv.obHandler,
		orchestrator.DestinationScope{IncludePrefixes: []string{"connector."}})
	if err != nil || processed != 1 {
		t.Fatalf("control-plane sweep = (%d, %v), want one deferred row", processed, err)
	}
	var status string
	var attempts int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, attempts FROM outbox WHERE tenant_id = $1 AND id = $2`, h.tenant, jobID).Scan(&status, &attempts)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attempts != 0 {
		t.Fatalf("after CP sweep row = status %q attempts %d, want pending/0", status, attempts)
	}

	profilePath := filepath.Join(root, "host-profile.json")
	profileJSON, err := json.Marshal(agentrelay.HostProfile{
		AllowedRoots: []string{root},
		Actions: []agentrelay.HostAction{{
			LogicalName: "nginx", Command: "/usr/bin/touch", Args: []string{reloadMarker}, TimeoutSecs: 5,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, profileJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	agentKeyPath := filepath.Join(root, "agent.key")
	agentCertPath := filepath.Join(root, "agent.crt")
	agentCAPath := filepath.Join(root, "agent-ca.crt")
	if err := h.identity.Identity().Save(agentKeyPath, agentCertPath); err != nil {
		t.Fatalf("persist enrolled agent identity: %v", err)
	}
	if err := os.WriteFile(agentCAPath, h.srv.AgentCACertPEM(), 0o644); err != nil { // #nosec G306 -- public CA certificate fixture (CWE-276)
		t.Fatalf("persist agent CA: %v", err)
	}
	processCtx, cancelProcess := context.WithTimeout(ctx, 30*time.Second)
	defer cancelProcess()
	cmd := exec.CommandContext(processCtx, os.Args[0], "-test.run=^TestAUD30HostAgentProcessHelper$", "-test.v") // #nosec G204 -- fixed current test binary and fixed argv (CWE-78)
	cmd.Env = append(os.Environ(),
		aud30HostAgentProcess+"=1",
		"TRSTCTL_AUD30_AGENT_CA_PATH="+agentCAPath,
		"TRSTCTL_AUD30_AGENT_COMMON_NAME="+h.agent,
		"TRSTCTL_AUD30_AGENT_KEY_PATH="+agentKeyPath,
		"TRSTCTL_AUD30_AGENT_CERT_PATH="+agentCertPath,
		"TRSTCTL_AUD30_AGENT_SERVER_NAME="+h.serverName,
		"TRSTCTL_AUD30_AGENT_CHANNEL_ADDR="+h.channelAddr,
		"TRSTCTL_AUD30_AGENT_HOST_PROFILE="+profilePath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		var rowStatus, lastError string
		_ = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status, COALESCE(last_error, '') FROM outbox WHERE tenant_id = $1 AND id = $2`, h.tenant, jobID).Scan(&rowStatus, &lastError)
		})
		_, markerErr := os.Stat(reloadMarker)
		t.Fatalf("separate host-agent process: %v; row=%s/%s marker=%v\n%s", err, rowStatus, lastError, markerErr, output)
	}
	for path, want := range map[string][]byte{certPath: newCert, keyPath: newKey} {
		got, readErr := os.ReadFile(path) // #nosec G304 -- test reads its own remote-host fixture (CWE-22)
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("remote host file %s was not replaced: err=%v", path, readErr)
		}
		secret.Wipe(got)
	}
	if _, err := os.Stat(reloadMarker); err != nil {
		t.Fatalf("host reload action did not run: %v", err)
	}

	// The full binary runs the durable projection tailer. The served harness
	// intentionally does not start background workers, so replay the emitted
	// verification event through the production projection before reading the
	// same state/API the console uses.
	projector := projections.New(h.store)
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == projections.EventEndpointVerified {
			return projector.Apply(ctx, event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	verifications, err := h.store.ListEndpointVerifications(ctx, h.tenant)
	if err != nil || len(verifications) != 1 {
		t.Fatalf("endpoint verifications = %+v, err=%v", verifications, err)
	}
	if !verifications[0].Verified() || verifications[0].AgentCommonName != h.agent ||
		verifications[0].ExpectedFingerprint != connector.CertificateFingerprint(newCert) {
		t.Fatalf("host verification does not bind new cert and agent identity: %+v", verifications[0])
	}
	receipts, err := h.store.ListConnectorDeliveryReceiptsPage(ctx, h.tenant, "", store.ZeroUUID, 20)
	if err != nil {
		t.Fatal(err)
	}
	verifiedReceipt := false
	for _, receipt := range receipts {
		if receipt.IdempotencyKey == idemKey+":verified" && receipt.Connector == "nginx" && receipt.Target == "remote-host-aud30" {
			verifiedReceipt = true
		}
	}
	if !verifiedReceipt {
		t.Fatalf("verified target timeline receipt lost sealed routing metadata: %+v", receipts)
	}
	// Read the same tenant-scoped APIs the Connectors target timeline consumes.
	// Store-only assertions would let a routing field or agent identity disappear
	// at the HTTP boundary while the assembled test still passed.
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:read", "certs:read")
	statusCode, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/deliveries", tok, nil)
	if statusCode != http.StatusOK || !jsonContains(t, body, "remote-host-aud30") || !jsonContains(t, body, "nginx") {
		t.Fatalf("served delivery timeline = status %d body %s", statusCode, body)
	}
	statusCode, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/endpoints/verifications", tok, nil)
	if statusCode != http.StatusOK || !jsonContains(t, body, "target-aud30") || !jsonContains(t, body, h.agent) {
		t.Fatalf("served verification timeline = status %d body %s", statusCode, body)
	}

	statement, signature := executedReceiptForRoleHarness(t, h, jobID)
	if err := mtls.VerifyStatement(h.identity.Identity().CertificateDER(), []byte(statement), signature); err != nil {
		t.Fatalf("stored host receipt does not verify against enrolled agent: %v", err)
	}
	if !strings.Contains(statement, "agent="+h.agent) || !strings.Contains(statement, "outcome="+transport.JobOutcomeVerified) {
		t.Fatalf("stored host receipt does not name executor and verified result:\n%s", statement)
	}
}

// TestServedHostRollbackG1AutomaticAndManualAcrossAgentRestartsAUD32 is the full
// G1 transcript, through the assembled mTLS channel and HTTP console surface.
// A wrong-SAN successor triggers an automatic restore; then the same successor
// is deployed with automation disabled and the operator restores it manually.
// Every execution is a fresh OS process using only its encrypted local ledger.
func TestServedHostRollbackG1AutomaticAndManualAcrossAgentRestartsAUD32(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, "connector.deploy", "connector.rollback")
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "listener.crt"), filepath.Join(root, "listener.key")
	reloadMarker := filepath.Join(root, "reload-ran")
	stateDir := filepath.Join(root, "host-rollbacks")

	firstCert, firstKey := issueHostPair(t, h, "rollback-aud32.test")
	secondCert, secondKey := issueHostPair(t, h, "rollback-aud32.test")
	badCert, badKey := issueHostPair(t, h, "wrong-san-aud32.test")
	defer secret.Wipe(firstCert)
	defer secret.Wipe(firstKey)
	defer secret.Wipe(secondCert)
	defer secret.Wipe(secondKey)
	defer secret.Wipe(badCert)
	defer secret.Wipe(badKey)
	if err := os.WriteFile(certPath, firstCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, firstKey, 0o600); err != nil {
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
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })} // #nosec G112 -- loopback fixture closed below (CWE-400)
	serveDone := make(chan error, 1)
	go func() { serveDone <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("target listener: %v", serveErr)
		}
	})

	targetConfig := func(auto bool) json.RawMessage {
		raw, marshalErr := json.Marshal(map[string]any{
			"cert_path": certPath, "key_path": keyPath,
			"verify_address": listener.Addr().String(), "verify_server_name": "rollback-aud32.test",
			"auto_rollback_on_verify_failure": auto,
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return raw
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "host/aud32", Type: "nginx", Config: targetConfig(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "AUD32 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "rollback-aud32.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	recordCertificate := func(certPEM []byte) store.Certificate {
		t.Helper()
		info, inspectErr := certinfo.Inspect(certPEM)
		if inspectErr != nil {
			t.Fatal(inspectErr)
		}
		notBefore, notAfter := info.NotBefore, info.NotAfter
		return store.Certificate{
			OwnerID: &owner.ID, Subject: identity.Name, SANs: info.DNSNames, Issuer: info.Issuer,
			Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm,
			NotBefore: &notBefore, NotAfter: &notAfter, Source: "issued", CertificatePEM: certPEM,
		}
	}
	first, err := h.srv.orch.RecordCertificate(ctx, h.tenant, recordCertificate(firstCert))
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.srv.orch.RecordSuccessorCertificate(ctx, h.tenant, recordCertificate(secondCert), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := h.srv.orch.RecordSuccessorCertificate(ctx, h.tenant, recordCertificate(badCert), second.ID)
	if err != nil {
		t.Fatal(err)
	}

	profilePath := filepath.Join(root, "host-profile.json")
	profileJSON, err := json.Marshal(agentrelay.HostProfile{
		AllowedRoots: []string{root},
		Actions:      []agentrelay.HostAction{{LogicalName: "nginx", Command: "/usr/bin/touch", Args: []string{reloadMarker}, TimeoutSecs: 5}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, profileJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	agentKeyPath, agentCertPath, agentCAPath := filepath.Join(root, "agent.key"), filepath.Join(root, "agent.crt"), filepath.Join(root, "agent-ca.crt")
	if err := h.identity.Identity().Save(agentKeyPath, agentCertPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentCAPath, h.srv.AgentCACertPEM(), 0o644); err != nil { // #nosec G306 -- public CA fixture (CWE-276)
		t.Fatal(err)
	}
	runColdAgent := func(wantOutcome string) {
		t.Helper()
		processCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(processCtx, os.Args[0], "-test.run=^TestAUD32HostAgentProcessHelper$", "-test.v") // #nosec G204 -- fixed current test binary and argv (CWE-78)
		cmd.Env = append(os.Environ(),
			aud32HostAgentProcess+"=1",
			"TRSTCTL_AUD32_AGENT_CA_PATH="+agentCAPath,
			"TRSTCTL_AUD32_AGENT_COMMON_NAME="+h.agent,
			"TRSTCTL_AUD32_AGENT_KEY_PATH="+agentKeyPath,
			"TRSTCTL_AUD32_AGENT_CERT_PATH="+agentCertPath,
			"TRSTCTL_AUD32_AGENT_SERVER_NAME="+h.serverName,
			"TRSTCTL_AUD32_AGENT_CHANNEL_ADDR="+h.channelAddr,
			"TRSTCTL_AUD32_AGENT_HOST_PROFILE="+profilePath,
			"TRSTCTL_AUD32_AGENT_ROLLBACK_DIR="+stateDir,
			"TRSTCTL_AUD32_EXPECT_OUTCOME="+wantOutcome,
		)
		if output, runErr := cmd.CombinedOutput(); runErr != nil {
			t.Fatalf("cold agent process: %v\n%s", runErr, output)
		}
	}
	enqueueDeploy := func(idem string, certPEM, keyPEM []byte, fingerprint string, cfg json.RawMessage) int64 {
		t.Helper()
		raw, marshalErr := json.Marshal(connector.DeployPayload{
			IdentityID: identity.ID, Connector: "nginx", Target: "host/aud32", TargetID: target.ID,
			TargetRevision: target.RevisionID, TargetConfig: cfg, CertPEM: certPEM, KeyPEM: keyPEM,
			Fingerprint: fingerprint,
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		sealed, sealErr := h.srv.sealRelayDeployForTest(ctx, h.tenant, "connector.deploy", idem, raw)
		secret.Wipe(raw)
		if sealErr != nil {
			t.Fatal(sealErr)
		}
		var jobID int64
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`INSERT INTO outbox
				        (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role)
				 VALUES ($1, 'connector.deploy', $2, $3, $4, 'host') RETURNING id`,
				h.tenant, sealed, idem, orchestrator.ConnectorTargetEffectLane(target.ID)).Scan(&jobID)
		}); err != nil {
			t.Fatal(err)
		}
		return jobID
	}

	enqueueDeploy("aud32-first", firstCert, firstKey, first.Fingerprint, target.Config)
	runColdAgent(transport.JobOutcomeVerified)
	enqueueDeploy("aud32-second", secondCert, secondKey, second.Fingerprint, target.Config)
	runColdAgent(transport.JobOutcomeVerified)
	badJob := enqueueDeploy("aud32-bad-auto", badCert, badKey, bad.Fingerprint, target.Config)
	runColdAgent(transport.JobOutcomeVerifyFailed)

	var rollbackJobID int64
	var requiredRole, requiredAgentID, lane string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, required_agent_role, required_agent_id::text, effect_lane
			   FROM outbox
			  WHERE tenant_id = $1 AND destination = 'connector.rollback' AND status = 'pending'`, h.tenant).
			Scan(&rollbackJobID, &requiredRole, &requiredAgentID, &lane)
	}); err != nil {
		t.Fatalf("automatic rollback was not queued after wrong-SAN deploy %d: %v", badJob, err)
	}
	if requiredRole != "host" || requiredAgentID != agentRowID(h.tenant, h.agent) || lane != orchestrator.ConnectorTargetEffectLane(target.ID) {
		t.Fatalf("automatic rollback routing role=%q agent=%q lane=%q", requiredRole, requiredAgentID, lane)
	}
	runColdAgent(transport.JobOutcomeVerified)
	assertFileEquals(t, certPath, secondCert)

	// Put the wrong-SAN successor back with automation disabled, then drive the
	// exact same restore from the console mutation.
	target, err = h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		ID: target.ID, Name: target.Name, Type: target.Type, Config: targetConfig(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	enqueueDeploy("aud32-bad-manual", badCert, badKey, bad.Fingerprint, target.Config)
	runColdAgent(transport.JobOutcomeVerifyFailed)
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:read", "connectors:write", "certs:read", "identities:read")
	statusCode, body := secretsReqKey(t, h.servedHarness, http.MethodPost,
		"/api/v1/connectors/targets/"+target.ID+"/rollback", tok, "aud32-manual-rollback",
		map[string]any{"identity_id": identity.ID, "reason": "AUD32 manual console restore"})
	if statusCode != http.StatusOK || !jsonContains(t, body, servedstatus.ConnectorRollbackQueued) {
		t.Fatalf("manual rollback: status=%d body=%s", statusCode, body)
	}
	var manualReceipt struct {
		RollbackRef string `json:"rollback_ref"`
	}
	if err := json.Unmarshal(body, &manualReceipt); err != nil {
		t.Fatalf("decode manual rollback receipt: %v body=%s", err, body)
	}
	if !strings.Contains(manualReceipt.RollbackRef, "exact enrolled host-agent") ||
		!strings.Contains(manualReceipt.RollbackRef, second.Fingerprint) ||
		strings.Contains(manualReceipt.RollbackRef, "re-bind") {
		t.Fatalf("manual host rollback describes the wrong execution model: %q", manualReceipt.RollbackRef)
	}
	runColdAgent(transport.JobOutcomeVerified)
	assertFileEquals(t, certPath, secondCert)

	// The signed event binds the whole G1 transcript, while the target timeline
	// gives the operator the human-readable verified result.
	var transcript map[string]any
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID != h.tenant || event.Type != "agent.job.executed" {
			return nil
		}
		var candidate map[string]any
		if json.Unmarshal(event.Data, &candidate) == nil {
			storedID, ok := candidate["job_id"].(float64)
			if ok && int64(storedID) == rollbackJobID {
				transcript = candidate
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"agent": h.agent, "connector": "nginx", "target_id": target.ID,
		"predecessor_fingerprint": second.Fingerprint, "successor_fingerprint": bad.Fingerprint,
		"required_agent_id": agentRowID(h.tenant, h.agent), "required_agent_role": "host",
	} {
		if got, _ := transcript[field].(string); got != want {
			t.Fatalf("G1 transcript %s=%q, want %q: %+v", field, got, want, transcript)
		}
	}
	statement, signature := executedReceiptForRoleHarness(t, h, rollbackJobID)
	if err := mtls.VerifyStatement(h.identity.Identity().CertificateDER(), []byte(statement), signature); err != nil {
		t.Fatalf("G1 rollback receipt signature: %v", err)
	}
	for _, field := range []string{
		"tenant=" + h.tenant,
		"agent=" + h.agent,
		fmt.Sprintf("job=%d", rollbackJobID),
		// Automatic and manual rollback intentionally reuse one durable job.
		// The manual execution is claim generation two, proving a signed
		// attempt-one receipt cannot be replayed after the row is re-armed.
		"attempt=2",
		"outcome=" + transport.JobOutcomeVerified,
	} {
		if !strings.Contains(statement, field+"\n") {
			t.Fatalf("G1 receipt does not bind %q:\n%s", field, statement)
		}
	}
	receipts, err := h.store.ListConnectorDeliveryReceiptsPage(ctx, h.tenant, "", store.ZeroUUID, 100)
	if err != nil {
		t.Fatal(err)
	}
	var verifiedRollback bool
	for _, receipt := range receipts {
		if receipt.Destination == "connector.rollback" && receipt.Status == servedstatus.ConnectorRolledBack &&
			receipt.Reason == "rolled_back_and_reverified" && strings.Contains(receipt.Detail, h.agent) {
			verifiedRollback = true
		}
	}
	if !verifiedRollback {
		t.Fatalf("target timeline has no agent-bound reverified rollback: %+v", receipts)
	}
}

func assertFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path) // #nosec G304 -- test-owned target fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(got)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s does not contain the expected predecessor", path)
	}
}

func issueHostPair(t *testing.T, h *roleHarness, dnsName string) ([]byte, []byte) {
	t.Helper()
	key, err := crypto.GenerateHostSubjectKey(dnsName, []string{dnsName})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	certPEM, err := h.srv.IssueLeaf(t.Context(), key.CSRDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, keyPEM
}

func executedReceiptForRoleHarness(t *testing.T, h *roleHarness, jobID int64) (string, []byte) {
	t.Helper()
	var statement, encoded string
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.TenantID != h.tenant || e.Type != "agent.job.executed" {
			return nil
		}
		var payload map[string]any
		if json.Unmarshal(e.Data, &payload) != nil {
			return nil
		}
		storedID, ok := payload["job_id"].(float64)
		if !ok || int64(storedID) != jobID {
			return nil
		}
		statement, _ = payload["receipt_statement"].(string)
		encoded, _ = payload["receipt_signature"].(string)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || statement == "" || len(signature) == 0 {
		t.Fatalf("stored receipt is incomplete: statement=%q signature=%d err=%v", statement, len(signature), err)
	}
	return statement, signature
}
