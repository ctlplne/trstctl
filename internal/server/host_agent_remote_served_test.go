// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// servedHostRelayChannel is the shipping agent's transport adapter, kept in
// this assembled test package so the proof crosses the real served gRPC/mTLS
// boundary while executing the same relay runtime as cmd/trstctl-agent.
type servedHostRelayChannel struct {
	client                  *transport.AgentClient
	identity                *agent.Agent
	lastOutcome, lastDetail string
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
	id := c.identity.Identity()
	req, err := transport.SignedReport(id, id.TenantID(), id.CommonName(), jobID, attempt,
		outcome, detail, evidenceDigest, time.Now().UTC().Unix())
	if err != nil {
		return false, err
	}
	resp, err := c.client.ReportJobResult(ctx, req)
	if err != nil {
		return false, err
	}
	return resp.Accepted, nil
}

const aud30HostAgentProcess = "TRSTCTL_AUD30_HOST_AGENT_PROCESS"

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
