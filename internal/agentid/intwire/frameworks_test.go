// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package intwire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	coreapi "trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/broker"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/graph"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	tenantFrameworks = "88888888-8888-8888-8888-888888888888"
	labAgentID       = "agent-frameworks"
	labSPIFFEPrefix  = "spiffe://lab.trstctl.test/agent/"
	// labStatusTTL is the reference tool server's status reuse window in this lab.
	labStatusTTL = 2 * time.Second
)

// TestAGID_ReferenceFrameworks_MCPToolServerAndADKAgent_RealInfra runs the two
// reference integrations under test/interop/agentframeworks against the real
// signer process and the served agent-delegation API: an agent built with Google's
// Agent Development Kit for Go (scripted model) calls a tool server built on the
// official MCP Go SDK, authenticated with a broker-issued agent identity and
// presenting a chain-bound delegated credential. The tool server honors the
// in-scope call, refuses an out-of-scope call and a stolen credential, stops
// honoring the credential within its status window after the delegation is
// revoked, and its audit log shows the delegation chain behind every decision.
func TestAGID_ReferenceFrameworks_MCPToolServerAndADKAgent_RealInfra(t *testing.T) {
	h := newHarness(t, tenantFrameworks)
	issued := h.issueAgent(t, labAgentID, "nonce-frameworks")
	toolserverBin, agentBin := buildReferenceIntegrations(t)
	apiURL, apiCA, token := h.serveRelyingPartyAPI(t)
	ids := newLabIdentities(t, h)
	dir := t.TempDir()

	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	serverCert, serverKey := ids.serverIdentity(t, dir)
	agentCert, agentKey := ids.agentIdentity(t, dir, labAgentID)
	otherCert, otherKey := ids.agentIdentity(t, dir, "agent-intruder")
	credentialFile := write("credential.der", issued.credential.CredentialDER)
	auditFile := filepath.Join(dir, "audit.jsonl")
	config, err := json.Marshal(map[string]any{
		"listen":             "127.0.0.1:0",
		"tls_cert_file":      serverCert,
		"tls_key_file":       serverKey,
		"agent_ca_file":      write("agent-ca.pem", crypto.EncodeCertificatePEM(ids.caDER)),
		"agent_id_prefix":    labSPIFFEPrefix,
		"tenant_id":          h.tenant,
		"pins_file":          filepath.Join(dir, "pins.json"),
		"trstctl_url":        apiURL,
		"trstctl_ca_file":    write("trstctl-ca.pem", apiCA),
		"trstctl_token_file": write("trstctl-token", []byte(token)),
		"status_ttl_seconds": int(labStatusTTL / time.Second),
		"audit_file":         auditFile,
		"policy": map[string]any{
			"approved_agent_stacks": []string{hex.EncodeToString(delegation.AgentStackDigestOf(issued.reprBytes))},
			"tool_manifest":         []string{"search"},
			"operations":            map[string][]string{"agent-worker": {"read"}},
			"tool_operations":       map[string]string{"search": "read", "delete_records": "delete"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	configFile := write("server.json", config)

	// The operator pins the tenant's issuing CA and roots through the API; the pin
	// matches what the signer holds.
	pinOut := runReference(t, toolserverBin, "pin", "--config", configFile)
	var pinned struct {
		SPKI  string `json:"issuing_ca_spki_sha256"`
		Roots int    `json:"root_anchors"`
	}
	if err := json.Unmarshal(pinOut, &pinned); err != nil {
		t.Fatalf("pin output %q: %v", pinOut, err)
	}
	signerCA, err := h.client.AgentIssuingCA(h.ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	signerSPKI, err := crypto.CertificateSubjectPublicKeyInfo(signerCA)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.SPKI != crypto.SHA256Hex(signerSPKI) || pinned.Roots != 1 {
		t.Fatalf("pinned %+v; the signer's issuing CA key is %s", pinned, crypto.SHA256Hex(signerSPKI))
	}

	endpoint := startToolServer(t, toolserverBin, configFile)
	call := func(cert, key, tool, args string) map[string]any {
		t.Helper()
		out := runReference(t, agentBin,
			"--server", endpoint, "--tls-cert", cert, "--tls-key", key, "--server-ca", filepath.Join(dir, "agent-ca.pem"),
			"--credential", credentialFile, "--credential-id", issued.credentialID, "--call", tool, "--args", args)
		var got struct {
			Tool   string         `json:"tool"`
			Answer map[string]any `json:"answer"`
		}
		if err := json.Unmarshal(out, &got); err != nil || got.Tool != tool {
			t.Fatalf("agent output %q: %v", out, err)
		}
		return got.Answer
	}
	refusal := func(answer map[string]any) string {
		msg, _ := answer["error"].(string)
		return msg
	}

	// 1. The agent calls the tool server with its delegated credential.
	if answer := call(agentCert, agentKey, "search", `{"query":"open invoices"}`); refusal(answer) != "" || !strings.Contains(fmt.Sprint(answer["output"]), "result for open invoices") {
		t.Fatalf("the in-scope call was not honored: %v", answer)
	}
	// 2. An out-of-scope call is refused by the relying service.
	if msg := refusal(call(agentCert, agentKey, "delete_records", `{"selector":"all"}`)); !strings.Contains(msg, "refused by the relying service") || !strings.Contains(msg, "tool") {
		t.Fatalf("the out-of-scope call was not refused by the relying service: %q", msg)
	}
	// 3. The credential presented by another agent's identity is refused.
	if msg := refusal(call(otherCert, otherKey, "search", `{"query":"open invoices"}`)); !strings.Contains(msg, "not to the connected agent agent-intruder") {
		t.Fatalf("another agent's use of the credential was not refused: %q", msg)
	}

	// 4. Revoking the delegation stops further calls within the status window: a
	// call that starts once the window has passed since the revocation reached
	// trstctl is refused, whatever the tool server read before.
	directive, err := h.api.Revoke(h.ctx, h.tenant, agidapi.RevokeRequest{Subject: "manager", Reason: "compromise", PublishDownstream: true})
	if err != nil {
		t.Fatal(err)
	}
	h.drain(t, 20)
	revokedAt := time.Now()
	var stoppedAfter time.Duration
	for {
		started := time.Now()
		msg := refusal(call(agentCert, agentKey, "search", `{"query":"open invoices"}`))
		if strings.Contains(msg, "revoked") {
			stoppedAfter = time.Since(revokedAt)
			break
		}
		if msg != "" {
			t.Fatalf("a call after revocation failed for another reason: %q", msg)
		}
		if started.Sub(revokedAt) > labStatusTTL {
			t.Fatalf("a call started %s after the revocation reached trstctl, past the %s status window, was honored", started.Sub(revokedAt), labStatusTTL)
		}
	}
	t.Logf("the tool server stopped honoring the revoked credential %s after the revocation reached trstctl (status window %s)", stoppedAfter, labStatusTTL)

	// 5. The relying service's audit shows the chain behind every decision.
	records := readAudit(t, auditFile)
	wantChain := []string{"root", "manager", labAgentID}
	find := func(match func(auditLine) bool) auditLine {
		t.Helper()
		for _, rec := range records {
			if match(rec) {
				return rec
			}
		}
		t.Fatalf("no audit record matched in %+v", records)
		return auditLine{}
	}
	allowed := find(func(r auditLine) bool { return r.Allowed && r.Tool == "search" })
	if !slices.Equal(allowed.Chain, wantChain) || allowed.Status != "active" || allowed.Agent != labAgentID || allowed.CredentialID != issued.credentialID {
		t.Fatalf("allowed call audit = %+v", allowed)
	}
	outOfScope := find(func(r auditLine) bool { return !r.Allowed && r.Tool == "delete_records" })
	if outOfScope.Operation != "delete" || !strings.Contains(outOfScope.Reason, "manifest") {
		t.Fatalf("out-of-scope audit = %+v", outOfScope)
	}
	intruder := find(func(r auditLine) bool { return !r.Allowed && r.Agent == "agent-intruder" })
	if !strings.Contains(intruder.Reason, "delegated to "+labAgentID) {
		t.Fatalf("stolen-credential audit = %+v", intruder)
	}
	afterRevocation := find(func(r auditLine) bool { return !r.Allowed && r.Status == "revoked" })
	if afterRevocation.DirectiveID != directive.DirectiveID || !slices.Equal(afterRevocation.Chain, wantChain) {
		t.Fatalf("revocation audit = %+v; directive %s", afterRevocation, directive.DirectiveID)
	}
	// trstctl's own record: the chain behind the credential and the evidenced revocation.
	if chain, err := h.api.FetchChain(h.ctx, h.tenant, issued.credentialID); err != nil || chain.Count != 2 {
		t.Fatalf("trstctl's chain for the credential = %+v, %v", chain, err)
	}
	if evidence, err := h.api.RevocationEvidence(h.ctx, h.tenant, directive.DirectiveID); err != nil || !evidence.Terminal {
		t.Fatalf("trstctl's revocation evidence = %+v, %v", evidence, err)
	}
}

type auditLine struct {
	Agent        string   `json:"agent"`
	CredentialID string   `json:"credential_id"`
	Tool         string   `json:"tool"`
	Operation    string   `json:"operation"`
	Allowed      bool     `json:"allowed"`
	Reason       string   `json:"reason"`
	Chain        []string `json:"chain"`
	Status       string   `json:"status"`
	DirectiveID  string   `json:"directive_id"`
}

func readAudit(t *testing.T, path string) []auditLine {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []auditLine
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var rec auditLine
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// serveRelyingPartyAPI serves the agent-delegation API over TLS, with a real API
// token scoped to agents:read for the relying service.
func (h *harness) serveRelyingPartyAPI(t *testing.T) (url string, caPEM []byte, token string) {
	t.Helper()
	licensed, err := agidapi.NewAPIOptionsFactory()(editionseam.LicensedAPIOptionsDeps{
		Store: h.store, Log: h.log, Outbox: h.outbox,
		AGIDRootAnchors: delegation.NewDurableAnchorStore(h.keystore), AGIDAttestors: h.client, AGIDIssuingCA: h.client,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := httptest.NewTLSServer(coreapi.New(h.store, coreorch.NewIdempotency(h.store), nil, licensed...))
	t.Cleanup(served.Close)
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.CreateAPIToken(h.ctx, corestore.APITokenRecord{
		TenantID: h.tenant, TokenHash: hash, Subject: "reference-relying-service", Scopes: []string{string(authz.AgentsRead)},
	}); err != nil {
		t.Fatal(err)
	}
	token = string(raw)
	secret.Wipe(raw)
	return served.URL, crypto.EncodeCertificatePEM(served.Certificate().Raw), token
}

// labIdentities issues the lab's agent identities through trstctl's broker, under
// a CA whose key the real signer holds; attestation is a lab stand-in.
type labIdentities struct {
	caDER  []byte
	signer *signing.RemoteSigner
	broker *broker.Broker
	ctx    context.Context
}

type labAttestor struct{}

func (labAttestor) Method() string { return "lab" }

func (labAttestor) Attest(_ context.Context, payload []byte) (attest.Attestation, error) {
	return attest.Attestation{Subject: string(payload), Selectors: []string{"lab:agent:" + string(payload)}}, nil
}

type labPolicy struct{}

func (labPolicy) Evaluate(context.Context, policy.Input) (policy.Decision, error) {
	return policy.Decision{Allow: true}, nil
}

func newLabIdentities(t *testing.T, h *harness) *labIdentities {
	t.Helper()
	ca, err := h.client.GenerateKeyHandle(h.ctx, crypto.ECDSAP256, "lab-agent-identity-ca")
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := crypto.SelfSignedCACert(ca, "Reference Lab Agent Identity CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	verifier, err := attest.NewVerifier(attest.Config{TenantID: h.tenant, Attestors: []attest.Attestor{labAttestor{}}, Graph: g})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ephemeral.New(ephemeral.Config{
		TenantID: h.tenant, Verifier: verifier, Idem: ephemeral.NewMemoryIdempotencer(),
		Policy: ephemeral.TTLPolicy{Default: 30 * time.Minute},
		Sign: func(_ context.Context, att attest.Attestation, pubDER []byte, ttl time.Duration) ([]byte, error) {
			return crypto.SignSVID(caDER, ca, pubDER, labSPIFFEPrefix+att.Subject, ttl)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.New(broker.Config{TenantID: h.tenant, Issuer: issuer, Policy: labPolicy{}, Graph: g})
	if err != nil {
		t.Fatal(err)
	}
	return &labIdentities{caDER: caDER, signer: ca, broker: b, ctx: h.ctx}
}

// agentIdentity has the broker issue an agent identity for a key generated here
// and writes the certificate and key for the agent process.
func (l *labIdentities) agentIdentity(t *testing.T, dir, agentID string) (certPath, keyPath string) {
	t.Helper()
	pkcs8, key := newLabKey(t)
	issued, err := l.broker.Issue(l.ctx, broker.IssueRequest{
		AgentID: agentID, Method: "lab", Payload: []byte(agentID), PublicKeyDER: key.Public().DER,
		Scopes: []string{"mcp"}, IdempotencyKey: "lab-identity-" + agentID,
	})
	key.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	return writeLabIdentity(t, dir, agentID, crypto.EncodeCertificatePEM(issued.CertDER), pkcs8)
}

// serverIdentity issues the tool server's TLS certificate for 127.0.0.1.
func (l *labIdentities) serverIdentity(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	pkcs8, key := newLabKey(t)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "reference-toolserver", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}, key)
	key.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, err := crypto.SignServerCertFromCSR(l.caDER, l.signer, csr, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return writeLabIdentity(t, dir, "toolserver", chainPEM, pkcs8)
}

func newLabKey(t *testing.T) ([]byte, *crypto.LockedSigner) {
	t.Helper()
	pkcs8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	return pkcs8, key
}

func writeLabIdentity(t *testing.T, dir, name string, certPEM, pkcs8 []byte) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	secret.Wipe(pkcs8)
	return certPath, keyPath
}

// buildReferenceIntegrations builds the two reference binaries from their own
// module, whose framework versions its go.mod pins.
func buildReferenceIntegrations(t *testing.T) (toolserver, agent string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	src := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "test", "interop", "agentframeworks"))
	out := t.TempDir()
	for _, name := range []string{"toolserver", "agent"} {
		cmd := exec.Command("go", "build", "-mod=readonly", "-o", filepath.Join(out, name), "./cmd/"+name)
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off",
			"GOPRIVATE=trstctl.com/*,github.com/ctlplne/*", "GONOPROXY=trstctl.com/*,github.com/ctlplne/*", "GONOSUMDB=trstctl.com/*,github.com/ctlplne/*")
		if built, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build reference %s: %v\n%s", name, err, built)
		}
	}
	return filepath.Join(out, "toolserver"), filepath.Join(out, "agent")
}

func runReference(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, stderr.String())
	}
	return out
}

// startToolServer runs the tool server until the test ends and returns its MCP
// endpoint.
func startToolServer(t *testing.T, bin, configFile string) string {
	t.Helper()
	cmd := exec.Command(bin, "serve", "--config", configFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
	})
	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if line := scanner.Text(); strings.HasPrefix(line, "listening ") {
				lines <- strings.TrimPrefix(line, "listening ")
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case endpoint := <-lines:
		return endpoint
	case <-time.After(30 * time.Second):
		t.Fatalf("the tool server did not start: %s", stderr.String())
		return ""
	}
}
