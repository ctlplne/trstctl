// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// keycloakLabImage is the pinned authorization-server stand-in for the MCP
// authorization lab; keycloakKeyCacheSeconds is the lifespan of its keys cache,
// which bounds how long it keeps accepting a client key trstctl no longer lists.
const (
	keycloakLabImage        = "quay.io/keycloak/keycloak:26.8.1@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b"
	keycloakKeyCacheSeconds = 5
)

// TestServedMCPAuthorizationWithKeycloak proves MCP authorization with a trstctl
// agent identity against Keycloak as the customer's authorization server. The agent
// (ADK for Go, test/interop/agentframeworks) reaches the reference MCP tool server,
// gets a 401 pointing at protected resource metadata, takes a client credentials
// grant at Keycloak authenticated with a private_key_jwt assertion signed by the key
// of its broker-issued trstctl certificate (Keycloak reads the key from trstctl's
// agent key set), exchanges that token through Keycloak's token exchange for one
// with the tool server's scope and audience, and calls the tool. After the
// certificate is revoked in trstctl, Keycloak refuses the agent a token once its key
// cache refreshes.
func TestServedMCPAuthorizationWithKeycloak(t *testing.T) {
	docker := requireKeycloakLab(t)
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	dir := t.TempDir()

	pkcs8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	body["public_key_pem"] = string(crypto.MarshalPublicKeyPEM(agentKey.Public().DER))
	agentKey.Destroy()
	agentKeyFile := filepath.Join(dir, "agent-key.pem")
	if err := os.WriteFile(agentKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	secret.Wipe(pkcs8)
	issued := servedBrokerIssue(t, h, owner, "a182-agent-identity", body, http.StatusCreated)

	toolPort := freeTCPPort(t)
	resource := fmt.Sprintf("https://127.0.0.1:%d/mcp", toolPort)
	toolCA, toolCert, toolKey := keycloakLabServerIdentity(t, dir)
	trstctlURL, err := url.Parse(h.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	jwksURL := fmt.Sprintf("http://host.docker.internal:%s/agent-keys/%s/agent-7/jwks.json", trstctlURL.Port(), h.tenant)
	keycloak := startKeycloakLab(t, docker, dir, keycloakLabRealm(resource, jwksURL))
	issuer := keycloak + "/realms/agents"

	toolBin, agentBin := buildKeycloakLabReferences(t)
	auditFile := filepath.Join(dir, "audit.jsonl")
	config, err := json.Marshal(map[string]any{
		"listen": fmt.Sprintf("127.0.0.1:%d", toolPort), "tls_cert_file": toolCert, "tls_key_file": toolKey,
		"audit_file": auditFile, "authorization": "oauth",
		"oauth": map[string]any{
			"resource": resource, "issuer": issuer, "jwks_url": issuer + "/protocol/openid-connect/certs",
			"scopes": []string{"mcp:tools"}, "allowed_clients": []string{"agent-7"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "server.json")
	if err := os.WriteFile(configFile, config, 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := startKeycloakLabToolServer(t, toolBin, configFile)
	if endpoint != resource {
		t.Fatalf("tool server endpoint %s, want %s", endpoint, resource)
	}

	type agentResult struct {
		Tool          string           `json:"tool"`
		Answer        map[string]any   `json:"answer"`
		Authorization []map[string]any `json:"authorization"`
	}
	call := func() agentResult {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, agentBin, "--server", resource, "--tls-key", agentKeyFile, "--server-ca", toolCA, // #nosec G204 -- test executes the reference binary it built itself (CWE-78)
			"--oauth-client-id", "agent-7", "--oauth-exchange", "--call", "search", "--args", `{"query":"open invoices"}`)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("agent: %v\n%s", err, stderr.String())
		}
		var got agentResult
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("agent output %q: %v", out, err)
		}
		return got
	}
	steps := func(r agentResult) []string {
		var out []string
		for _, s := range r.Authorization {
			out = append(out, fmt.Sprint(s["step"]))
		}
		return out
	}

	// The agent authenticates with its trstctl identity and calls the tool.
	first := call()
	if msg, _ := first.Answer["error"].(string); msg != "" || !strings.Contains(fmt.Sprint(first.Answer["output"]), "result for open invoices") {
		t.Fatalf("the tool call with a Keycloak token failed: %+v", first)
	}
	if want := []string{"protected-resource-metadata", "authorization-server", "client-credentials", "token-exchange"}; !slices.Equal(steps(first), want) {
		t.Fatalf("authorization steps = %v, want %v", steps(first), want)
	}
	audit, err := os.ReadFile(auditFile) // #nosec G304 -- the test's own TempDir audit log (CWE-22)
	if err != nil || !bytes.Contains(audit, []byte(`"client":"agent-7"`)) || !bytes.Contains(audit, []byte(`"mcp:tools"`)) {
		t.Fatalf("the tool server did not record agent-7's token: %s %v", audit, err)
	}

	// Revoking the agent's certificate in trstctl stops Keycloak issuing it tokens.
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "a182-revoke",
		map[string]any{"certificate_ids": []string{issued.CertificateID}, "reason": "keyCompromise"})
	if status != http.StatusOK {
		t.Fatalf("revoke: HTTP %d %s", status, raw)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	revokedAt := time.Now()
	bound := time.Duration(keycloakKeyCacheSeconds+15) * time.Second
	for {
		started := time.Now()
		r := call()
		msg, _ := r.Answer["error"].(string)
		if strings.Contains(msg, "refused the token request") {
			t.Logf("Keycloak refused the revoked agent a token %s after the revocation reached trstctl (key cache %ds)",
				time.Since(revokedAt).Round(time.Millisecond), keycloakKeyCacheSeconds)
			break
		}
		if msg != "" {
			t.Fatalf("a call after revocation failed for another reason: %q", msg)
		}
		if started.Sub(revokedAt) > bound {
			t.Fatalf("Keycloak still issued the revoked agent a token %s after the revocation", started.Sub(revokedAt))
		}
		time.Sleep(time.Second)
	}
}

// requireKeycloakLab skips when Docker or the pinned image is absent, unless
// TRSTCTL_REQUIRE_KEYCLOAK=1 makes their absence a failure.
func requireKeycloakLab(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("starts a Keycloak container; skipped in -short")
	}
	required := os.Getenv("TRSTCTL_REQUIRE_KEYCLOAK") == "1"
	docker, err := exec.LookPath("docker")
	if err == nil {
		err = exec.Command(docker, "image", "inspect", keycloakLabImage).Run() // #nosec G204 -- test inspects a pinned image with the local docker client (CWE-78)
	}
	if err != nil {
		if required {
			t.Fatalf("TRSTCTL_REQUIRE_KEYCLOAK is set but docker or %s is unavailable: %v", keycloakLabImage, err)
		}
		t.Skipf("the Keycloak lab needs docker and the pinned image (docker pull %s)", keycloakLabImage)
	}
	return docker
}

// keycloakLabRealm is the authorization server's configuration: client agent-7
// authenticates with private_key_jwt against the key set trstctl publishes, may
// exchange its own tokens, and can request mcp:tools, whose tokens carry the tool
// server's canonical URI as audience.
func keycloakLabRealm(resource, jwksURL string) []byte {
	realm, _ := json.Marshal(map[string]any{
		"realm": "agents", "enabled": true, "sslRequired": "none", "accessTokenLifespan": 120,
		"clientScopes": []map[string]any{{
			"name": "mcp:tools", "protocol": "openid-connect",
			"attributes": map[string]string{"include.in.token.scope": "true", "display.on.consent.screen": "false"},
			"protocolMappers": []map[string]any{{
				"name": "mcp-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
				"config": map[string]string{"included.custom.audience": resource, "access.token.claim": "true", "introspection.token.claim": "true"},
			}},
		}},
		"clients": []map[string]any{{
			"clientId": "agent-7", "enabled": true, "publicClient": false, "protocol": "openid-connect",
			"clientAuthenticatorType": "client-jwt", "serviceAccountsEnabled": true,
			"standardFlowEnabled": false, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false,
			"attributes": map[string]string{
				"use.jwks.url": "true", "jwks.url": jwksURL, "token.endpoint.auth.signing.alg": "ES256",
				"standard.token.exchange.enabled": "true",
			},
			"defaultClientScopes": []string{}, "optionalClientScopes": []string{"mcp:tools"},
		}},
	})
	return realm
}

// keycloakLabCacheConfig gives Keycloak's keys cache a lifespan. Keycloak returns
// a client key it holds for the presented key ID without asking the key set
// again, and by default keeps the entry while it is in use, so without a lifespan
// a key trstctl stopped listing would keep authenticating the client.
const keycloakLabCacheConfig = `<?xml version="1.0" encoding="UTF-8"?>
<infinispan xmlns="urn:infinispan:config:16.0">
    <cache-container name="keycloak">
        <local-cache name="keys" simple-cache="true">
            <expiration max-idle="-1" lifespan="%d"/>
            <memory max-count="1000"/>
        </local-cache>
    </cache-container>
</infinispan>
`

// startKeycloakLab runs the pinned Keycloak with the realm imported and a short
// keys cache lifespan, and returns its base URL once the realm answers.
func startKeycloakLab(t *testing.T, docker, dir string, realm []byte) string {
	t.Helper()
	importDir := filepath.Join(dir, "keycloak-import")
	if err := os.MkdirAll(importDir, 0o755); err != nil { // #nosec G301 -- the container's keycloak user must read the import directory (CWE-276)
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(importDir, "agents-realm.json"), realm, 0o644); err != nil { // #nosec G306 -- public realm configuration the container reads (CWE-276)
		t.Fatal(err)
	}
	cacheFile := filepath.Join(dir, "keycloak-cache.xml")
	if err := os.WriteFile(cacheFile, []byte(fmt.Sprintf(keycloakLabCacheConfig, keycloakKeyCacheSeconds*1000)), 0o644); err != nil { // #nosec G306 -- public cache configuration the container reads (CWE-276)
		t.Fatal(err)
	}
	name := fmt.Sprintf("trstctl-a182-keycloak-%d", time.Now().UnixNano())
	args := []string{"run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::8080",
		"--add-host=host.docker.internal:host-gateway", "-v", importDir + ":/opt/keycloak/data/import:ro",
		"-v", cacheFile + ":/opt/keycloak/conf/cache-lab.xml:ro",
		keycloakLabImage, "start-dev", "--import-realm", "--cache-config-file=cache-lab.xml"}
	if out, err := exec.Command(docker, args...).CombinedOutput(); err != nil { // #nosec G204 -- test runs the pinned image with fixed arguments (CWE-78)
		t.Fatalf("start Keycloak: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command(docker, "rm", "-f", name).Run() // #nosec G204 -- test removes the container it started (CWE-78)
	})
	out, err := exec.Command(docker, "port", name, "8080/tcp").Output() // #nosec G204 -- test reads its own container's port (CWE-78)
	if err != nil {
		t.Fatalf("Keycloak port: %v", err)
	}
	base := "http://" + strings.TrimSpace(strings.Split(string(out), "\n")[0])
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/realms/agents/.well-known/openid-configuration") // #nosec G107 -- the lab container's own loopback URL (CWE-88)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		time.Sleep(time.Second)
	}
	logs, _ := exec.Command(docker, "logs", "--tail", "40", name).CombinedOutput() // #nosec G204 -- test reads its own container's logs (CWE-78)
	t.Fatalf("Keycloak did not serve the realm in time:\n%s", logs)
	return ""
}

// keycloakLabServerIdentity issues the tool server's TLS identity for 127.0.0.1
// from a lab CA and returns the CA, certificate chain and key files.
func keycloakLabServerIdentity(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "Reference Lab Tool Server CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "reference-toolserver", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}, key)
	key.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, err := crypto.SignServerCertFromCSR(caDER, ca, csr, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile, certFile, keyFile = filepath.Join(dir, "tool-ca.pem"), filepath.Join(dir, "tool.pem"), filepath.Join(dir, "tool-key.pem")
	for path, data := range map[string][]byte{
		caFile: crypto.EncodeCertificatePEM(caDER), certFile: chainPEM,
		keyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	secret.Wipe(pkcs8)
	return caFile, certFile, keyFile
}

// buildKeycloakLabReferences builds the reference tool server and agent from their
// own module, whose framework versions its go.mod pins.
func buildKeycloakLabReferences(t *testing.T) (toolserver, agent string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	src := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "test", "interop", "agentframeworks"))
	out := t.TempDir()
	for _, name := range []string{"toolserver", "agent"} {
		cmd := exec.Command("go", "build", "-mod=readonly", "-o", filepath.Join(out, name), "./cmd/"+name) // #nosec G204 -- test builds the in-repo reference module (CWE-78)
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off",
			"GOPRIVATE=trstctl.com/*,github.com/ctlplne/*", "GONOPROXY=trstctl.com/*,github.com/ctlplne/*", "GONOSUMDB=trstctl.com/*,github.com/ctlplne/*")
		if built, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build reference %s: %v\n%s", name, err, built)
		}
	}
	return filepath.Join(out, "toolserver"), filepath.Join(out, "agent")
}

// startKeycloakLabToolServer runs the tool server until the test ends and
// returns its MCP endpoint.
func startKeycloakLabToolServer(t *testing.T, bin, configFile string) string {
	t.Helper()
	cmd := exec.Command(bin, "serve", "--config", configFile) // #nosec G204 -- test executes the reference binary it built itself (CWE-78)
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
	}()
	select {
	case endpoint := <-lines:
		return endpoint
	case <-time.After(30 * time.Second):
		t.Fatalf("the tool server did not start: %s", stderr.String())
		return ""
	}
}
