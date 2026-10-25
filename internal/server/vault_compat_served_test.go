// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

func TestVaultTokenLookupReportsServedTokenExpiry(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Vault token TTL tenant")
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(10 * time.Minute)
	if _, err := h.store.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: h.tenant, TokenHash: hash, Subject: "vault-ttl-test",
		Scopes: []string{"secrets:read"}, ExpiresAt: &expires,
	}); err != nil {
		t.Fatal(err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	status, body := doBearer(t, h.ts, http.MethodGet, "/v1/auth/token/lookup-self", token, "", nil)
	if status != http.StatusOK {
		t.Fatalf("token lookup status=%d body=%s", status, body)
	}
	var result struct {
		Data struct {
			TTL int `json:"ttl"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.TTL < 590 || result.Data.TTL > 600 {
		t.Fatalf("Vault token TTL=%d, want remaining token lifetime", result.Data.TTL)
	}
}

// TestVaultCLICompatibilityAgainstServedHandler is VAULT-01's stock-client proof:
// the real HashiCorp Vault CLI drives the served trstctl handler through the common
// migration-capture subset: token login/lookup, KV v2 write/read, and PKI issue.
// The test intentionally uses the binary CLI rather than an in-process client so the
// compatibility shim must satisfy the same HTTP shape operators already script.
func TestVaultCLICompatibilityAgainstServedHandler(t *testing.T) {
	vault := vaultCLIBinary(t)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Vault compatibility stock-client tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	home := t.TempDir()

	runVault(t, vault, home, h.ts.URL, token, "login", "-no-store", token)

	firstPut := runVault(t, vault, home, h.ts.URL, token,
		"kv", "put", "secret/trstctl-vault",
		"username=app",
		"password=vault-compat-s3cr3t",
	)
	replayedPut := runVault(t, vault, home, h.ts.URL, token,
		"kv", "put", "secret/trstctl-vault",
		"username=app", "password=vault-compat-s3cr3t")
	if string(firstPut) != string(replayedPut) {
		t.Fatal("stock CLI exact KV retry did not replay the original response")
	}
	kvRaw := runVault(t, vault, home, h.ts.URL, token,
		"kv", "get", "-format=json", "secret/trstctl-vault",
	)
	var kv struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(kvRaw, &kv); err != nil {
		t.Fatalf("decode vault kv get output: %v\n%s", err, kvRaw)
	}
	if kv.Data.Data["username"] != "app" || kv.Data.Data["password"] != "vault-compat-s3cr3t" {
		t.Fatalf("vault kv read returned %+v, want stored username/password", kv.Data.Data)
	}

	pkiRaw := runVault(t, vault, home, h.ts.URL, token,
		"write", "-format=json", "pki/issue/trstctl", "common_name=svc.vault.test", "ttl=1h",
	)
	pkiReplay := runVault(t, vault, home, h.ts.URL, token,
		"write", "-format=json", "pki/issue/trstctl", "common_name=svc.vault.test", "ttl=1h")
	if string(pkiRaw) != string(pkiReplay) {
		t.Fatal("stock CLI exact PKI retry minted a different certificate")
	}
	var issued struct {
		Data struct {
			Serial      string `json:"serial_number"`
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"private_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(pkiRaw, &issued); err != nil {
		t.Fatalf("decode vault pki issue output: %v\n%s", err, pkiRaw)
	}
	if issued.Data.Serial == "" || !strings.Contains(issued.Data.Certificate, "BEGIN CERTIFICATE") || !strings.Contains(issued.Data.PrivateKey, "BEGIN PRIVATE KEY") {
		t.Fatalf("vault pki issue returned incomplete keypair metadata: serial=%q cert=%d key=%d",
			issued.Data.Serial, len(issued.Data.Certificate), len(issued.Data.PrivateKey))
	}

	if !h.hasEvent(t, "secret.created") || !h.hasEvent(t, "pkisecret.issued") {
		t.Fatal("Vault CLI compatibility did not drive the event-sourced served secret + PKI paths")
	}
	if h.logContains(t, "vault-compat-s3cr3t") || h.logContains(t, issued.Data.PrivateKey) || h.logContains(t, "PRIVATE KEY") {
		t.Fatal("Vault compatibility leaked secret material into the event log")
	}
}

// The tenant's control-plane key generation switch refuses Vault's pki/issue,
// which generates the key in the control plane, and the refusal names pki/sign.
// The stock CLI reads only Vault's own error shape ({"errors": [...]}): the
// refusal reached it as problem+json, so it printed "Errors:" with nothing after
// it and the operator never learned why or what to use instead.
func TestVaultCLIShowsWhyPKIIssueIsRefused(t *testing.T) {
	vault := vaultCLIBinary(t)
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "Vault refusal stock-client tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "access:read", "access:write")
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", token, "vault-keygen-off",
		map[string]any{"enabled": false, "reason": "requesters bring their own keys"}); status != http.StatusOK {
		t.Fatalf("turn control-plane key generation off = %d %s", status, body)
	}

	out := runVaultExpectingFailure(t, vault, t.TempDir(), h.ts.URL, token,
		"write", "pki/issue/trstctl", "common_name=svc.vault.test", "ttl=1h")
	if !strings.Contains(string(out), "pki/sign") || !strings.Contains(string(out), "key generation is off") {
		t.Fatalf("stock vault CLI refusal = %s, want the reason naming pki/sign", out)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, h.ts.URL+"/v1/pki/issue/default",
		strings.NewReader(`{"common_name":"raw.vault.test","ttl":"1h"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Idempotency-Key", "vault-refusal-shape")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var shaped struct {
		Errors []string `json:"errors"`
	}
	if resp.StatusCode != http.StatusConflict || json.Unmarshal(raw, &shaped) != nil || len(shaped.Errors) != 1 ||
		!strings.Contains(shaped.Errors[0], "pki/sign") {
		t.Fatalf("pki/issue refusal = %d %s, want 409 in Vault's error shape naming pki/sign", resp.StatusCode, raw)
	}
}

// runVaultExpectingFailure runs the stock CLI for a request the server refuses
// and returns what the CLI printed.
func runVaultExpectingFailure(t *testing.T, vault, home, addr, token string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(vault, args...) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"VAULT_ADDR="+addr,
		"VAULT_TOKEN="+token,
		"VAULT_SKIP_VERIFY=true",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("vault %s succeeded, want a refusal:\n%s", strings.Join(args, " "), out)
	}
	return out
}

func vaultCLIBinary(t *testing.T) string {
	t.Helper()
	if path := strings.TrimSpace(os.Getenv("TRSTCTL_VAULT_BIN")); path != "" {
		if _, err := os.Stat(path); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
			t.Fatalf("TRSTCTL_VAULT_BIN=%s is not usable: %v", path, err)
		}
		return path
	}
	path, err := exec.LookPath("vault")
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("vault CLI is required for VAULT-01 acceptance; set TRSTCTL_VAULT_BIN")
		}
		t.Fatalf("look up vault CLI: %v", err)
	}
	return path
}

func runVault(t *testing.T, vault, home, addr, token string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(vault, args...) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"VAULT_ADDR="+addr,
		"VAULT_TOKEN="+token,
		"VAULT_FORMAT=json",
		"VAULT_SKIP_VERIFY=true",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("vault %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}
