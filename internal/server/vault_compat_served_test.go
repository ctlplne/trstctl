// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

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

	runVault(t, vault, home, h.ts.URL, token,
		"kv", "put", "-header=Idempotency-Key=vault-compat-kv-put-1", "secret/trstctl-vault",
		"username=app",
		"password=vault-compat-s3cr3t",
	)
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
		"write", "-header=Idempotency-Key=vault-compat-pki-issue-1", "-format=json", "pki/issue/trstctl", "common_name=svc.vault.test", "ttl=1h",
	)
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
