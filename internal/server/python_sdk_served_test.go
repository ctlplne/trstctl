package server

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestPythonSDKAuthIssueAndSecretsRoundTripAgainstServedHandler is DIST-04's
// acceptance proof. It drives the assembled served handler with the published Python
// SDK, not a fake server: bearer auth, dynamic PKI issue, and secret
// create/read/rotate/delete all cross the same REST routes cmd/trstctl serves.
func TestPythonSDKAuthIssueAndSecretsRoundTripAgainstServedHandler(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required for the Python SDK acceptance test: %v", err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	sdkSrc := filepath.Join(repoRoot, "clients", "sdk", "python", "src")
	scriptPath := filepath.Join(t.TempDir(), "roundtrip.py")
	script := `
import json
import os

from trstctl_sdk import ProblemError, TrstctlClient

base = os.environ["TRSTCTL_SERVER"]
tenant = os.environ["TRSTCTL_TENANT"]

try:
    TrstctlClient(base_url=base, tenant=tenant, retry={"max_attempts": 1}).list_secrets()
    raise AssertionError("unauthenticated list_secrets unexpectedly succeeded")
except ProblemError as exc:
    assert exc.http_status == 401, exc

client = TrstctlClient.from_env(retry={"max_attempts": 1})

issued = client.issue_pki_secret("python-sdk.served.test", ttl_seconds=300, idempotency_key="py-sdk-issue")
assert issued["serial"], issued
assert "BEGIN CERTIFICATE" in issued["certificate"], issued
assert "BEGIN PRIVATE KEY" in issued["private_key"], issued

created = client.create_secret("sdk/python/password", "initial-fixture-value", idempotency_key="py-sdk-secret-create")
assert created["name"] == "sdk/python/password", created
assert created["version"] == 1, created

read = client.get_secret("sdk/python/password")
assert read["value"] == "initial-fixture-value", read
assert read["version"] == 1, read

rotated = client.rotate_secret("sdk/python/password", "rotated-fixture-value", idempotency_key="py-sdk-secret-rotate")
assert rotated["version"] == 2, rotated

read2 = client.get_secret("sdk/python/password")
assert read2["value"] == "rotated-fixture-value", read2
assert read2["version"] == 2, read2

client.delete_secret("sdk/python/password", idempotency_key="py-sdk-secret-delete")

print(json.dumps({"serial": issued["serial"], "version": read2["version"]}, sort_keys=True))
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write python roundtrip script: %v", err)
	}

	cmd := exec.Command(python, scriptPath)
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+sdkSrc,
		"TRSTCTL_SERVER="+h.ts.URL,
		"TRSTCTL_TENANT="+h.tenant,
		"TRSTCTL_TOKEN="+token,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python SDK served round-trip failed: %v\n%s", err, out)
	}
	var got struct {
		Serial  string `json:"serial"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &got); err != nil {
		t.Fatalf("decode python SDK round-trip output %q: %v", out, err)
	}
	if got.Serial == "" || got.Version != 2 {
		t.Fatalf("python SDK round-trip output = %+v, want serial and version 2", got)
	}
	if !h.hasEvent(t, "pkisecret.issued") || !h.hasEvent(t, "secret.created") || !h.hasEvent(t, "secret.rotated") || !h.hasEvent(t, "secret.deleted") {
		t.Fatal("Python SDK did not drive the served issue + secrets event-sourced paths")
	}
}
