// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

func exitCode(err error) int {
	var exit ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	if err != nil {
		return -1
	}
	return 0
}

// A188: the command refuses to run without its inputs, takes the token only
// from the environment or a file, and `evaluate verify` accepts a pack only
// under the key set the operator pinned.
func TestEvaluateCommandInputsAndOfflineVerify(t *testing.T) {
	empty := func(string) string { return "" }
	var stdout, stderr bytes.Buffer
	if code := exitCode(Run(t.Context(), []string{"--deployment-target", "t1"}, empty, &stdout, &stderr)); code != 2 ||
		!strings.Contains(stderr.String(), "an API token") {
		t.Fatalf("missing server and token = %d: %s", code, stderr.String())
	}
	stderr.Reset()
	env := map[string]string{"TRSTCTL_SERVER": "https://cp.example.test", "TRSTCTL_TOKEN": "token"}
	withEnv := func(name string) string { return env[name] }
	if code := exitCode(Run(t.Context(), []string{"--deployment-target", "t1", "--sign"}, withEnv, &stdout, &stderr)); code != 2 ||
		!strings.Contains(stderr.String(), "--sign requires --signer-socket") {
		t.Fatalf("--sign without a socket = %d: %s", code, stderr.String())
	}

	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	other, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	pack := Pack{Format: PackFormat, GeneratedAt: now, StartedAt: now, Server: "https://cp.example.test",
		Target:  Target{Endpoint: "lab.example.test:443", Name: "lab.example.test", DeploymentTargetID: "t1"},
		Verdict: StatusFail, Summary: Summary{Failed: 1, Skipped: 7},
		Steps:  []Step{{Name: StepDiscovery, Status: StatusFail, Detail: "The control plane could not complete a TLS handshake with lab.example.test:443.", StartedAt: now, FinishedAt: now}},
		Limits: []string{"one run"}}
	if err := Sign(&pack, key, "audit-export"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	raw, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	packPath := write("pack.json", raw)
	keys, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	otherKeys, err := other.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	pinned, wrong := write("audit-jwks.json", keys), write("other-jwks.json", otherKeys)

	stdout.Reset()
	if code := exitCode(Run(t.Context(), []string{"verify", "--pack", packPath, "--audit-jwks", pinned}, withEnv, &stdout, &stderr)); code != 0 ||
		!strings.Contains(stdout.String(), "verified: evaluation pack") || !strings.Contains(stdout.String(), "Verdict: FAIL") {
		t.Fatalf("verify = %d: %s %s", code, stdout.String(), stderr.String())
	}
	if code := exitCode(Run(t.Context(), []string{"verify", "--pack", packPath, "--audit-jwks", wrong}, withEnv, &stdout, &stderr)); code != 1 {
		t.Fatalf("another key set = %d", code)
	}
	pack.Verdict, pack.Summary = StatusPass, Summary{Passed: 8}
	forged, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if code := exitCode(Run(t.Context(), []string{"verify", "--pack", write("forged.json", forged), "--audit-jwks", pinned}, withEnv, &stdout, &stderr)); code != 1 {
		t.Fatalf("a pack edited to pass = %d", code)
	}
}
