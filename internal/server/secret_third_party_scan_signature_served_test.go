// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// An exported artifact can carry the provider's detached signature. When the
// operator supplies the signature and the provider's public key, trstctl
// verifies the artifact bytes before scanning them, records the verification on
// every finding, and refuses to scan a tampered or unsigned artifact when the
// source requires a signature. Nothing about the artifact's content is scanned
// or stored until the signature holds.
func TestServedThirdPartySecretScanVerifiesProviderSignature(t *testing.T) {
	root := t.TempDir()
	artifact := writeSecretArtifact(t, root, "cicd-log/build.log", "CI_JOB_TOKEN=xoxb-signed-fixture-value\n") // #nosec G101 -- fabricated fixture (CWE-798)
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	content, err := os.ReadFile(artifact) // #nosec G304 -- test reads its own tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SignMessage(signer, content)
	if err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(root, "cicd-log", "build.log.sig")
	if err := os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil { // #nosec G703 -- test-owned temp path
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(root, "cicd-log", "build.log.bad.sig")
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0x01
	if err := os.WriteFile(tamperedPath, []byte(base64.StdEncoding.EncodeToString(bad)), 0o600); err != nil { // #nosec G703 -- test-owned temp path
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: signer.Public().DER}))

	fake := &fakeThirdPartySecretScanner{called: make(chan string, 4)}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) { d.SecretScanner = fake })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read")

	ingest := func(key string, body map[string]any, want int) map[string]json.RawMessage {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/cicd_log/ingest", tok, key, body)
		if status != want {
			t.Fatalf("%s: status=%d want %d body=%s", key, status, want, raw)
		}
		var out map[string]json.RawMessage
		_ = json.Unmarshal(raw, &out)
		return out
	}
	runOf := func(receipt map[string]json.RawMessage) string {
		t.Helper()
		var id string
		if err := json.Unmarshal(receipt["run_id"], &id); err != nil || id == "" {
			t.Fatalf("receipt has no run_id: %v", receipt)
		}
		return id
	}
	awaitRun := func(runID string) (status, errText string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			h.srv.dispatchOnce(context.Background())
			code, raw := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+runID, tok, nil)
			if code != http.StatusOK {
				t.Fatalf("run %s: %d %s", runID, code, raw)
			}
			var run struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			}
			_ = json.Unmarshal(raw, &run)
			if run.Status == "succeeded" || run.Status == "partial" || run.Status == "failed" {
				return run.Status, run.Error
			}
			select {
			case <-deadline:
				t.Fatalf("run %s did not finish: %s", runID, raw)
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	// A source that requires a signature refuses to queue without one.
	ingest("sig-missing", map[string]any{"source": "acme/ci", "artifact_path": artifact, "require_signature": true, "signer_public_key_pem": pubPEM}, http.StatusBadRequest)

	// Valid signature: the run succeeds and every finding carries the verification.
	okRun := runOf(ingest("sig-ok", map[string]any{"source": "acme/ci", "artifact_path": artifact, "signature_path": signaturePath, "signer_public_key_pem": pubPEM, "require_signature": true}, http.StatusAccepted))
	if status, errText := awaitRun(okRun); status != "succeeded" {
		t.Fatalf("signed artifact run = %s (%s); want succeeded", status, errText)
	}
	deadline := time.After(5 * time.Second)
	for {
		code, raw := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+okRun, tok, nil)
		if code == http.StatusOK && strings.Contains(string(raw), `"signature_verified":true`) {
			if !strings.Contains(string(raw), `"signer_key_sha256"`) {
				t.Fatalf("findings carry no signer key digest: %s", raw)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("findings never recorded signature_verified: %d %s", code, raw)
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Tampered signature: nothing is scanned, the run fails naming the signature.
	before := len(fake.paths())
	badRun := runOf(ingest("sig-bad", map[string]any{"source": "acme/ci-bad", "artifact_path": artifact, "signature_path": tamperedPath, "signer_public_key_pem": pubPEM, "require_signature": true}, http.StatusAccepted))
	status, errText := awaitRun(badRun)
	if status != "failed" || !strings.Contains(strings.ToLower(errText), "signature") {
		t.Fatalf("tampered artifact run = %s (%s); want failed naming the signature", status, errText)
	}
	if len(fake.paths()) != before {
		t.Fatalf("the scanner ran on an artifact whose signature did not verify: %v", fake.paths())
	}
}
