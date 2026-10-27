// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/store"
)

// A179: verify-assurance-record checks a saved record offline against a JWK
// set the operator pinned, and refuses a tampered one or one signed by other
// keys.
func TestVerifyAssuranceRecordOffline(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	record := assurance.Build(assurance.Inputs{
		TenantID: "tenant", Now: now,
		Evidence: store.CredentialEvidence{Certificate: store.Certificate{ID: "cert-1", Fingerprint: "fp-1", Subject: "CN=svc", Status: "active", Source: "issued", IssuanceIdempotencyKey: "issue:x"}},
	})
	signed, err := assurance.Sign(key, record)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(signed)
	jwks, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	keys := write("audit-jwks.json", jwks)
	good := write("record.json", document)

	var stdout, stderr bytes.Buffer
	if code := runCertificateVerifyAssuranceRecord([]string{"--record", good, "--audit-jwks", keys}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), "verified: assurance record for certificate cert-1 (fp-1)") ||
		!strings.Contains(stdout.String(), "recorded by trstctl only: issuance") {
		t.Fatalf("genuine record: code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}

	var tampered map[string]any
	_ = json.Unmarshal(document, &tampered)
	tampered["record"].(map[string]any)["credential"].(map[string]any)["fingerprint"] = "fp-forged"
	forged, _ := json.Marshal(tampered)
	other, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	otherJWKS, _ := other.PublicJWKS()
	for name, args := range map[string][]string{
		"tampered record": {"--record", write("forged.json", forged), "--audit-jwks", keys},
		"other keys":      {"--record", good, "--audit-jwks", write("other-jwks.json", otherJWKS)},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := runCertificateVerifyAssuranceRecord(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "error:") || strings.Contains(stdout.String(), "verified") {
			t.Fatalf("%s: code %d stdout %q stderr %q", name, code, stdout.String(), stderr.String())
		}
	}
	stderr.Reset()
	if code := runCertificateVerifyAssuranceRecord([]string{"--record", good}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "--audit-jwks are required") {
		t.Fatalf("missing pinned keys: code %d stderr %q", code, stderr.String())
	}
}
