// SPDX-License-Identifier: BUSL-1.1

package compliance

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func testReportKey(t *testing.T) *crypto.LockedSigner {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

// signTestReport wraps a manifest the way the governance signer does, naming
// claimedKey as the signer.
func signTestReport(t *testing.T, key crypto.DigestSigner, claimedKey []byte, manifest []byte) []byte {
	t.Helper()
	signature, err := crypto.SignMessage(key, manifest)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(struct {
		Manifest     json.RawMessage `json:"manifest"`
		Signature    []byte          `json:"signature"`
		PublicKeyDER []byte          `json:"public_key_der"`
	}{manifest, signature, claimedKey})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func testManifest(t *testing.T, runID string) []byte {
	t.Helper()
	due := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	manifest, err := json.Marshal(map[string]any{
		"format": ScheduledReportFormat, "tenant_id": "11111111-1111-1111-1111-111111111111",
		"schedule_id": "22222222-2222-2222-2222-222222222222", "run_id": runID, "due_at": due,
		"generated_at": due.Add(time.Minute), "framework": "soc2", "report_type": "customer_assurance",
		"payload": map[string]any{"format": "example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

// A187: a saved scheduled report verifies only under the key the verifier
// pinned, never the key the file names, and only as a complete run binding.
func TestVerifyScheduledReportTrustsOnlyThePinnedKey(t *testing.T) {
	key, other := testReportKey(t), testReportKey(t)
	pinned, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.Public().DER}))
	if err != nil || !bytes.Equal(pinned, key.Public().DER) {
		t.Fatalf("parse PEM key: %v", err)
	}
	if raw, err := ParsePublicKey(key.Public().DER); err != nil || !bytes.Equal(raw, pinned) {
		t.Fatalf("parse DER key: %v", err)
	}
	if _, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})); err == nil {
		t.Fatal("a certificate block was taken as a public key")
	}

	manifest := testManifest(t, "33333333-3333-3333-3333-333333333333")
	report, err := VerifyScheduledReport(signTestReport(t, key, key.Public().DER, manifest), pinned)
	if err != nil || report.RunID != "33333333-3333-3333-3333-333333333333" || report.ReportType != "customer_assurance" ||
		report.KeySHA256 != crypto.SHA256Hex(pinned) || !strings.Contains(string(report.Payload), "example") {
		t.Fatalf("verify = %+v, %v", report, err)
	}
	// A forgery that ships its own key.
	if _, err := VerifyScheduledReport(signTestReport(t, other, other.Public().DER, manifest), pinned); err == nil {
		t.Fatal("a report signed by another key was accepted")
	}
	// A forgery that names the pinned key but was signed by another.
	if _, err := VerifyScheduledReport(signTestReport(t, other, key.Public().DER, manifest), pinned); err == nil {
		t.Fatal("a signature from another key was accepted")
	}
	tampered := signTestReport(t, key, key.Public().DER, manifest)
	tampered = bytes.Replace(tampered, []byte("soc2"), []byte("pci4"), 1)
	if !bytes.Contains(tampered, []byte("pci4")) {
		t.Fatal("the fixture did not change the manifest")
	}
	if _, err := VerifyScheduledReport(tampered, pinned); err == nil {
		t.Fatal("an edited manifest verified")
	}
	if _, err := VerifyScheduledReport(signTestReport(t, key, key.Public().DER, testManifest(t, "")), pinned); err == nil {
		t.Fatal("a manifest without a run verified")
	}
	if _, err := VerifyScheduledReport(signTestReport(t, key, key.Public().DER, manifest), nil); err == nil {
		t.Fatal("a report verified with no pinned key")
	}
}
