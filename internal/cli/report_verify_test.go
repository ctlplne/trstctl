// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
)

func signedTestRun(t *testing.T, key *crypto.LockedSigner, reportType string, payload []byte) []byte {
	t.Helper()
	due := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	manifest, err := json.Marshal(map[string]any{
		"format": compliance.ScheduledReportFormat, "tenant_id": "11111111-1111-1111-1111-111111111111",
		"schedule_id": "22222222-2222-2222-2222-222222222222", "run_id": "33333333-3333-3333-3333-333333333333",
		"due_at": due, "generated_at": due.Add(time.Minute), "framework": "soc2", "report_type": reportType,
		"payload": json.RawMessage(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := crypto.SignMessage(key, manifest)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(map[string]any{"manifest": json.RawMessage(manifest), "signature": signature, "public_key_der": key.Public().DER})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A187: 'compliance report-runs verify' checks a saved run against the key
// the operator pinned, and only then writes the branded rendering out.
func TestComplianceReportRunVerifyChecksOfflineBeforeWritingTheRendering(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Destroy)
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	report, err := assurance.BuildCustomerReport(assurance.CustomerInputs{TenantID: "11111111-1111-1111-1111-111111111111",
		TenantName: "Customer One", Brand: branding.Brand{ProductName: "AcmeTrust"},
		GeneratedAt: base, From: base.Add(-30 * 24 * time.Hour), Through: base})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
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
	runPath := write("run.json", signedTestRun(t, key, "customer_assurance", payload))
	keyPath := write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.Public().DER}))
	otherPath := write("other.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: other.Public().DER}))
	htmlPath := filepath.Join(dir, "report.html")

	var stdout, stderr bytes.Buffer
	if code := runComplianceReportRunVerify([]string{"--report", runPath, "--public-key", keyPath, "--html", htmlPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "verified: customer_assurance report run 33333333-3333-3333-3333-333333333333") ||
		!strings.Contains(stdout.String(), "in the AcmeTrust brand") || !strings.Contains(stdout.String(), "There is no earlier report to compare with.") {
		t.Fatalf("output = %s", stdout.String())
	}
	if html, err := os.ReadFile(htmlPath); err != nil || string(html) != report.HTML { // #nosec G304 -- the test's own temporary file (CWE-22)
		t.Fatalf("written rendering differs: %v", err)
	}

	refusedHTML := filepath.Join(dir, "refused.html")
	stdout.Reset()
	stderr.Reset()
	if code := runComplianceReportRunVerify([]string{"--report", runPath, "--public-key", otherPath, "--html", refusedHTML}, &stdout, &stderr); code != 1 {
		t.Fatalf("another pinned key = %d", code)
	}
	if _, err := os.Stat(refusedHTML); !os.IsNotExist(err) {
		t.Fatal("the rendering was written for a report that did not verify")
	}
	report.HTML += "<!-- edited -->"
	edited, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	editedPath := write("edited.json", signedTestRun(t, key, "customer_assurance", edited))
	if code := runComplianceReportRunVerify([]string{"--report", editedPath, "--public-key", keyPath, "--html", refusedHTML}, &stdout, &stderr); code != 1 {
		t.Fatalf("a rendering that differs from its digest = %d", code)
	}
	if _, err := os.Stat(refusedHTML); !os.IsNotExist(err) {
		t.Fatal("a rendering that differs from its digest was written")
	}
	otherRun := write("pack.json", signedTestRun(t, key, "framework_evidence_pack", []byte(`{"format":"pack"}`)))
	if code := runComplianceReportRunVerify([]string{"--report", otherRun, "--public-key", keyPath, "--html", refusedHTML}, &stdout, &stderr); code != 2 {
		t.Fatalf("--html on another report type = %d", code)
	}
	if code := runComplianceReportRunVerify([]string{"--report", otherRun, "--public-key", keyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("another report type verifies without --html: %d %s", code, stderr.String())
	}
}
