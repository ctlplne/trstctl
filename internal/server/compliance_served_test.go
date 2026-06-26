package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// COMP-01 acceptance: an auditor can pull a signed SOC 2/FIPS evidence pack from
// the real served API, and a non-auditor is denied by RBAC. The pack is generated
// from the tenant audit log plus CBOM inventory and verifies offline with the
// returned public key.
func TestServedComplianceEvidencePackAuditorOnly(t *testing.T) {
	auditKey, err := jose.GenerateRSASigningKey("comp-01-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditSigningKey = auditKey
	})

	seedCBOMEvidence(t, h)

	auditor := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "external-auditor", []string{
		string(authz.AuditRead),
	})
	viewer := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "risk-viewer", []string{
		string(authz.RiskRead),
	})

	code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", viewer, "", nil)
	if code != http.StatusForbidden {
		t.Fatalf("non-auditor evidence pack = %d body=%s; want 403", code, body)
	}

	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", auditor, "", nil)
	if code != http.StatusOK {
		t.Fatalf("auditor evidence pack = %d body=%s; want 200", code, body)
	}
	var resp struct {
		Format       string          `json:"format"`
		Framework    string          `json:"framework"`
		SignedExport json.RawMessage `json:"signed_export"`
		PublicKeyDER []byte          `json:"public_key_der"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode evidence pack response: %v body=%s", err, body)
	}
	if resp.Format != "trstctl.compliance.evidence-pack.v1" || resp.Framework != string(compliance.SOC2) {
		t.Fatalf("evidence pack metadata = format %q framework %q", resp.Format, resp.Framework)
	}
	if len(resp.SignedExport) == 0 || len(resp.PublicKeyDER) == 0 {
		t.Fatalf("evidence pack missing signed export or public key: %s", body)
	}
	manifest, err := compliance.Verify(resp.SignedExport, resp.PublicKeyDER)
	if err != nil {
		t.Fatalf("signed evidence pack does not verify: %v export=%s", err, resp.SignedExport)
	}
	var report compliance.Report
	if err := json.Unmarshal(manifest, &report); err != nil {
		t.Fatalf("decode verified evidence manifest: %v manifest=%s", err, manifest)
	}
	if report.Framework != string(compliance.SOC2) || len(report.Controls) == 0 {
		t.Fatalf("report = framework %q controls %d", report.Framework, len(report.Controls))
	}
	if report.Posture.TotalCryptoAssets == 0 {
		t.Fatalf("report posture did not include CBOM crypto assets: %+v", report.Posture)
	}
	if !bytes.Contains(manifest, []byte("FIPS")) {
		t.Fatalf("SOC 2/FIPS evidence manifest missing FIPS posture marker: %s", manifest)
	}
	if _, err := audit.VerifyChain(mustAuditRecords(t, h)); err != nil {
		t.Fatalf("underlying audit records are not chain-verifiable: %v", err)
	}
}

func seedCBOMEvidence(t *testing.T, h *servedHarness) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "openssl.cnf")
	if err := os.WriteFile(conf, []byte("ssl_protocols TLSv1.2;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"), 0o644); err != nil {
		t.Fatalf("write CBOM fixture: %v", err)
	}
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cbom-operator", []string{
		string(authz.DiscoveryWrite), string(authz.RiskRead),
	})
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/cbom/scans", token, "comp-01-cbom-scan", map[string]any{
		"host_configs": []string{conf},
	})
	if code != http.StatusCreated {
		t.Fatalf("seed CBOM scan = %d body=%s; want 201", code, body)
	}
}

func mustAuditRecords(t *testing.T, h *servedHarness) []audit.Record {
	t.Helper()
	auditKey, err := jose.GenerateRSASigningKey("comp-01-verify-only")
	if err != nil {
		t.Fatalf("generate verify audit key: %v", err)
	}
	svc := audit.NewService(h.log, auditKey)
	records, err := svc.Search(context.Background(), audit.Query{TenantID: h.tenant})
	if err != nil {
		t.Fatalf("search audit records: %v", err)
	}
	return records
}
