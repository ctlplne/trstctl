package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
)

type stubComplianceEvidence struct{}

func (stubComplianceEvidence) ExportEvidencePack(_ context.Context, tenantID string, framework api.ComplianceFramework) (api.ComplianceEvidencePack, error) {
	return api.ComplianceEvidencePack{
		Format:       api.ComplianceEvidencePackFormat,
		Framework:    string(framework),
		SignedExport: json.RawMessage(`{"tenant_id":"` + tenantID + `","ok":true}`),
		PublicKeyDER: []byte("test-public-key"),
	}, nil
}

func TestComplianceEvidenceRequiresGovernanceFactory(t *testing.T) {
	auditKey, err := jose.GenerateRSASigningKey("governance-seam-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditSigningKey = auditKey
	})
	auditor := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "external-auditor", []string{
		string(authz.AuditRead),
	})

	code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", auditor, "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("unlicensed compliance evidence pack = %d body=%s; want 404", code, body)
	}
}

func TestComplianceEvidenceServedThroughGovernanceFactory(t *testing.T) {
	auditKey, err := jose.GenerateRSASigningKey("governance-seam-audit")
	if err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AuditSigningKey = auditKey
		d.GovernanceFactory = func(deps GovernanceFactoryDeps) (api.ComplianceEvidenceService, error) {
			if deps.Audit == nil || deps.Store == nil || deps.Signer == nil {
				t.Fatalf("governance factory deps incomplete: %+v", deps)
			}
			return stubComplianceEvidence{}, nil
		}
	})

	viewer := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "risk-viewer", []string{
		string(authz.RiskRead),
	})
	code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", viewer, "", nil)
	if code != http.StatusForbidden {
		t.Fatalf("non-auditor evidence pack = %d body=%s; want 403", code, body)
	}

	auditor := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "external-auditor", []string{
		string(authz.AuditRead),
	})
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/compliance/evidence-packs/soc2", auditor, "", nil)
	if code != http.StatusOK {
		t.Fatalf("auditor evidence pack = %d body=%s; want 200", code, body)
	}
	var resp api.ComplianceEvidencePack
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode evidence pack response: %v body=%s", err, body)
	}
	if resp.Format != api.ComplianceEvidencePackFormat || resp.Framework != string(api.ComplianceSOC2) {
		t.Fatalf("evidence pack metadata = format %q framework %q", resp.Format, resp.Framework)
	}
}
