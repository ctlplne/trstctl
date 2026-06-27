package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ComplianceEvidencePackFormat is the stable wire marker for signed compliance
// evidence packs. The signed_export field is self-verifying; public_key_der is
// the verifier material an auditor needs offline.
const ComplianceEvidencePackFormat = "trstctl.compliance.evidence-pack.v1"

// ComplianceFramework is the stable path/API value for a governance evidence pack.
type ComplianceFramework string

const (
	CompliancePCIDSS  ComplianceFramework = "pci-dss"
	ComplianceHIPAA   ComplianceFramework = "hipaa"
	ComplianceSOC2    ComplianceFramework = "soc2"
	ComplianceFedRAMP ComplianceFramework = "fedramp"
	ComplianceCNSA2   ComplianceFramework = "cnsa-2.0"
)

// ParseComplianceFramework accepts stable API path values and common aliases.
func ParseComplianceFramework(raw string) (ComplianceFramework, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pci-dss", "pcidss", "pci":
		return CompliancePCIDSS, nil
	case "hipaa":
		return ComplianceHIPAA, nil
	case "soc2", "soc-2", "soc_2":
		return ComplianceSOC2, nil
	case "fedramp":
		return ComplianceFedRAMP, nil
	case "cnsa-2.0", "cnsa-2", "cnsa2":
		return ComplianceCNSA2, nil
	default:
		return "", fmt.Errorf("framework must be one of pci-dss, hipaa, soc2, fedramp, or cnsa-2.0")
	}
}

// ComplianceEvidenceService generates tenant-scoped, signed compliance evidence
// packs from the audit log and CBOM graph.
type ComplianceEvidenceService interface {
	ExportEvidencePack(ctx context.Context, tenantID string, framework ComplianceFramework) (ComplianceEvidencePack, error)
}

// ComplianceEvidencePack is the served response for a signed framework export.
type ComplianceEvidencePack struct {
	Format       string          `json:"format"`
	Framework    string          `json:"framework"`
	SignedExport json.RawMessage `json:"signed_export"`
	PublicKeyDER []byte          `json:"public_key_der"`
}

// WithComplianceEvidence wires the served compliance evidence-pack backend.
func WithComplianceEvidence(svc ComplianceEvidenceService) Option {
	return func(c *config) { c.complianceEvidence = svc }
}

func (a *API) getComplianceEvidencePack(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.complianceEvidence == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "compliance evidence packs are not configured"))
		return
	}
	fw, err := ParseComplianceFramework(r.PathValue("framework"))
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	pack, err := a.complianceEvidence.ExportEvidencePack(r.Context(), tenantID, fw)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, pack)
}
