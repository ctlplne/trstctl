package api

import (
	"context"
	"net/http"
	"time"
)

const (
	nhiComplianceReportFormat = "trstctl.nhi.compliance-report.v1"
	nhiComplianceCapability   = "CAP-CMP-06"
)

type nhiComplianceReport struct {
	Format       string                   `json:"format"`
	Capability   string                   `json:"capability"`
	GeneratedAt  time.Time                `json:"generated_at"`
	AuditReady   bool                     `json:"audit_ready"`
	Summary      nhiComplianceSummary     `json:"summary"`
	Frameworks   []nhiComplianceFramework `json:"frameworks"`
	Controls     []nhiComplianceControl   `json:"controls"`
	ReportTypes  []string                 `json:"report_types"`
	Routes       []string                 `json:"routes"`
	EvidenceRefs []string                 `json:"evidence_refs"`
	Residuals    []string                 `json:"residuals"`
}

type nhiComplianceSummary struct {
	TotalNHIs                 int `json:"total_nhis"`
	InventoryKinds            int `json:"inventory_kinds"`
	FrameworksSupported       int `json:"frameworks_supported"`
	ControlsMapped            int `json:"controls_mapped"`
	OverprivilegedFindings    int `json:"overprivileged_findings"`
	StaleFindings             int `json:"stale_findings"`
	StaticCredentialFindings  int `json:"static_credential_findings"`
	AuditEvidenceRefs         int `json:"audit_evidence_refs"`
	OperatorAttestationNeeded int `json:"operator_attestation_needed"`
}

type nhiComplianceFramework struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	MappingStatus   string   `json:"mapping_status"`
	EvidenceSources []string `json:"evidence_sources"`
}

type nhiComplianceControl struct {
	Framework      string   `json:"framework"`
	ControlID      string   `json:"control_id"`
	Title          string   `json:"title"`
	Status         string   `json:"status"`
	EvidenceRefs   []string `json:"evidence_refs"`
	PostureSignals []string `json:"posture_signals"`
	FindingCount   int      `json:"finding_count"`
	Residual       string   `json:"residual,omitempty"`
}

type nhiComplianceControlDefinition struct {
	Framework      string
	ControlID      string
	Title          string
	PostureSignals []string
	Residual       string
}

func (a *API) getNHIComplianceReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.buildNHIComplianceReport(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) buildNHIComplianceReport(ctx context.Context, tenantID string) (nhiComplianceReport, error) {
	inventory, err := a.nhiInventory(ctx, tenantID)
	if err != nil {
		return nhiComplianceReport{}, err
	}
	overprivilege, err := a.nhiOverPrivilegePosture(ctx, tenantID)
	if err != nil {
		return nhiComplianceReport{}, err
	}
	stale, err := a.nhiStalePosture(ctx, tenantID)
	if err != nil {
		return nhiComplianceReport{}, err
	}
	static, err := a.nhiStaticPosture(ctx, tenantID)
	if err != nil {
		return nhiComplianceReport{}, err
	}

	evidenceRefs := nhiComplianceEvidenceRefs()
	frameworks := nhiComplianceFrameworks()
	controls := buildNHIComplianceControls(inventory, overprivilege, stale, static)
	operatorResiduals := nhiComplianceResiduals()
	return nhiComplianceReport{
		Format:       nhiComplianceReportFormat,
		Capability:   nhiComplianceCapability,
		GeneratedAt:  time.Now().UTC(),
		AuditReady:   true,
		Summary:      buildNHIComplianceSummary(inventory, overprivilege, stale, static, len(frameworks), len(controls), len(evidenceRefs), len(operatorResiduals)),
		Frameworks:   frameworks,
		Controls:     controls,
		ReportTypes:  append([]string(nil), complianceReportTypes...),
		Routes:       nhiComplianceRoutes(),
		EvidenceRefs: evidenceRefs,
		Residuals:    operatorResiduals,
	}, nil
}

func buildNHIComplianceSummary(inventory nhiInventoryResponse, overprivilege nhiOverPrivilegeResponse, stale nhiStalePostureResponse, static nhiStaticPostureResponse, frameworks, controls, evidenceRefs, residuals int) nhiComplianceSummary {
	return nhiComplianceSummary{
		TotalNHIs:                 len(inventory.Items),
		InventoryKinds:            len(inventory.Summary),
		FrameworksSupported:       frameworks,
		ControlsMapped:            controls,
		OverprivilegedFindings:    overprivilege.Summary.Overprivileged,
		StaleFindings:             stale.Summary.Findings,
		StaticCredentialFindings:  static.Summary.Findings,
		AuditEvidenceRefs:         evidenceRefs,
		OperatorAttestationNeeded: residuals,
	}
}

func nhiComplianceFrameworks() []nhiComplianceFramework {
	sources := nhiComplianceEvidenceRefs()
	return []nhiComplianceFramework{
		{ID: "nist-800-53", Name: "NIST SP 800-53", Version: "Rev. 5", MappingStatus: "served", EvidenceSources: sources},
		{ID: "nist-csf-2.0", Name: "NIST Cybersecurity Framework", Version: "2.0", MappingStatus: "served", EvidenceSources: sources},
		{ID: "pci-dss-4.0", Name: "PCI DSS", Version: "4.0", MappingStatus: "served", EvidenceSources: sources},
		{ID: "dora", Name: "Digital Operational Resilience Act", Version: "Regulation (EU) 2022/2554", MappingStatus: "served", EvidenceSources: sources},
		{ID: "iso-27001", Name: "ISO/IEC 27001", Version: "2022 Annex A", MappingStatus: "served", EvidenceSources: sources},
		{ID: "fedramp", Name: "FedRAMP", Version: "Rev. 5 baselines", MappingStatus: "served", EvidenceSources: sources},
		{ID: "cmmc-2.0", Name: "CMMC", Version: "2.0", MappingStatus: "served", EvidenceSources: sources},
		{ID: "eidas", Name: "eIDAS", Version: "Regulation (EU) No 910/2014 and eIDAS 2.0", MappingStatus: "served", EvidenceSources: sources},
		{ID: "nis2", Name: "NIS2", Version: "Directive (EU) 2022/2555", MappingStatus: "served", EvidenceSources: sources},
	}
}

func buildNHIComplianceControls(inventory nhiInventoryResponse, overprivilege nhiOverPrivilegeResponse, stale nhiStalePostureResponse, static nhiStaticPostureResponse) []nhiComplianceControl {
	defs := []nhiComplianceControlDefinition{
		{Framework: "nist-800-53", ControlID: "CM-8", Title: "System component inventory for NHIs", PostureSignals: []string{"inventory"}},
		{Framework: "nist-800-53", ControlID: "AC-2", Title: "Account management for machine principals", PostureSignals: []string{"inventory", "stale_orphaned"}},
		{Framework: "nist-800-53", ControlID: "AC-6", Title: "Least privilege for non-human entitlements", PostureSignals: []string{"overprivilege"}},
		{Framework: "nist-800-53", ControlID: "IA-5", Title: "Authenticator lifecycle for NHI credentials", PostureSignals: []string{"static_rotation"}},
		{Framework: "nist-800-53", ControlID: "AU-6", Title: "Audit review evidence for NHI changes", PostureSignals: []string{"audit"}},

		{Framework: "nist-csf-2.0", ControlID: "ID.AM", Title: "NHI assets are inventoried", PostureSignals: []string{"inventory"}},
		{Framework: "nist-csf-2.0", ControlID: "PR.AA", Title: "Identity and access control for NHIs", PostureSignals: []string{"overprivilege", "stale_orphaned"}},
		{Framework: "nist-csf-2.0", ControlID: "PR.PS", Title: "Platform and credential safeguards", PostureSignals: []string{"static_rotation"}},
		{Framework: "nist-csf-2.0", ControlID: "DE.CM", Title: "Continuous monitoring signals", PostureSignals: []string{"stale_orphaned", "audit"}},

		{Framework: "pci-dss-4.0", ControlID: "7.2", Title: "Least-privilege access control", PostureSignals: []string{"overprivilege"}},
		{Framework: "pci-dss-4.0", ControlID: "8.2", Title: "Identity lifecycle for accounts and credentials", PostureSignals: []string{"inventory", "stale_orphaned"}},
		{Framework: "pci-dss-4.0", ControlID: "8.6", Title: "Application and system account credential controls", PostureSignals: []string{"static_rotation", "overprivilege"}},
		{Framework: "pci-dss-4.0", ControlID: "10.2", Title: "Audit logging for access and credential events", PostureSignals: []string{"audit"}},

		{Framework: "dora", ControlID: "Article 6", Title: "ICT risk management framework evidence", PostureSignals: []string{"inventory", "audit"}, Residual: "Organization-level ICT risk appetite, ownership, and board-approved policy remain operator attestations."},
		{Framework: "dora", ControlID: "Article 8", Title: "ICT asset identification and classification", PostureSignals: []string{"inventory"}},
		{Framework: "dora", ControlID: "Article 9", Title: "Protection and prevention for NHI credentials", PostureSignals: []string{"overprivilege", "static_rotation"}},
		{Framework: "dora", ControlID: "Article 10", Title: "Detection of anomalous NHI posture", PostureSignals: []string{"stale_orphaned", "audit"}},

		{Framework: "iso-27001", ControlID: "A.5.9", Title: "Inventory of information and associated assets", PostureSignals: []string{"inventory"}},
		{Framework: "iso-27001", ControlID: "A.5.15", Title: "Access control for non-human identities", PostureSignals: []string{"overprivilege"}},
		{Framework: "iso-27001", ControlID: "A.5.16", Title: "Identity management for machine accounts", PostureSignals: []string{"inventory", "stale_orphaned"}},
		{Framework: "iso-27001", ControlID: "A.5.18", Title: "Access rights review and removal", PostureSignals: []string{"overprivilege", "stale_orphaned"}},
		{Framework: "iso-27001", ControlID: "A.8.15", Title: "Logging of NHI control evidence", PostureSignals: []string{"audit"}, Residual: "Control applicability, SoA scope, and auditor sampling decisions remain operator attestations."},

		{Framework: "fedramp", ControlID: "AC-2", Title: "Machine-account lifecycle and ownership", PostureSignals: []string{"inventory", "stale_orphaned"}},
		{Framework: "fedramp", ControlID: "AC-6", Title: "Least privilege for NHI entitlements", PostureSignals: []string{"overprivilege"}},
		{Framework: "fedramp", ControlID: "IA-5", Title: "Authenticator lifecycle and rotation evidence", PostureSignals: []string{"static_rotation"}},
		{Framework: "fedramp", ControlID: "AU-6", Title: "Audit review evidence for NHI changes", PostureSignals: []string{"audit"}, Residual: "FedRAMP authorization package, SSP tailoring, and assessment evidence remain operator responsibilities."},

		{Framework: "cmmc-2.0", ControlID: "AC.L2-3.1.5", Title: "Least-privilege access for non-human accounts", PostureSignals: []string{"overprivilege"}},
		{Framework: "cmmc-2.0", ControlID: "IA.L2-3.5.7", Title: "Credential complexity and lifecycle evidence for NHIs", PostureSignals: []string{"static_rotation"}},
		{Framework: "cmmc-2.0", ControlID: "AU.L2-3.3.1", Title: "System audit logs for NHI activity", PostureSignals: []string{"audit"}},
		{Framework: "cmmc-2.0", ControlID: "CM.L2-3.4.1", Title: "Inventory-backed configuration accountability", PostureSignals: []string{"inventory", "stale_orphaned"}, Residual: "CMMC scoping, CUI boundary, and assessor package remain operator attestations."},

		{Framework: "eidas", ControlID: "Article 19", Title: "Security risk management and incident evidence for trust-service operations", PostureSignals: []string{"audit", "stale_orphaned"}, Residual: "Qualified trust-service status and supervisory notification duties remain operator responsibilities."},
		{Framework: "eidas", ControlID: "Article 24", Title: "Identity, certificate, and trust-service lifecycle evidence", PostureSignals: []string{"inventory", "static_rotation"}},
		{Framework: "eidas", ControlID: "Annex I", Title: "Certificate subject and issuer evidence inventory", PostureSignals: []string{"inventory", "audit"}},

		{Framework: "nis2", ControlID: "Article 21", Title: "Cybersecurity risk-management measures for NHI assets", PostureSignals: []string{"inventory", "overprivilege", "static_rotation"}, Residual: "Organization-wide NIS2 governance, supply-chain, and board oversight evidence remain operator attestations."},
		{Framework: "nis2", ControlID: "Article 23", Title: "Incident evidence and reporting support", PostureSignals: []string{"audit", "stale_orphaned"}},
		{Framework: "nis2", ControlID: "Article 20", Title: "Governance evidence for accountable NHI controls", PostureSignals: []string{"audit"}, Residual: "Management-body accountability and national transposition obligations remain operator responsibilities."},
	}
	out := make([]nhiComplianceControl, 0, len(defs))
	for _, def := range defs {
		status := "evidenced"
		if def.Residual != "" {
			status = "evidenced_with_operator_attestation"
		}
		out = append(out, nhiComplianceControl{
			Framework:      def.Framework,
			ControlID:      def.ControlID,
			Title:          def.Title,
			Status:         status,
			EvidenceRefs:   nhiComplianceEvidenceForSignals(def.PostureSignals),
			PostureSignals: append([]string(nil), def.PostureSignals...),
			FindingCount:   nhiComplianceFindingCount(def.PostureSignals, inventory, overprivilege, stale, static),
			Residual:       def.Residual,
		})
	}
	return out
}

func nhiComplianceFindingCount(signals []string, inventory nhiInventoryResponse, overprivilege nhiOverPrivilegeResponse, stale nhiStalePostureResponse, static nhiStaticPostureResponse) int {
	total := 0
	for _, signal := range signals {
		switch signal {
		case "inventory":
			total += len(inventory.Items)
		case "overprivilege":
			total += overprivilege.Summary.Overprivileged
		case "stale_orphaned":
			total += stale.Summary.Findings
		case "static_rotation":
			total += static.Summary.Findings
		}
	}
	return total
}

func nhiComplianceEvidenceForSignals(signals []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ref string) {
		if seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, ref)
	}
	for _, signal := range signals {
		switch signal {
		case "inventory":
			add("api:GET /api/v1/nhi/inventory")
		case "overprivilege":
			add("api:GET /api/v1/nhi/posture/overprivilege")
		case "stale_orphaned":
			add("api:GET /api/v1/nhi/posture/stale")
		case "static_rotation":
			add("api:GET /api/v1/nhi/posture/static-credentials")
		case "audit":
			add("api:GET /api/v1/audit/events")
			add("api:GET /api/v1/audit/export")
		}
	}
	return out
}

func nhiComplianceRoutes() []string {
	return []string{
		"GET /api/v1/compliance/nhi-report",
		"GET /api/v1/nhi/inventory",
		"GET /api/v1/nhi/posture/overprivilege",
		"GET /api/v1/nhi/posture/stale",
		"GET /api/v1/nhi/posture/static-credentials",
		"GET /api/v1/audit/events",
		"GET /api/v1/audit/export",
	}
}

func nhiComplianceEvidenceRefs() []string {
	return []string{
		"api:GET /api/v1/compliance/nhi-report",
		"api:GET /api/v1/nhi/inventory",
		"api:GET /api/v1/nhi/posture/overprivilege",
		"api:GET /api/v1/nhi/posture/stale",
		"api:GET /api/v1/nhi/posture/static-credentials",
		"api:GET /api/v1/audit/events",
		"api:GET /api/v1/audit/export",
		"report_type:nhi_compliance_mapping",
	}
}

func nhiComplianceResiduals() []string {
	return []string{
		"trstctl maps tenant evidence to framework controls but does not certify legal or regulatory compliance.",
		"Operator scope, asset criticality, compensating controls, and policy exceptions remain auditor-facing attestations.",
		"DORA, ISO 27001, FedRAMP, CMMC, eIDAS, and NIS2 organization-level governance evidence must be attached by the operator.",
	}
}
