package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// ComplianceEvidencePackFormat is the stable wire marker for signed compliance
// evidence packs. The signed_export field is self-verifying; public_key_der is
// the verifier material an auditor needs offline.
const ComplianceEvidencePackFormat = "trstctl.compliance.evidence-pack.v1"

// ComplianceFramework is the stable path/API value for a governance evidence pack.
type ComplianceFramework string

const (
	CompliancePCIDSS         ComplianceFramework = "pci-dss"
	ComplianceHIPAA          ComplianceFramework = "hipaa"
	ComplianceSOC2           ComplianceFramework = "soc2"
	ComplianceFedRAMP        ComplianceFramework = "fedramp"
	ComplianceCNSA2          ComplianceFramework = "cnsa-2.0"
	ComplianceFIPS140        ComplianceFramework = "fips-140"
	ComplianceCommonCriteria ComplianceFramework = "common-criteria"
	ComplianceCABFBR         ComplianceFramework = "cabf-br"
	ComplianceWebTrust       ComplianceFramework = "webtrust"
	ComplianceETSI           ComplianceFramework = "etsi"
)

var complianceFrameworks = []ComplianceFramework{
	CompliancePCIDSS,
	ComplianceHIPAA,
	ComplianceSOC2,
	ComplianceFedRAMP,
	ComplianceCNSA2,
	ComplianceFIPS140,
	ComplianceCommonCriteria,
	ComplianceCABFBR,
	ComplianceWebTrust,
	ComplianceETSI,
}

var complianceReportTypes = []string{"framework_evidence_pack", "inventory_snapshot", "cbom_posture", "audit_summary", "nhi_compliance_mapping"}

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
	case "fips-140", "fips-140-2", "fips-140-3", "fips140", "fips":
		return ComplianceFIPS140, nil
	case "common-criteria", "commoncriteria", "cc", "iso-15408", "iso15408":
		return ComplianceCommonCriteria, nil
	case "cabf-br", "cabf", "ca-browser-forum", "ca-browser-forum-br", "ca-browser-forum-baseline-requirements":
		return ComplianceCABFBR, nil
	case "webtrust", "web-trust", "webtrust-ca":
		return ComplianceWebTrust, nil
	case "etsi", "etsi-en-319-411", "etsi-en-319-411-1", "etsi-en-319-411-2":
		return ComplianceETSI, nil
	default:
		return "", fmt.Errorf("framework must be one of pci-dss, hipaa, soc2, fedramp, cnsa-2.0, fips-140, common-criteria, cabf-br, webtrust, or etsi")
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

type complianceReportScheduleRequest struct {
	Framework       string `json:"framework"`
	Name            string `json:"name"`
	ReportType      string `json:"report_type"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         *bool  `json:"enabled"`
	Delivery        string `json:"delivery"`
	RecipientRef    string `json:"recipient_ref"`
}

type complianceReportScheduleResponse struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Framework       string    `json:"framework"`
	Name            string    `json:"name"`
	ReportType      string    `json:"report_type"`
	IntervalSeconds int       `json:"interval_seconds"`
	Enabled         bool      `json:"enabled"`
	Delivery        string    `json:"delivery"`
	RecipientRef    string    `json:"recipient_ref"`
	NextRunAt       time.Time `json:"next_run_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type complianceInventoryReport struct {
	Capability   string                             `json:"capability"`
	GeneratedAt  time.Time                          `json:"generated_at"`
	Summary      complianceInventorySummary         `json:"summary"`
	Frameworks   []string                           `json:"frameworks"`
	ReportTypes  []string                           `json:"report_types"`
	Routes       []string                           `json:"routes"`
	EvidenceRefs []string                           `json:"evidence_refs"`
	Schedules    []complianceReportScheduleResponse `json:"schedules"`
}

type complianceInventorySummary struct {
	Certificates           int `json:"certificates"`
	CryptoAssets           int `json:"crypto_assets"`
	DiscoverySchedules     int `json:"discovery_schedules"`
	ReportSchedules        int `json:"report_schedules"`
	EnabledReportSchedules int `json:"enabled_report_schedules"`
	FrameworksSupported    int `json:"frameworks_supported"`
	ReportTypesSupported   int `json:"report_types_supported"`
	InventoryRows          int `json:"inventory_rows"`
}

// WithComplianceEvidence wires the served compliance evidence-pack backend.
func WithComplianceEvidence(svc ComplianceEvidenceService) Option {
	return func(c *config) { c.complianceEvidence = svc }
}

//trstctl:mutation
func (a *API) createComplianceReportSchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req complianceReportScheduleRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		fw, err := ParseComplianceFramework(req.Framework)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name is required")
		}
		reportType := strings.ToLower(strings.TrimSpace(req.ReportType))
		if !validComplianceReportType(reportType) {
			return 0, nil, errStatus(http.StatusBadRequest, "report_type must be one of framework_evidence_pack, inventory_snapshot, cbom_posture, audit_summary, or nhi_compliance_mapping")
		}
		if req.IntervalSeconds <= 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "interval_seconds must be greater than zero")
		}
		delivery := strings.ToLower(strings.TrimSpace(req.Delivery))
		if delivery == "" {
			delivery = "audit_export"
		}
		if delivery != "audit_export" {
			return 0, nil, errStatus(http.StatusBadRequest, "delivery must be audit_export")
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		sched, err := a.orch.UpsertComplianceReportSchedule(ctx, tenantID, store.ComplianceReportSchedule{
			Framework: string(fw), Name: name, ReportType: reportType,
			IntervalSeconds: req.IntervalSeconds, Enabled: enabled,
			Delivery: delivery, RecipientRef: strings.TrimSpace(req.RecipientRef),
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toComplianceReportScheduleResponse(sched), nil
	})
}

func (a *API) listComplianceReportSchedules(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListComplianceReportSchedulesPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]complianceReportScheduleResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toComplianceReportScheduleResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getComplianceInventoryReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	counts, err := a.store.ComplianceInventoryCounts(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	rows, err := a.store.ListComplianceReportSchedulesPage(r.Context(), tenantID, store.ZeroUUID, 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	schedules := make([]complianceReportScheduleResponse, 0, len(rows))
	for _, row := range rows {
		schedules = append(schedules, toComplianceReportScheduleResponse(row))
	}
	frameworks := complianceFrameworkValues()
	out := complianceInventoryReport{
		Capability:  "CAP-OBS-02",
		GeneratedAt: time.Now().UTC(),
		Summary: complianceInventorySummary{
			Certificates:           counts.Certificates,
			CryptoAssets:           counts.CryptoAssets,
			DiscoverySchedules:     counts.DiscoverySchedules,
			ReportSchedules:        counts.ReportSchedules,
			EnabledReportSchedules: counts.EnabledReportSchedules,
			FrameworksSupported:    len(frameworks),
			ReportTypesSupported:   len(complianceReportTypes),
			InventoryRows:          counts.InventoryRows,
		},
		Frameworks:  frameworks,
		ReportTypes: append([]string(nil), complianceReportTypes...),
		Routes: []string{
			"GET /api/v1/compliance/inventory-report",
			"GET /api/v1/compliance/nhi-report",
			"POST /api/v1/compliance/report-schedules",
			"GET /api/v1/compliance/report-schedules",
			"GET /api/v1/compliance/evidence-packs/{framework}",
		},
		EvidenceRefs: []string{
			"event:compliance.report_schedule.upserted",
			"projection:compliance_report_schedules",
			"api:GET /api/v1/compliance/inventory-report",
		},
		Schedules: schedules,
	}
	a.writeJSON(w, http.StatusOK, out)
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

func validComplianceReportType(reportType string) bool {
	for _, typ := range complianceReportTypes {
		if reportType == typ {
			return true
		}
	}
	return false
}

func complianceFrameworkValues() []string {
	out := make([]string, 0, len(complianceFrameworks))
	for _, fw := range complianceFrameworks {
		out = append(out, string(fw))
	}
	return out
}

func toComplianceReportScheduleResponse(s store.ComplianceReportSchedule) complianceReportScheduleResponse {
	return complianceReportScheduleResponse{
		ID: s.ID, TenantID: s.TenantID, Framework: s.Framework, Name: s.Name,
		ReportType: s.ReportType, IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled,
		Delivery: s.Delivery, RecipientRef: s.RecipientRef, NextRunAt: s.NextRunAt,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}
