// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/cryptoreadiness"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// ComplianceEvidencePackFormat is the stable wire marker for signed compliance
// evidence packs. Version 5 binds the signed manifest to a tenant and bounded
// evidence window, carries exact immutable event/object references plus
// missing prerequisites, and includes certificate-custody counts plus explicit
// incomplete rows, complete AD CS posture/drift evidence, and the canonical
// crypto-readiness dataset/actions. The signed_export field is self-verifying;
// public_key_der is the verifier material an auditor needs offline.
const ComplianceEvidencePackFormat = "trstctl.compliance.evidence-pack.v5"

// ComplianceFramework is the stable path/API value for a governance evidence pack.
type ComplianceFramework string

const (
	CompliancePCIDSS         ComplianceFramework = "pci-dss"
	ComplianceHIPAA          ComplianceFramework = "hipaa"
	ComplianceSOC2           ComplianceFramework = "soc2"
	ComplianceNIST80053      ComplianceFramework = "nist-800-53"
	ComplianceNISTCSF20      ComplianceFramework = "nist-csf-2.0"
	ComplianceFedRAMP        ComplianceFramework = "fedramp"
	ComplianceCMMC20         ComplianceFramework = "cmmc-2.0"
	ComplianceCNSA2          ComplianceFramework = "cnsa-2.0"
	ComplianceFIPS140        ComplianceFramework = "fips-140"
	ComplianceCommonCriteria ComplianceFramework = "common-criteria"
	ComplianceCABFBR         ComplianceFramework = "cabf-br"
	ComplianceWebTrust       ComplianceFramework = "webtrust"
	ComplianceETSI           ComplianceFramework = "etsi"
	ComplianceEIDAS          ComplianceFramework = "eidas"
	ComplianceNIS2           ComplianceFramework = "nis2"
)

var complianceFrameworks = []ComplianceFramework{
	CompliancePCIDSS,
	ComplianceHIPAA,
	ComplianceSOC2,
	ComplianceNIST80053,
	ComplianceNISTCSF20,
	ComplianceFedRAMP,
	ComplianceCMMC20,
	ComplianceCNSA2,
	ComplianceFIPS140,
	ComplianceCommonCriteria,
	ComplianceCABFBR,
	ComplianceWebTrust,
	ComplianceETSI,
	ComplianceEIDAS,
	ComplianceNIS2,
}

var complianceReportTypes = []string{"framework_evidence_pack", "inventory_snapshot", "cbom_posture", "audit_summary", "nhi_compliance_mapping"}

const (
	minComplianceReportIntervalSeconds = 60 * 60
	maxComplianceReportIntervalSeconds = 366 * 24 * 60 * 60
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
	case "nist-800-53", "nist80053", "nist-sp-800-53", "nist-sp800-53", "sp-800-53", "800-53":
		return ComplianceNIST80053, nil
	case "nist-csf-2.0", "nist-csf-2", "nist-csf", "csf-2.0", "csf2", "csf":
		return ComplianceNISTCSF20, nil
	case "fedramp":
		return ComplianceFedRAMP, nil
	case "cmmc-2.0", "cmmc-2", "cmmc2", "cmmc":
		return ComplianceCMMC20, nil
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
	case "eidas", "eidas-2.0", "eidas2", "electronic-identification-trust-services":
		return ComplianceEIDAS, nil
	case "nis2", "nis-2", "nis2-directive", "directive-2022-2555":
		return ComplianceNIS2, nil
	default:
		return "", fmt.Errorf("framework must be one of %s", strings.Join(complianceFrameworkValues(), ", "))
	}
}

// ComplianceEvidenceService generates tenant-scoped, signed compliance evidence
// packs from the audit log and CBOM graph.
type ComplianceEvidenceService interface {
	ExportEvidencePack(ctx context.Context, tenantID string, framework ComplianceFramework) (ComplianceEvidencePack, error)
}

// ComplianceScheduledSigner is the licensed signing seam for a completed
// scheduled-report manifest. The API assembles the tenant/run-bound data; the
// Enterprise service signs it through the isolated compliance-evidence key.
// Keeping this optional preserves core read/export routes while a missing
// licensed signer makes scheduled execution fail closed.
type ComplianceScheduledSigner interface {
	SignScheduledManifest(ctx context.Context, manifest json.RawMessage) (json.RawMessage, error)
	ScheduledVerificationKeyDER() []byte
}

// ComplianceEvidencePack is the served response for a signed framework export.
type ComplianceEvidencePack struct {
	Format       string          `json:"format"`
	Framework    string          `json:"framework"`
	SignedExport json.RawMessage `json:"signed_export"`
	PublicKeyDER []byte          `json:"public_key_der"`
	// Custody is a convenience projection of the exact summary inside the
	// signed manifest. Offline verifiers treat signed_export.manifest.custody as
	// authoritative; the outer copy lets API and console clients render it
	// without implementing envelope decoding first.
	Custody custody.CertificateSummary `json:"custody"`
	// ADCS is the convenience copy of signed_export.manifest.adcs. The signed
	// manifest is authoritative; this copy lets API/console clients render the
	// exact relay findings without first decoding the signed envelope.
	ADCS ADCSComplianceEvidence `json:"adcs"`
	// CryptoReadiness is the convenience copy of the exact canonical dataset in
	// the signed manifest. Its digest lets API, Posture, Risk, workflow, and an
	// offline auditor prove they consumed the same ordered topology/actions.
	CryptoReadiness cryptoreadiness.Dataset `json:"crypto_readiness"`
}

// ADCSAuditReference binds a rendered posture fact to its immutable tenant
// audit-chain entry. Digest is the record's chain hash, not a mutable row hash.
type ADCSAuditReference struct {
	EventID    string    `json:"event_id"`
	EventType  string    `json:"event_type"`
	Sequence   uint64    `json:"sequence"`
	Digest     string    `json:"digest"`
	ObservedAt time.Time `json:"observed_at"`
}

// ADCSComplianceObservation is the latest complete v2 relay observation for a
// domain within the signed evidence window.
type ADCSComplianceObservation struct {
	Reference         ADCSAuditReference `json:"reference"`
	RunID             string             `json:"run_id"`
	SourceID          string             `json:"source_id"`
	Domain            string             `json:"domain"`
	AgentID           string             `json:"agent_id"`
	AgentName         string             `json:"agent_name"`
	DirectoryVerified bool               `json:"directory_verified"`
	Inventory         adcs.Inventory     `json:"inventory"`
	Findings          []adcs.Finding     `json:"findings"`
}

// ADCSComplianceDrift is one source/run-bound semantic change in the same
// signed window. It intentionally repeats the human-checkable before/after
// facts served by the Posture console.
type ADCSComplianceDrift struct {
	Reference  ADCSAuditReference            `json:"reference"`
	RunID      string                        `json:"run_id"`
	SourceID   string                        `json:"source_id"`
	Domain     string                        `json:"domain"`
	AgentID    string                        `json:"agent_id"`
	ObservedBy string                        `json:"observed_by"`
	Direction  string                        `json:"direction"`
	Worsened   bool                          `json:"worsened"`
	Changes    []ADCSTemplateDriftChange     `json:"changes"`
	Lifecycle  []ADCSTemplateLifecycleChange `json:"lifecycle"`
}

// ADCSComplianceEvidence is the tenant-scoped posture/drift artifact copied
// inside and outside the signed manifest.
type ADCSComplianceEvidence struct {
	Observations []ADCSComplianceObservation `json:"observations"`
	Drift        []ADCSComplianceDrift       `json:"drift"`
}

type complianceReportScheduleRequest struct {
	Framework       string `json:"framework"`
	Name            string `json:"name"`
	ReportType      string `json:"report_type"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         *bool  `json:"enabled"`
	Delivery        string `json:"delivery"`
	RecipientRef    string `json:"recipient_ref"`
	// Dispatch announces each completed run on named notification channels
	// and in one ServiceNow ticket (A103); the archive stays the record.
	Dispatch *store.ComplianceReportDispatch `json:"dispatch,omitempty"`
}

type complianceReportScheduleResponse struct {
	ID              string `json:"id"`
	TenantID        string `json:"tenant_id"`
	Framework       string `json:"framework"`
	Name            string `json:"name"`
	ReportType      string `json:"report_type"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         bool   `json:"enabled"`
	Delivery        string `json:"delivery"`
	RecipientRef    string `json:"recipient_ref"`
	// Dispatch is absent for an archive-only schedule.
	Dispatch  *store.ComplianceReportDispatch `json:"dispatch,omitempty"`
	NextRunAt time.Time                       `json:"next_run_at"`
	CreatedAt time.Time                       `json:"created_at"`
	UpdatedAt time.Time                       `json:"updated_at"`
}

type complianceReportSchedulePreviewResponse struct {
	Capability             string                          `json:"capability"`
	Operation              string                          `json:"operation"`
	Ready                  bool                            `json:"ready"`
	EffectFree             bool                            `json:"effect_free"`
	RequestFingerprint     string                          `json:"request_fingerprint"`
	RequiredPermission     string                          `json:"required_permission"`
	NormalizedRequest      complianceReportScheduleRequest `json:"normalized_request"`
	Blockers               []string                        `json:"blockers"`
	Warnings               []string                        `json:"warnings"`
	PreviewWrites          []string                        `json:"preview_writes"`
	PreviewExternalEffects []string                        `json:"preview_external_effects"`
	ExecuteWrites          []string                        `json:"execute_writes"`
	ExecuteExternalEffects []string                        `json:"execute_external_effects"`
	RecoverySteps          []string                        `json:"recovery_steps"`
	VerificationSteps      []string                        `json:"verification_steps"`
	SecretDataHandling     string                          `json:"secret_data_handling"`
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

// WithComplianceReportArchive binds scheduled reports to a private durable
// directory under the operator's audit archive mount.
func WithComplianceReportArchive(root string) Option {
	return func(c *config) { c.complianceReportArchive.Dir.Root = root }
}

// WithComplianceReportObjectStore keeps new scheduled report artifacts in the
// object store under each tenant's prefix (audit.archive_object_store). A
// directory bound alongside it stays readable for earlier artifacts.
func WithComplianceReportObjectStore(store objectstore.Store) Option {
	return func(c *config) { c.complianceReportArchive.Objects = store }
}

func (a *API) complianceReportBlockers() []string {
	blockers := []string{}
	signer, ok := a.complianceEvidence.(ComplianceScheduledSigner)
	if !ok || len(signer.ScheduledVerificationKeyDER()) == 0 {
		blockers = append(blockers, "The licensed, isolated governance report signer is not attached.")
	}
	if err := a.complianceReportArchive.Ready(); err != nil {
		blockers = append(blockers, "Configure audit.archive_dir as a mounted private 0700 directory writable by the control plane, or audit.archive_object_store with an object store.")
	}
	return blockers
}

// previewComplianceReportSchedule is a POST-shaped read because the exact
// unsaved definition is structured. It calls the execution validator but does
// not append an event, reserve an idempotency key, project a row, generate a
// report, or contact a delivery destination.
func (a *API) previewComplianceReportSchedule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req complianceReportScheduleRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	normalized, err := normalizeComplianceReportScheduleRequest(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	fingerprintBody, err := json.Marshal(struct {
		Domain   string                          `json:"domain"`
		TenantID string                          `json:"tenant_id"`
		Request  complianceReportScheduleRequest `json:"request"`
	}{
		Domain: "trstctl.api.compliance-report-schedule-preview.v1", TenantID: tenantID, Request: normalized,
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	warnings := []string{}
	blockers := append(a.complianceReportBlockers(), a.complianceReportDispatchBlockers(r.Context(), tenantID, normalized.Dispatch)...)
	executeEffects := complianceReportDispatchEffects(normalized.Dispatch)
	if normalized.Enabled != nil && !*normalized.Enabled {
		warnings = append(warnings, "This definition will be saved paused, so no run becomes due until an operator resumes it.")
	}
	a.writeJSON(w, http.StatusOK, complianceReportSchedulePreviewResponse{
		Capability: "F62", Operation: "create_report_schedule", Ready: len(blockers) == 0, EffectFree: true,
		RequestFingerprint: crypto.SHA256Hex(fingerprintBody), RequiredPermission: string(authz.AuditWrite),
		NormalizedRequest: normalized, Blockers: blockers, Warnings: warnings,
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"Append one tenant-scoped compliance.report_schedule.upserted event.",
			"Project one report definition with its cadence, enabled state, destination reference, and next due time.",
		},
		ExecuteExternalEffects: executeEffects,
		RecoverySteps: []string{
			"Pause the schedule before its next run; already retained evidence is not deleted.",
			"Inspect failed run receipts, correct the signer or archive dependency, then requeue the exact due edge with an Idempotency-Key.",
			"Correct the definition by creating a reviewed replacement, then resume only the intended schedule.",
		},
		VerificationSteps: []string{
			"Read GET /api/v1/compliance/report-schedules and match the exact definition and enabled state.",
			"Read GET /api/v1/compliance/inventory-report and confirm schedule and enabled-schedule totals.",
			"After the due time, read the schedule's run receipts and download the exact signed artifact; compare its SHA-256 with the completed receipt.",
		},
		SecretDataHandling: "recipient_ref is an optional correlation label only; it does not route or change the archive destination. Dispatch notices and the ticket carry the run, its digest and its download route, never the report body; the ticket's token_ref names an operator-approved credential reference resolved only at egress. Preview neither resolves nor returns a credential, report body, private key, or secret value.",
	})
}

//trstctl:mutation
func (a *API) createComplianceReportSchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req complianceReportScheduleRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		normalized, err := normalizeComplianceReportScheduleRequest(req)
		if err != nil {
			return 0, nil, err
		}
		if blockers := a.complianceReportBlockers(); len(blockers) != 0 {
			return 0, nil, errStatus(http.StatusServiceUnavailable, strings.Join(blockers, " "))
		}
		if blockers := a.complianceReportDispatchBlockers(ctx, tenantID, normalized.Dispatch); len(blockers) != 0 {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, strings.Join(blockers, " "))
		}
		sched, err := a.orch.UpsertComplianceReportSchedule(ctx, tenantID, store.ComplianceReportSchedule{
			Framework: normalized.Framework, Name: normalized.Name, ReportType: normalized.ReportType,
			IntervalSeconds: normalized.IntervalSeconds, Enabled: *normalized.Enabled,
			Delivery: normalized.Delivery, RecipientRef: normalized.RecipientRef, Dispatch: normalized.Dispatch,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toComplianceReportScheduleResponse(sched), nil
	})
}

func normalizeComplianceReportScheduleRequest(req complianceReportScheduleRequest) (complianceReportScheduleRequest, error) {
	fw, err := ParseComplianceFramework(req.Framework)
	if err != nil {
		return complianceReportScheduleRequest{}, errStatus(http.StatusBadRequest, err.Error())
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return complianceReportScheduleRequest{}, errStatus(http.StatusBadRequest, "name is required")
	}
	if len(name) > 160 {
		return complianceReportScheduleRequest{}, errStatus(http.StatusBadRequest, "name must be 160 characters or fewer")
	}
	reportType := strings.ToLower(strings.TrimSpace(req.ReportType))
	if !validComplianceReportType(reportType) {
		return complianceReportScheduleRequest{}, errStatus(http.StatusBadRequest, "report_type must be one of framework_evidence_pack, inventory_snapshot, cbom_posture, audit_summary, or nhi_compliance_mapping")
	}
	if req.IntervalSeconds < minComplianceReportIntervalSeconds || req.IntervalSeconds > maxComplianceReportIntervalSeconds {
		return complianceReportScheduleRequest{}, errStatus(http.StatusBadRequest, "interval_seconds must be between 3600 and 31622400")
	}
	delivery := strings.ToLower(strings.TrimSpace(req.Delivery))
	if delivery == "" {
		delivery = "audit_export"
	}
	if delivery != "audit_export" {
		return complianceReportScheduleRequest{}, errStatus(http.StatusBadRequest, "delivery must be audit_export")
	}
	recipientRef := strings.TrimSpace(req.RecipientRef)
	if len(recipientRef) > 256 {
		return complianceReportScheduleRequest{}, errStatus(http.StatusBadRequest, "recipient_ref must be 256 characters or fewer")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	dispatch, err := normalizeComplianceReportDispatch(req.Dispatch)
	if err != nil {
		return complianceReportScheduleRequest{}, err
	}
	return complianceReportScheduleRequest{
		Framework: string(fw), Name: name, ReportType: reportType,
		IntervalSeconds: req.IntervalSeconds, Enabled: &enabled,
		Delivery: delivery, RecipientRef: recipientRef, Dispatch: dispatch,
	}, nil
}

// maxComplianceReportDispatchChannels bounds one schedule's notices per run.
const maxComplianceReportDispatchChannels = 8

var complianceReportChannelID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// normalizeComplianceReportDispatch canonicalizes a schedule's dispatch (A103):
// channel IDs as the notification API spells them, deduplicated, and one
// ServiceNow ticket with a normalized instance URL and table. Whether a
// channel is configured and the ticket's binding approved depends on tenant
// and operator configuration, which complianceReportDispatchBlockers checks.
func normalizeComplianceReportDispatch(in *store.ComplianceReportDispatch) (*store.ComplianceReportDispatch, error) {
	if in == nil {
		return nil, nil
	}
	out := &store.ComplianceReportDispatch{}
	seen := map[string]bool{}
	for _, raw := range in.Channels {
		id := canonicalNotificationChannelID(raw)
		if !complianceReportChannelID.MatchString(id) {
			return nil, errStatus(http.StatusBadRequest, "dispatch.channels must name notification channel IDs")
		}
		if !seen[id] {
			seen[id] = true
			out.Channels = append(out.Channels, id)
		}
	}
	if len(out.Channels) > maxComplianceReportDispatchChannels {
		return nil, errStatus(http.StatusBadRequest, "dispatch.channels names at most 8 channels")
	}
	if t := in.Ticket; t != nil {
		if provider := strings.ToLower(strings.TrimSpace(t.Provider)); provider != "servicenow" {
			return nil, errStatus(http.StatusBadRequest, "dispatch.ticket.provider must be servicenow")
		}
		instanceURL, err := normalizeServiceNowInstanceURL(t.InstanceURL)
		if err != nil {
			return nil, errStatus(http.StatusBadRequest, "dispatch.ticket.instance_url must be an absolute HTTP(S) URL without credentials, query, or fragment")
		}
		table, ok := orchestrator.NormalizeServiceNowTable(t.Table)
		if !ok {
			return nil, errStatus(http.StatusBadRequest, "dispatch.ticket.table must be incident, change_request, or sc_task")
		}
		tokenRef := strings.TrimSpace(t.TokenRef)
		if tokenRef == "" || len(tokenRef) > 256 {
			return nil, errStatus(http.StatusBadRequest, "dispatch.ticket.token_ref must name a credential reference")
		}
		out.Ticket = &store.ComplianceReportTicket{Provider: "servicenow", InstanceURL: instanceURL, Table: table, TokenRef: tokenRef}
	}
	if out.Empty() {
		return nil, nil
	}
	return out, nil
}

// complianceReportDispatchBlockers checks a dispatch against configuration:
// each channel must be a configured channel of this tenant, and the ticket
// must match an operator-approved ServiceNow binding, so a schedule cannot
// send a credential to a destination the operator never approved.
func (a *API) complianceReportDispatchBlockers(ctx context.Context, tenantID string, d *store.ComplianceReportDispatch) []string {
	if d.Empty() {
		return nil
	}
	var blockers []string
	for _, channel := range d.Channels {
		if _, err := a.notificationChannelForTest(ctx, tenantID, channel); err != nil {
			detail := "it could not be checked"
			var apiErr *apiError
			if errors.As(err, &apiErr) {
				detail = apiErr.detail
			}
			blockers = append(blockers, "Notification channel "+channel+" cannot receive report notices: "+detail+".")
		}
	}
	if t := d.Ticket; t != nil && !a.ComplianceReportTicketApproved(*t) {
		blockers = append(blockers, "The report ticket's instance_url and token_ref must match an operator-approved public ServiceNow binding.")
	}
	return blockers
}

// ComplianceReportTicketApproved reports whether a schedule's ticket still
// matches an operator-approved public ServiceNow binding. The report worker
// asks again at each completion, so withdrawing a binding stops new tickets.
func (a *API) ComplianceReportTicketApproved(t store.ComplianceReportTicket) bool {
	if a == nil {
		return false
	}
	_, err := a.approvedServiceNowBinding(serviceNowTicketRequest{InstanceURL: t.InstanceURL, TokenRef: t.TokenRef}, false)
	return err == nil
}

func complianceReportDispatchEffects(d *store.ComplianceReportDispatch) []string {
	effects := []string{}
	if d.Empty() {
		return effects
	}
	for _, channel := range d.Channels {
		effects = append(effects, "After each completed run, queue one compliance.report_ready notice on notification channel "+channel+" naming the run, its SHA-256 and its download route; never the report body.")
	}
	if d.Ticket != nil {
		effects = append(effects, "After each completed run, queue one ServiceNow "+d.Ticket.Table+" ticket at "+d.Ticket.InstanceURL+" correlated to the run ID.")
	}
	return effects
}

//trstctl:mutation
func (a *API) pauseComplianceReportSchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.setComplianceReportScheduleEnabled(w, r, idempotencyKey, false)
}

//trstctl:mutation
func (a *API) resumeComplianceReportSchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.setComplianceReportScheduleEnabled(w, r, idempotencyKey, true)
}

func (a *API) setComplianceReportScheduleEnabled(w http.ResponseWriter, r *http.Request, idempotencyKey string, enabled bool) {
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		id := strings.TrimSpace(r.PathValue("id"))
		if parsed, err := googleuuid.Parse(id); err != nil || parsed == googleuuid.Nil {
			return 0, nil, errStatus(http.StatusBadRequest, "report schedule id must be a non-zero UUID")
		}
		current, err := a.store.GetComplianceReportSchedule(ctx, tenantID, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, errStatus(http.StatusNotFound, "compliance report schedule not found")
		}
		if err != nil {
			return 0, nil, err
		}
		if current.Enabled == enabled {
			return http.StatusOK, toComplianceReportScheduleResponse(current), nil
		}
		if enabled {
			if blockers := a.complianceReportBlockers(); len(blockers) != 0 {
				return 0, nil, errStatus(http.StatusServiceUnavailable, strings.Join(blockers, " "))
			}
		}
		current.Enabled = enabled
		updated, err := a.orch.UpsertComplianceReportSchedule(ctx, tenantID, current)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toComplianceReportScheduleResponse(updated), nil
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
			"POST /api/v1/compliance/report-schedules/preview",
			"POST /api/v1/compliance/report-schedules",
			"GET /api/v1/compliance/report-schedules",
			"POST /api/v1/compliance/report-schedules/{id}/pause",
			"POST /api/v1/compliance/report-schedules/{id}/resume",
			"GET /api/v1/compliance/report-schedules/{id}/runs",
			"GET /api/v1/compliance/report-runs/{id}",
			"GET /api/v1/compliance/report-runs/{id}/artifact",
			"POST /api/v1/compliance/report-runs/{id}/requeue",
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
		Delivery: s.Delivery, RecipientRef: s.RecipientRef, Dispatch: s.Dispatch, NextRunAt: s.NextRunAt,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}
