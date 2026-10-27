// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// The customer assurance report (A187) is one tenant's plain-language account
// of its credentials over a period, in its white-label brand: inventory and
// ownership, expiry, renewals and failures, independent verification, and
// incidents with their evidence, each compared with the previous period. A
// schedule signs it with its rendering inside, and the Provider plane reads a
// customer's signed runs so the Provider can share them.
const (
	customerAssuranceReportType  = "customer_assurance"
	customerAssuranceDefaultDays = 30
	customerAssuranceMaxDays     = 366
	// customerAssuranceRunLimit bounds the signed runs the Provider plane lists.
	customerAssuranceRunLimit = 50
)

var customerAssuranceQuery = []param{
	{name: "days", typ: "integer", desc: "the period's length in days, ending now (1-366, default 30)"},
}

// ReportSigningKey is the public key scheduled reports are signed with, for a
// verifier to pin before it checks a saved report offline.
type ReportSigningKey struct {
	PublicKeyPEM string `json:"public_key_pem"`
	PublicKeyDER []byte `json:"public_key_der"`
	SHA256       string `json:"sha256"`
}

// ReportRunSummary is one completed, signed customer assurance report run.
type ReportRunSummary struct {
	RunID          string    `json:"run_id"`
	ScheduleID     string    `json:"schedule_id"`
	DueAt          time.Time `json:"due_at"`
	CompletedAt    time.Time `json:"completed_at"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
}

// TenantReportReader is what the Provider plane reads of a customer's signed
// customer assurance reports.
type TenantReportReader interface {
	ReportSigningKey() (ReportSigningKey, error)
	CustomerAssuranceRuns(ctx context.Context, tenantID string) ([]ReportRunSummary, error)
	CustomerAssuranceArtifact(ctx context.Context, tenantID, runID string) ([]byte, error)
}

// ProviderTenantServices is the core surface the Provider plane reaches a
// customer tenant through.
type ProviderTenantServices interface {
	TenantBaselineService
	TenantReportReader
}

var (
	// ErrReportSignerUnavailable: no licensed governance signer is attached,
	// so no scheduled report is signed and there is no key to pin.
	ErrReportSignerUnavailable = errors.New("compliance: the licensed, isolated governance report signer is not attached")
	// ErrReportRunNotFound: the tenant has no completed customer assurance
	// report run with that ID.
	ErrReportRunNotFound = errors.New("compliance: no completed customer assurance report run has that id")
	// ErrReportArchiveUnavailable: the signed report could not be read back
	// from the archive and verified.
	ErrReportArchiveUnavailable = errors.New("compliance: the signed report archive is unavailable or failed verification")
)

func (a *API) getCustomerAssuranceReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeError(w, errStatus(http.StatusUnauthorized, "unauthorized"))
		return
	}
	days := customerAssuranceDefaultDays
	if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > customerAssuranceMaxDays {
			a.writeError(w, errStatus(http.StatusBadRequest, fmt.Sprintf("days must be an integer between 1 and %d", customerAssuranceMaxDays)))
			return
		}
		days = n
	}
	now := time.Now().UTC()
	previous, note := a.previousCustomerAssuranceReport(r.Context(), tenantID, "", time.Time{})
	report, err := a.customerAssuranceReport(r.Context(), tenantID, now, now.Add(-time.Duration(days)*24*time.Hour), now, previous, note)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, report)
}

// customerAssuranceReport builds the tenant's report for [from, through),
// reading the inventory at now.
func (a *API) customerAssuranceReport(ctx context.Context, tenantID string, now, from, through time.Time, previous *assurance.CustomerReport, previousNote string) (assurance.CustomerReport, error) {
	facts, err := a.store.CustomerAssuranceFacts(ctx, tenantID, now, from, through, assurance.ExpiringWithin)
	if err != nil {
		return assurance.CustomerReport{}, err
	}
	inventory, err := a.store.ComplianceInventoryCounts(ctx, tenantID)
	if err != nil {
		return assurance.CustomerReport{}, err
	}
	tenant, err := a.store.GetTenant(ctx, tenantID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return assurance.CustomerReport{}, err
	}
	in := assurance.CustomerInputs{
		TenantID: tenantID, TenantName: tenant.Name, Brand: branding.Resolve(ctx, "", tenantID),
		GeneratedAt: now, From: from, Through: through, Facts: facts, Inventory: inventory,
		Previous: previous, PreviousNote: previousNote,
	}
	if a.assurance == nil {
		in.RecordsNote = "Credential assurance records are not available on this deployment, so changed credentials are not classified by how they were verified."
	} else if in.Records, in.RecordsTruncated, err = a.assurance.Recent(ctx, tenantID, from, through); err != nil {
		return assurance.CustomerReport{}, err
	}
	return assurance.BuildCustomerReport(in)
}

// scheduledCustomerAssuranceReport is the customer_assurance payload of one
// scheduled run: the schedule's preceding interval, compared with the
// schedule's previous completed run.
func (a *API) scheduledCustomerAssuranceReport(ctx context.Context, tenantID string, schedule store.ComplianceReportSchedule) (json.RawMessage, error) {
	through := schedule.NextRunAt.UTC()
	from := through.Add(-time.Duration(schedule.IntervalSeconds) * time.Second)
	previous, note := a.previousCustomerAssuranceReport(ctx, tenantID, schedule.ID, through)
	report, err := a.customerAssuranceReport(ctx, tenantID, time.Now().UTC(), from, through, previous, note)
	if err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

func (a *API) previousCustomerAssuranceReport(ctx context.Context, tenantID, scheduleID string, before time.Time) (*assurance.CustomerReport, string) {
	payload, runID, note := a.previousScheduledReport(ctx, tenantID, scheduleID, customerAssuranceReportType, "customer assurance", before)
	if payload == nil {
		return nil, note
	}
	report, err := assurance.CheckCustomerReport(payload)
	if err != nil || report.TenantID != tenantID {
		return nil, "The previous report (run " + runID + ") could not be read and verified, so nothing is compared."
	}
	return &report, ""
}

// previousScheduledReport reads the newest completed reportType report due
// before `before` (any time when zero; scheduleID narrows it to one schedule)
// back from the report archive, verifies it, and returns its payload and run.
// When there is none, or it cannot be read or verified, the note says so and
// the payload is nil.
func (a *API) previousScheduledReport(ctx context.Context, tenantID, scheduleID, reportType, label string, before time.Time) (json.RawMessage, string, string) {
	if !a.complianceReportArchive.Configured() {
		return nil, "", "No report archive is configured, so no previous report can be compared."
	}
	var schedules []string
	if scheduleID != "" {
		schedules = []string{scheduleID}
	} else {
		after := store.ZeroUUID
		for page := 0; page < 10; page++ {
			rows, err := a.store.ListComplianceReportSchedulesPage(ctx, tenantID, after, 100)
			if err != nil {
				return nil, "", "The report schedules could not be read, so no previous report is compared."
			}
			for _, s := range rows {
				if s.ReportType == reportType {
					schedules = append(schedules, s.ID)
				}
			}
			if len(rows) < 100 {
				break
			}
			after = rows[len(rows)-1].ID
		}
	}
	var newest *store.ComplianceReportRun
	for _, id := range schedules {
		runs, err := a.store.ListComplianceReportRunsPage(ctx, tenantID, id, before, 50)
		if err != nil {
			return nil, "", "The report runs could not be read, so no previous report is compared."
		}
		for i := range runs {
			run := runs[i]
			if run.Status != "completed" || run.ReportType != reportType {
				continue
			}
			if newest == nil || run.DueAt.After(newest.DueAt) {
				newest = &run
			}
			break
		}
	}
	if newest == nil {
		return nil, "", "There is no earlier completed scheduled " + label + " report to compare with."
	}
	unread := "The previous report (run " + newest.ID + ") could not be read and verified, so nothing is compared."
	artifact, err := a.complianceReportArchive.Read(ctx, newest.ArtifactRef, newest.TenantID, newest.ID, newest.ArtifactDigest)
	if err != nil || a.VerifyScheduledComplianceArtifact(artifact, *newest) != nil {
		return nil, newest.ID, unread
	}
	var envelope struct {
		Manifest ScheduledComplianceManifest `json:"manifest"`
	}
	if err := json.Unmarshal(artifact, &envelope); err != nil || envelope.Manifest.TenantID != tenantID ||
		envelope.Manifest.ReportType != reportType {
		return nil, newest.ID, unread
	}
	return envelope.Manifest.Payload, newest.ID, ""
}

// ReportSigningKey is the governance key scheduled reports are signed with.
func (a *API) ReportSigningKey() (ReportSigningKey, error) {
	signer, ok := a.complianceEvidence.(ComplianceScheduledSigner)
	if !ok {
		return ReportSigningKey{}, ErrReportSignerUnavailable
	}
	der := signer.ScheduledVerificationKeyDER()
	if len(der) == 0 {
		return ReportSigningKey{}, ErrReportSignerUnavailable
	}
	return ReportSigningKey{
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		PublicKeyDER: der, SHA256: crypto.SHA256Hex(der),
	}, nil
}

func (a *API) getReportSigningKey(w http.ResponseWriter, _ *http.Request) {
	key, err := a.ReportSigningKey()
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, err.Error()))
		return
	}
	a.writeJSON(w, http.StatusOK, key)
}

// CustomerAssuranceRuns lists the tenant's completed customer assurance
// report runs, newest due edge first, at most customerAssuranceRunLimit.
func (a *API) CustomerAssuranceRuns(ctx context.Context, tenantID string) ([]ReportRunSummary, error) {
	out := []ReportRunSummary{}
	after := store.ZeroUUID
	for page := 0; page < 10; page++ {
		schedules, err := a.store.ListComplianceReportSchedulesPage(ctx, tenantID, after, 100)
		if err != nil {
			return nil, err
		}
		for _, s := range schedules {
			if s.ReportType != customerAssuranceReportType {
				continue
			}
			runs, err := a.store.ListComplianceReportRunsPage(ctx, tenantID, s.ID, time.Time{}, customerAssuranceRunLimit)
			if err != nil {
				return nil, err
			}
			for _, run := range runs {
				if run.Status == "completed" && run.ReportType == customerAssuranceReportType {
					out = append(out, ReportRunSummary{
						RunID: run.ID, ScheduleID: run.ScheduleID, DueAt: run.DueAt.UTC(),
						CompletedAt: run.CompletedAt.UTC(), ArtifactSHA256: run.ArtifactDigest,
					})
				}
			}
		}
		if len(schedules) < 100 {
			break
		}
		after = schedules[len(schedules)-1].ID
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].DueAt.Equal(out[j].DueAt) {
			return out[i].DueAt.After(out[j].DueAt)
		}
		return out[i].RunID < out[j].RunID
	})
	if len(out) > customerAssuranceRunLimit {
		out = out[:customerAssuranceRunLimit]
	}
	return out, nil
}

// CustomerAssuranceArtifact reads one completed customer assurance run's
// exact signed bytes back from the archive and verifies them.
func (a *API) CustomerAssuranceArtifact(ctx context.Context, tenantID, runID string) ([]byte, error) {
	if _, err := googleuuid.Parse(runID); err != nil {
		return nil, ErrReportRunNotFound
	}
	run, err := a.store.GetComplianceReportRun(ctx, tenantID, runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrReportRunNotFound
	}
	if err != nil {
		return nil, err
	}
	if run.Status != "completed" || run.ReportType != customerAssuranceReportType {
		return nil, ErrReportRunNotFound
	}
	artifact, err := a.complianceReportArchive.Read(ctx, run.ArtifactRef, run.TenantID, run.ID, run.ArtifactDigest)
	if err != nil || a.VerifyScheduledComplianceArtifact(artifact, run) != nil {
		return nil, ErrReportArchiveUnavailable
	}
	return artifact, nil
}

func customerAssuranceSchemas() map[string]*Schema {
	count := func(desc string) *Schema { return &Schema{Type: "integer", Description: desc} }
	certificate := object(map[string]*Schema{
		"id": uuid(), "subject": str(), "not_after": timestamp(), "owner": str(),
	}, "id", "subject")
	return map[string]*Schema{
		"CustomerAssuranceCertificate": certificate,
		"CustomerAssuranceReport": object(map[string]*Schema{
			"format": str(), "tenant_id": uuid(), "tenant_name": str(),
			"brand": object(map[string]*Schema{
				"product_name":  str(),
				"logo_data_uri": {Type: "string", Description: "The brand's logo when it is a PNG, JPEG, GIF or WebP data URI of at most 256 KiB."},
				"accent":        {Type: "string", Description: "The token_overrides accent color as #rgb or #rrggbb, or the default."},
				"footer":        str(),
				"custom":        {Type: "boolean", Description: "False when the tenant has no white-label brand."},
			}, "product_name", "accent", "custom"),
			"period_from": timestamp(), "period_through": timestamp(), "generated_at": timestamp(),
			"summary": {Type: "array", Items: str(), Description: "The report in a few plain sentences."},
			"inventory": object(map[string]*Schema{
				"active_certificates": count(""), "owned_certificates": count(""),
				"ownership_coverage_percent": count("Rounded down; absent with no active certificate."),
				"unowned":                    {Type: "array", Items: ref("CustomerAssuranceCertificate"), Description: "Unowned certificates, soonest expiry first, at most 10."},
				"crypto_assets":              count(""), "discovery_inventory_rows": count(""),
			}, "active_certificates", "owned_certificates", "unowned", "crypto_assets", "discovery_inventory_rows"),
			"credentials": object(map[string]*Schema{
				"expiring_within_days": count(""), "expiring": count(""),
				"expiring_soonest": {Type: "array", Items: ref("CustomerAssuranceCertificate"), Description: "At most 10, soonest first."},
				"expired_active":   count("Active certificates already past not_after."),
				"added":            count(""), "renewed": count(""), "revoked": count(""),
				"failed_renewals": count(""), "failed_deliveries": count(""),
				"failures": {Type: "array", Items: object(map[string]*Schema{
					"kind": {Type: "string", Enum: []string{"renewal", "delivery"}}, "id": uuid(), "subject": str(), "via": str(),
					"status": str(), "reason": str(), "at": timestamp(),
				}, "kind", "id", "subject", "status", "at"), Description: "At most 10, newest first."},
			}, "expiring_within_days", "expiring", "expiring_soonest", "expired_active", "added", "renewed", "revoked", "failed_renewals", "failed_deliveries", "failures"),
			"verification": object(map[string]*Schema{
				"verified_deliveries": count(""), "endpoint_observations": count("The latest observation per endpoint and vantage."),
				"endpoints_matching": count(""), "endpoints_mismatched": count(""), "endpoints_unreachable": count(""),
				"endpoints_checked_in_period":   count(""),
				"changed_credentials":           count("Credentials whose lifecycle changed in the period, at most 50."),
				"changed_credentials_truncated": {Type: "boolean"},
				"independently_verified":        count("Seen served from outside the product's own record."),
				"recorded_only":                 count(""), "not_verified": count(""),
				"note": str(),
			}, "verified_deliveries", "endpoint_observations", "endpoints_matching", "endpoints_mismatched", "endpoints_unreachable", "endpoints_checked_in_period", "changed_credentials", "independently_verified", "recorded_only", "not_verified"),
			"incidents": object(map[string]*Schema{
				"in_period": count("Incident runs open or updated in the period."), "opened_in_period": count(""), "open": count(""),
				"items": {Type: "array", Items: object(map[string]*Schema{
					"kind": {Type: "string", Enum: []string{"credential_compromise", "issuer_compromise"}}, "id": uuid(),
					"status": str(), "phase": str(), "reason": str(), "opened_at": timestamp(), "updated_at": timestamp(),
					"evidence_format": str(), "evidence_sha256": str(),
					"evidence": {Type: "string", Description: "The incident's evidence bundle when it is at most 64 KiB."},
				}, "kind", "id", "status", "phase", "opened_at", "updated_at"), Description: "At most 10, newest first."},
			}, "in_period", "opened_in_period", "open", "items"),
			"changes": object(map[string]*Schema{
				"comparable": {Type: "boolean"}, "note": str(),
				"previous_period_from": timestamp(), "previous_period_through": timestamp(), "previous_generated_at": timestamp(),
				"metrics": {Type: "array", Items: object(map[string]*Schema{
					"key": str(), "label": str(), "previous": count(""), "current": count(""), "delta": count(""), "sentence": str(),
				}, "key", "label", "previous", "current", "delta", "sentence")},
			}, "comparable", "metrics"),
			"limits":      {Type: "array", Items: str(), Description: "What the report does not establish."},
			"html":        {Type: "string", Description: "The branded, self-contained HTML rendering."},
			"html_sha256": str(),
		}, "format", "tenant_id", "tenant_name", "brand", "period_from", "period_through", "generated_at", "summary", "inventory", "credentials", "verification", "incidents", "changes", "limits", "html", "html_sha256"),
		"ReportSigningKey": object(map[string]*Schema{
			"public_key_pem": str(),
			"public_key_der": {Type: "string", Format: "byte"},
			"sha256":         {Type: "string", Description: "SHA-256 of the DER public key, to compare over an independent channel."},
		}, "public_key_pem", "public_key_der", "sha256"),
	}
}
