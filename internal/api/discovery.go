// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cbom/coverage"
	"trstctl.com/trstctl/internal/discovery"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/discovery/apikey"
	"trstctl.com/trstctl/internal/discovery/compromise"
	"trstctl.com/trstctl/internal/discovery/k8stls"
	"trstctl.com/trstctl/internal/discovery/nhi"
	"trstctl.com/trstctl/internal/discovery/nhibehavior"
	"trstctl.com/trstctl/internal/discovery/oauthgrant"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/discovery/serviceaccount"
	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type discoverySourceRequest struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

type discoverySourceResponse struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type discoveryPlanPreviewResponse struct {
	Kind                  string   `json:"kind"`
	Execution             string   `json:"execution"`
	Protocol              string   `json:"protocol,omitempty"`
	ConnectionOrigin      string   `json:"connection_origin"`
	Segment               string   `json:"segment,omitempty"`
	NormalizedTargets     []string `json:"normalized_targets,omitempty"`
	NormalizedTargetCount int      `json:"normalized_target_count"`
	PreviewTruncated      bool     `json:"preview_truncated"`
	ExcludedTargetCount   int      `json:"excluded_target_count"`
	AppliedExclusions     []string `json:"applied_exclusions,omitempty"`
	ChildJobCount         int      `json:"child_job_count"`
	Concurrency           int      `json:"concurrency"`
	QueueDepth            int      `json:"queue_depth"`
	EstimatedUpperSeconds int      `json:"estimated_upper_seconds"`
	Permission            string   `json:"permission"`
	DataHandling          string   `json:"data_handling"`
	SideEffects           bool     `json:"side_effects"`
	BlockedReasons        []string `json:"blocked_reasons"`
}

// listDiscoveryCapabilities serves the exact typed configuration contract used
// by the console and CLI. It is process capability metadata, but remains behind
// discovery:read so anonymous callers cannot fingerprint the enabled product.
func (a *API) listDiscoveryCapabilities(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, sourcecatalog.All())
}

// previewDiscoveryPlan is a state-free server oracle for the exact scope the
// candidate would accept. The browser does not recreate segment, relay, range,
// exclusion, or provider policy decisions locally.
func (a *API) previewDiscoveryPlan(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req discoverySourceRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = "Discovery plan preview"
	}
	cfg, err := validateDiscoverySourceRequest(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.requireDiscoveryCredentialRefsAllowed(cfg); err != nil {
		a.writeError(w, err)
		return
	}
	capability, _ := sourcecatalog.Find(strings.TrimSpace(req.Kind))
	preview := discoveryPlanPreviewResponse{
		Kind: req.Kind, Execution: capability.Execution, ConnectionOrigin: capability.Execution,
		Permission: capability.Permission, DataHandling: capability.DataHandling,
		SideEffects: false, BlockedReasons: []string{}, AppliedExclusions: []string{},
		ChildJobCount: 1,
	}
	if req.Kind == "network" || req.Kind == "ssh" {
		intent, resolveErr := segmentscan.Resolve(req.Kind, cfg)
		if resolveErr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, resolveErr.Error()))
			return
		}
		segment, segmentErr := a.store.GetDiscoverySegmentByName(r.Context(), tenantID, intent.Segment)
		if segmentErr != nil {
			message := "declared segment could not be read"
			if store.IsNotFound(segmentErr) {
				message = "segment must be declared before previewing a network or SSH source"
			}
			a.writeError(w, errStatus(http.StatusBadRequest, message))
			return
		}
		if segment.Excluded {
			a.writeError(w, errStatus(http.StatusBadRequest, "an excluded segment cannot back an executable discovery source"))
			return
		}
		if scopeErr := segmentscan.ValidateDeclaredSegment(intent, segment.Ranges); scopeErr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, scopeErr.Error()))
			return
		}
		if relayErr := a.validateDiscoveryRelay(r.Context(), tenantID, intent.RequiredAgentID); relayErr != nil {
			a.writeError(w, relayErr)
			return
		}
		const previewTargetLimit = 100
		preview.Protocol = intent.Mode
		preview.ConnectionOrigin = "eligible active network-role relay"
		if intent.RequiredAgentID != "" {
			preview.ConnectionOrigin = "network relay " + intent.RequiredAgentID
		}
		preview.Segment = intent.Segment
		preview.NormalizedTargetCount = len(intent.Targets)
		preview.NormalizedTargets = append([]string(nil), intent.Targets...)
		if len(preview.NormalizedTargets) > previewTargetLimit {
			preview.NormalizedTargets = preview.NormalizedTargets[:previewTargetLimit]
			preview.PreviewTruncated = true
		}
		preview.ExcludedTargetCount = intent.ExcludedTargets
		preview.AppliedExclusions = append([]string(nil), intent.AppliedExclusions...)
		preview.Concurrency = 16
		preview.QueueDepth = 256
		// One bounded handshake attempt can consume roughly ten seconds. This is
		// a deliberately conservative upper estimate, not a completion promise.
		preview.EstimatedUpperSeconds = ((len(intent.Targets) + preview.Concurrency - 1) / preview.Concurrency) * 10
	}
	a.writeJSON(w, http.StatusOK, preview)
}

func (a *API) validateDiscoveryRelay(ctx context.Context, tenantID, relayAgentID string) error {
	if relayAgentID == "" {
		return nil
	}
	agent, err := a.store.GetAgent(ctx, tenantID, relayAgentID)
	if err != nil {
		return errStatus(http.StatusBadRequest, "relay_agent_id must name an enrolled tenant agent")
	}
	if agent.Status == "offboarded" || !sourceKindsContain(agent.Roles, segmentscan.RequiredRoleNetwork) {
		return errStatus(http.StatusBadRequest, "relay_agent_id must name an active network-role agent")
	}
	return nil
}

type discoverySegmentRequest struct {
	Name            string   `json:"name"`
	Ranges          []string `json:"ranges"`
	StalenessHours  int      `json:"staleness_hours"`
	Excluded        bool     `json:"excluded"`
	ExclusionReason string   `json:"exclusion_reason"`
}

type discoverySegmentResponse struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Ranges          []string   `json:"ranges"`
	StalenessHours  int        `json:"staleness_hours"`
	Excluded        bool       `json:"excluded"`
	ExclusionReason string     `json:"exclusion_reason"`
	LastSweptAt     *time.Time `json:"last_swept_at,omitempty"`
	LastSweptBy     string     `json:"last_swept_by,omitempty"`
	LastFoundCount  int        `json:"last_found_count"`
	CreatedAt       time.Time  `json:"created_at"`
}

type discoveryScheduleRequest struct {
	SourceID        string `json:"source_id"`
	Name            string `json:"name"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         *bool  `json:"enabled"`
}

type discoveryScheduleResponse struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	SourceID        string    `json:"source_id"`
	Name            string    `json:"name"`
	IntervalSeconds int       `json:"interval_seconds"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type discoveryRunRequest struct {
	SourceID   string `json:"source_id"`
	ScheduleID string `json:"schedule_id"`
	DryRun     bool   `json:"dry_run"`
}

type discoveryRunResponse struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	SourceID          string     `json:"source_id"`
	ScheduleID        *string    `json:"schedule_id"`
	Status            string     `json:"status"`
	DryRun            bool       `json:"dry_run"`
	RequestedBy       string     `json:"requested_by"`
	Execution         string     `json:"execution"`
	Segment           string     `json:"segment"`
	RequiredAgentRole string     `json:"required_agent_role"`
	RequiredAgentID   string     `json:"required_agent_id"`
	ExecutedByAgentID string     `json:"executed_by_agent_id"`
	Targets           int        `json:"targets"`
	Discovered        int        `json:"discovered"`
	Failed            int        `json:"failed"`
	Rejected          int        `json:"rejected"`
	Blocked           int        `json:"blocked"`
	Error             string     `json:"error"`
	StartedAt         *time.Time `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

type discoveryFindingResponse struct {
	ID                string          `json:"id"`
	TenantID          string          `json:"tenant_id"`
	RunID             string          `json:"run_id"`
	SourceID          string          `json:"source_id"`
	Kind              string          `json:"kind"`
	Ref               string          `json:"ref"`
	Provenance        string          `json:"provenance"`
	Fingerprint       string          `json:"fingerprint"`
	RiskScore         int             `json:"risk_score"`
	Metadata          json.RawMessage `json:"metadata"`
	DiscoveredAt      time.Time       `json:"discovered_at"`
	TriageStatus      string          `json:"triage_status"`
	ManagedIdentityID *string         `json:"managed_identity_id,omitempty"`
	TriageActor       string          `json:"triage_actor,omitempty"`
	TriageReason      string          `json:"triage_reason,omitempty"`
	TriagedAt         *time.Time      `json:"triaged_at,omitempty"`
}

type discoveryFindingTriageRequest struct {
	ManagedIdentityID string   `json:"managed_identity_id,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	Owner             *string  `json:"owner,omitempty"`
	Team              *string  `json:"team,omitempty"`
	Tags              []string `json:"tags,omitempty"`
}

func (r discoveryFindingTriageRequest) metadataPatch() json.RawMessage {
	patch := map[string]any{}
	if r.Owner != nil {
		patch["owner"] = strings.TrimSpace(*r.Owner)
	}
	if r.Team != nil {
		patch["team"] = strings.TrimSpace(*r.Team)
	}
	if r.Tags != nil {
		patch["tags"] = cleanDiscoveryFindingTags(r.Tags)
	}
	if len(patch) == 0 {
		return nil
	}
	b, err := json.Marshal(patch)
	if err != nil {
		return nil
	}
	return b
}

func cleanDiscoveryFindingTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := map[string]struct{}{}
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
		if len(out) == 16 {
			break
		}
	}
	return out
}

type DiscoveryMonitoring struct {
	RepositoryPath string                      `json:"repository_path"`
	FindingsPath   string                      `json:"findings_path"`
	SourcesPath    string                      `json:"sources_path"`
	SchedulesPath  string                      `json:"schedules_path"`
	RunsPath       string                      `json:"runs_path"`
	Summary        DiscoveryMonitoringSummary  `json:"summary"`
	Sources        []DiscoveryMonitoringSource `json:"sources"`
}

type DiscoveryMonitoringSummary struct {
	SourceCount               int `json:"source_count"`
	ScheduledSourceCount      int `json:"scheduled_source_count"`
	ActiveMonitoringCount     int `json:"active_monitoring_count"`
	RunCount                  int `json:"run_count"`
	CompletedRunCount         int `json:"completed_run_count"`
	FailedRunCount            int `json:"failed_run_count"`
	FindingCount              int `json:"finding_count"`
	OpenFindingCount          int `json:"open_finding_count"`
	CertificateInventoryCount int `json:"certificate_inventory_count"`
}

type DiscoveryMonitoringSource struct {
	SourceID                  string     `json:"source_id"`
	Kind                      string     `json:"kind"`
	Name                      string     `json:"name"`
	Scheduled                 bool       `json:"scheduled"`
	ScheduleID                string     `json:"schedule_id"`
	MonitoringIntervalSeconds int        `json:"monitoring_interval_seconds"`
	LastRunID                 string     `json:"last_run_id"`
	LastRunStatus             string     `json:"last_run_status"`
	LastRunError              string     `json:"last_run_error"`
	LastRunCompletedAt        *time.Time `json:"last_run_completed_at,omitempty"`
	LastDiscoveryAt           *time.Time `json:"last_discovery_at,omitempty"`
	RunCount                  int        `json:"run_count"`
	CompletedRunCount         int        `json:"completed_run_count"`
	FailedRunCount            int        `json:"failed_run_count"`
	FindingCount              int        `json:"finding_count"`
	OpenFindingCount          int        `json:"open_finding_count"`
	CertificateInventoryCount int        `json:"certificate_inventory_count"`
	RepositoryPath            string     `json:"repository_path"`
	FindingsPath              string     `json:"findings_path"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}

// DiscoveryCoverageResponse classifies the tenant's estate into the three
// coverage buckets against the served sources' observability envelopes:
// OBSERVED, OBSERVABLE-UNOBSERVED (with the specific reason and the action
// that closes the gap), and STRUCTURALLY-UNOBSERVABLE (no configured source
// can ever see the class). The counters cover the returned classes.
type DiscoveryCoverageResponse struct {
	GeneratedAt              time.Time                `json:"generated_at"`
	Observed                 int                      `json:"observed"`
	Unobserved               int                      `json:"unobserved"`
	StructurallyUnobservable int                      `json:"structurally_unobservable"`
	Classes                  []DiscoveryCoverageClass `json:"classes"`
	// Segments is coverage measured against what an operator DECLARED they own
	// (epic C3), rather than against what discovery happened to find. It is the
	// only way to report a network nobody has looked at: an inventory built
	// from findings can describe what it found and nothing else.
	Segments []DiscoverySegmentCoverage `json:"segments"`
	// SegmentCoveragePercent is the share of declared, non-excluded segments
	// swept within their own staleness SLO. Excluded segments are left out of
	// both halves rather than counted as covered — an operator who declares a
	// lab out of scope has not thereby observed it.
	SegmentCoveragePercent int `json:"segment_coverage_percent"`
	// Provenance is how much of the certificate inventory has an observation
	// behind it. It is what stops a certificate count reading as an inventory.
	Provenance DiscoveryProvenanceSummary `json:"provenance"`
	// Unknowns is the register of things this deployment cannot see and knows
	// it cannot. Naming them is the entire point of the epic: a coverage number
	// with no denominator is a reassurance, not a measurement.
	Unknowns []DiscoveryUnknown `json:"unknowns"`
}

// DiscoverySegmentCoverage is one declared segment's observation state.
type DiscoverySegmentCoverage struct {
	Name   string   `json:"name"`
	Ranges []string `json:"ranges"`
	// Status is one of: swept (within SLO), stale (swept, but longer ago than
	// this segment's own SLO), never (declared and never swept), excluded
	// (declared out of scope, with a reason).
	Status          string     `json:"status"`
	StalenessHours  int        `json:"staleness_hours"`
	LastSweptAt     *time.Time `json:"last_swept_at,omitempty"`
	LastSweptBy     string     `json:"last_swept_by,omitempty"`
	LastFoundCount  int        `json:"last_found_count,omitempty"`
	ExclusionReason string     `json:"exclusion_reason,omitempty"`
}

// DiscoveryProvenanceSummary counts inventory rows by observation freshness.
type DiscoveryProvenanceSummary struct {
	Total    int `json:"total"`
	Observed int `json:"observed"`
	Stale    int `json:"stale"`
	// NeverObserved rows have no observation at all — typically certificates
	// this control plane issued that nothing has since scanned. Legitimate, and
	// not verified inventory: the row is evidence of an issuance, not of a
	// deployment.
	NeverObserved int `json:"never_observed"`
	// StaleAfterHours is the window this summary was computed against, so the
	// numbers are interpretable without guessing.
	StaleAfterHours int `json:"stale_after_hours"`
}

// DiscoveryUnknown is one named blind spot.
type DiscoveryUnknown struct {
	// Kind distinguishes the reasons, because they need different responses:
	// segment_never_swept, segment_stale, segment_excluded, class_unobservable,
	// inventory_unobserved.
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	// Action names what closes the gap, or says plainly that nothing does.
	Action string `json:"action,omitempty"`
}

// DiscoveryCoverageClass is one asset class's computed coverage bucket.
type DiscoveryCoverageClass struct {
	Class          string     `json:"class"`
	Status         string     `json:"status"`
	SourceKinds    []string   `json:"source_kinds,omitempty"`
	ObservedBy     []string   `json:"observed_by,omitempty"`
	LastObservedAt *time.Time `json:"last_observed_at,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	Action         string     `json:"action,omitempty"`
}

func (a *API) getDiscoveryCoverage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rows, err := a.store.ListDiscoveryCoverage(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	states := make([]coverage.SourceState, 0, len(rows))
	for _, row := range rows {
		states = append(states, coverage.SourceState{
			SourceID: row.SourceID, Kind: row.SourceKind, Name: row.SourceName,
			LastRunStatus: row.LastRunStatus, LastCompletedAt: row.LastCompletedAt,
		})
	}
	rep := coverage.Classify(time.Now().UTC(), states)

	classFilter := strings.TrimSpace(r.URL.Query().Get("class"))
	kindFilter := strings.TrimSpace(r.URL.Query().Get("source_kind"))
	out := DiscoveryCoverageResponse{GeneratedAt: rep.GeneratedAt, Classes: []DiscoveryCoverageClass{}}
	for _, c := range rep.Classes {
		if classFilter != "" && string(c.Class) != classFilter {
			continue
		}
		if kindFilter != "" && !sourceKindsContain(c.SourceKinds, kindFilter) {
			continue
		}
		out.Classes = append(out.Classes, DiscoveryCoverageClass{
			Class: string(c.Class), Status: string(c.Status), SourceKinds: c.SourceKinds,
			ObservedBy: c.ObservedBy, LastObservedAt: c.LastObservedAt,
			Reason: c.Reason, Action: c.Action,
		})
		switch c.Status {
		case coverage.StatusObserved:
			out.Observed++
		case coverage.StatusUnobserved:
			out.Unobserved++
		case coverage.StatusStructural:
			out.StructurallyUnobservable++
			// A class no configured source can ever see is a permanent blind
			// spot, and belongs in the register beside the temporary ones.
			out.Unknowns = append(out.Unknowns, DiscoveryUnknown{
				Kind: "class_unobservable", Subject: string(c.Class),
				Detail: c.Reason, Action: c.Action,
			})
		}
	}
	a.appendSegmentCoverage(r.Context(), tenantID, &out)
	a.appendProvenance(r.Context(), tenantID, &out)
	if out.Segments == nil {
		out.Segments = []DiscoverySegmentCoverage{}
	}
	if out.Unknowns == nil {
		out.Unknowns = []DiscoveryUnknown{}
	}
	a.writeJSON(w, http.StatusOK, out)
}

// appendSegmentCoverage measures declared segments against reality.
//
// Excluded segments are removed from BOTH halves of the percentage rather than
// counted as covered. An operator who declares a lab out of scope has not
// observed it, and a coverage number that rose when somebody excluded something
// would reward exactly the wrong behaviour.
func (a *API) appendSegmentCoverage(ctx context.Context, tenantID string, out *DiscoveryCoverageResponse) {
	segments, err := a.store.ListDiscoverySegments(ctx, tenantID)
	if err != nil {
		// A coverage surface that fails closed to "no segments" would report
		// 100% for an estate it could not read. Leave the percentage at its
		// zero value and say why in the register instead.
		out.Unknowns = append(out.Unknowns, DiscoveryUnknown{
			Kind: "segment_read_failed", Subject: "declared segments",
			Detail: "the declared segments could not be read, so segment coverage is not computed",
			Action: "retry; if it persists this is a control-plane fault, not an estate gap",
		})
		return
	}
	now := time.Now().UTC()
	inScope, covered := 0, 0
	for _, seg := range segments {
		row := DiscoverySegmentCoverage{
			Name: seg.Name, Ranges: seg.Ranges, StalenessHours: seg.StalenessHours,
			LastSweptAt: seg.LastSweptAt, LastSweptBy: seg.LastSweptBy,
			LastFoundCount: seg.LastFoundCount, ExclusionReason: seg.ExclusionReason,
		}
		if row.Ranges == nil {
			row.Ranges = []string{}
		}
		switch {
		case seg.Excluded:
			row.Status = "excluded"
			out.Unknowns = append(out.Unknowns, DiscoveryUnknown{
				Kind: "segment_excluded", Subject: seg.Name,
				Detail: "declared out of scope: " + seg.ExclusionReason,
				Action: "remove the exclusion to bring this segment into coverage",
			})
		case seg.LastSweptAt == nil:
			inScope++
			row.Status = "never"
			out.Unknowns = append(out.Unknowns, DiscoveryUnknown{
				Kind: "segment_never_swept", Subject: seg.Name,
				Detail: "declared, and nothing has ever swept it",
				Action: "enrol a network-role agent that can reach it and run a discovery sweep",
			})
		case now.Sub(*seg.LastSweptAt) > time.Duration(seg.StalenessHours)*time.Hour:
			inScope++
			row.Status = "stale"
			out.Unknowns = append(out.Unknowns, DiscoveryUnknown{
				Kind: "segment_stale", Subject: seg.Name,
				Detail: "last swept outside this segment's own " +
					strconv.Itoa(seg.StalenessHours) + "h staleness window",
				Action: "run a discovery sweep, or widen the window if it is wrong",
			})
		default:
			inScope++
			covered++
			row.Status = "swept"
		}
		out.Segments = append(out.Segments, row)
	}
	if inScope > 0 {
		out.SegmentCoveragePercent = covered * 100 / inScope
	}
}

// appendProvenance summarizes how much of the inventory has an observation
// behind it.
func (a *API) appendProvenance(ctx context.Context, tenantID string, out *DiscoveryCoverageResponse) {
	const staleAfterHours = 168
	counts, err := a.store.CertificateProvenance(ctx, tenantID,
		time.Now().UTC().Add(-staleAfterHours*time.Hour))
	if err != nil {
		return
	}
	out.Provenance = DiscoveryProvenanceSummary{
		Total: counts.Total, Observed: counts.Observed, Stale: counts.Stale,
		NeverObserved: counts.NeverObserved, StaleAfterHours: staleAfterHours,
	}
	if counts.NeverObserved > 0 {
		out.Unknowns = append(out.Unknowns, DiscoveryUnknown{
			Kind: "inventory_unobserved", Subject: "certificate inventory",
			Detail: strconv.Itoa(counts.NeverObserved) + " of " + strconv.Itoa(counts.Total) +
				" certificates have no observation behind them — they are evidence of an " +
				"issuance, not of a deployment",
			Action: "run discovery over the networks those certificates should be deployed on",
		})
	}
}

func sourceKindsContain(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

//trstctl:mutation
func (a *API) createDiscoverySegment(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoverySegmentRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		segment, err := validateDiscoverySegmentRequest(req)
		if err != nil {
			return 0, nil, err
		}
		created, err := a.orch.UpsertDiscoverySegment(ctx, tenantID, segment)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDiscoverySegmentResponse(created), nil
	})
}

//trstctl:mutation
func (a *API) createDiscoverySource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoverySourceRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		cfg, err := validateDiscoverySourceRequest(req)
		if err != nil {
			return 0, nil, err
		}
		if err := a.requireDiscoveryCredentialRefsAllowed(cfg); err != nil {
			return 0, nil, err
		}
		kind := strings.TrimSpace(req.Kind)
		if kind == "network" || kind == "ssh" {
			intent, resolveErr := segmentscan.Resolve(kind, cfg)
			if resolveErr != nil {
				return 0, nil, errStatus(http.StatusBadRequest, resolveErr.Error())
			}
			segment, segmentErr := a.store.GetDiscoverySegmentByName(ctx, tenantID, intent.Segment)
			if segmentErr != nil {
				if store.IsNotFound(segmentErr) {
					return 0, nil, errStatus(http.StatusBadRequest, "segment must be declared before creating a network or SSH source")
				}
				return 0, nil, segmentErr
			}
			if segment.Excluded {
				return 0, nil, errStatus(http.StatusBadRequest, "an excluded segment cannot back an executable discovery source")
			}
			if err := segmentscan.ValidateDeclaredSegment(intent, segment.Ranges); err != nil {
				return 0, nil, errStatus(http.StatusBadRequest, err.Error())
			}
			if err := a.validateDiscoveryRelay(ctx, tenantID, intent.RequiredAgentID); err != nil {
				return 0, nil, err
			}
		}
		if kind == adcsdiscovery.SourceKind {
			intent, resolveErr := adcsdiscovery.ResolveInventoryIntent(cfg)
			if resolveErr != nil {
				return 0, nil, errStatus(http.StatusBadRequest, resolveErr.Error())
			}
			if intent.RequiredAgentID != "" {
				agent, agentErr := a.store.GetAgent(ctx, tenantID, intent.RequiredAgentID)
				if agentErr != nil {
					return 0, nil, errStatus(http.StatusBadRequest, "relay_agent_id must name an enrolled tenant agent")
				}
				if agent.Status == "offboarded" || !sourceKindsContain(agent.Roles, adcsdiscovery.RequiredRoleNetwork) {
					return 0, nil, errStatus(http.StatusBadRequest, "relay_agent_id must name an active network-role agent")
				}
			}
		}
		privateEgress, err := discoveryPrivateEgressRequested(cfg)
		if err != nil {
			return 0, nil, err
		}
		if privateEgress {
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
		}
		src, err := a.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
			Kind: kind, Name: strings.TrimSpace(req.Name), Config: cfg,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDiscoverySourceResponse(src), nil
	})
}

func (a *API) listDiscoverySources(w http.ResponseWriter, r *http.Request) {
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
	rows, err := a.store.ListDiscoverySourcesPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]discoverySourceResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDiscoverySourceResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) createDiscoverySchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryScheduleRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.SourceID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "source_id is required")
		}
		if strings.TrimSpace(req.Name) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name is required")
		}
		if req.IntervalSeconds <= 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "interval_seconds must be greater than zero")
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		sched, err := a.orch.UpsertDiscoverySchedule(ctx, tenantID, store.DiscoverySchedule{
			SourceID: req.SourceID, Name: req.Name, IntervalSeconds: req.IntervalSeconds, Enabled: enabled,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDiscoveryScheduleResponse(sched), nil
	})
}

func (a *API) listDiscoverySchedules(w http.ResponseWriter, r *http.Request) {
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
	rows, err := a.store.ListDiscoverySchedulesPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]discoveryScheduleResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDiscoveryScheduleResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) startDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryRunRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.SourceID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "source_id is required")
		}
		var scheduleID *string
		if req.ScheduleID != "" {
			scheduleID = &req.ScheduleID
		}
		// Per-feature telemetry (COVER-009): time the served discovery-run enqueue and
		// record a non-sensitive feature/action/outcome signal (no source/tenant labels).
		start := time.Now()
		run, err := a.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
			SourceID: req.SourceID, ScheduleID: scheduleID, DryRun: req.DryRun,
		})
		a.observeFeature("discovery", "start_run", start, err)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDiscoveryRunResponse(run), nil
	})
}

func (a *API) getDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	run, err := a.store.GetDiscoveryRun(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toDiscoveryRunResponse(run))
}

func (a *API) listDiscoveryRuns(w http.ResponseWriter, r *http.Request) {
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
	rows, err := a.store.ListDiscoveryRunsPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]discoveryRunResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDiscoveryRunResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) listDiscoveryMonitoring(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rows, err := a.store.ListDiscoveryMonitoringSources(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := DiscoveryMonitoring{
		RepositoryPath: "/api/v1/certificates",
		FindingsPath:   "/api/v1/discovery/findings",
		SourcesPath:    "/api/v1/discovery/sources",
		SchedulesPath:  "/api/v1/discovery/schedules",
		RunsPath:       "/api/v1/discovery/runs",
		Sources:        make([]DiscoveryMonitoringSource, 0, len(rows)),
	}
	for _, row := range rows {
		item := toDiscoveryMonitoringSource(row)
		out.Sources = append(out.Sources, item)
		out.Summary.SourceCount++
		if item.Scheduled {
			out.Summary.ScheduledSourceCount++
		}
		if discoveryMonitoringActive(item) {
			out.Summary.ActiveMonitoringCount++
		}
		out.Summary.RunCount += item.RunCount
		out.Summary.CompletedRunCount += item.CompletedRunCount
		out.Summary.FailedRunCount += item.FailedRunCount
		out.Summary.FindingCount += item.FindingCount
		out.Summary.OpenFindingCount += item.OpenFindingCount
		out.Summary.CertificateInventoryCount += item.CertificateInventoryCount
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) listDiscoveryFindings(w http.ResponseWriter, r *http.Request) {
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
	rows, err := a.store.ListDiscoveryFindingsPage(r.Context(), tenantID, r.URL.Query().Get("run_id"), after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]discoveryFindingResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDiscoveryFindingResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) claimDiscoveryFinding(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryFindingTriageRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		var managedID *string
		if strings.TrimSpace(req.ManagedIdentityID) != "" {
			id := strings.TrimSpace(req.ManagedIdentityID)
			managedID = &id
		}
		f, err := a.orch.ClaimDiscoveryFinding(ctx, tenantID, r.PathValue("id"), managedID, req.Reason, req.metadataPatch())
		if err != nil {
			return 0, nil, discoveryTriageError(err)
		}
		return http.StatusOK, toDiscoveryFindingResponse(f), nil
	})
}

//trstctl:mutation
func (a *API) dismissDiscoveryFinding(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryFindingTriageRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		f, err := a.orch.DismissDiscoveryFinding(ctx, tenantID, r.PathValue("id"), req.Reason, req.metadataPatch())
		if err != nil {
			return 0, nil, discoveryTriageError(err)
		}
		return http.StatusOK, toDiscoveryFindingResponse(f), nil
	})
}

func discoveryTriageError(err error) error {
	if errors.Is(err, discovery.ErrInvalidTriageTransition) {
		return errStatus(http.StatusConflict, err.Error())
	}
	if store.IsNotFound(err) {
		return errStatus(http.StatusNotFound, "discovery finding not found")
	}
	return err
}

func validateDiscoverySourceRequest(req discoverySourceRequest) (json.RawMessage, error) {
	req.Kind = strings.TrimSpace(req.Kind)
	req.Name = strings.TrimSpace(req.Name)
	if req.Kind == "" {
		return nil, errStatus(http.StatusBadRequest, "kind is required")
	}
	if req.Name == "" {
		return nil, errStatus(http.StatusBadRequest, "name is required")
	}
	if _, ok := sourcecatalog.Find(req.Kind); !ok {
		return nil, errStatus(http.StatusBadRequest, "kind must be one of "+strings.Join(sourcecatalog.Kinds(), ", "))
	}
	cfg := req.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(cfg, &obj); err != nil || obj == nil {
		return nil, errStatus(http.StatusBadRequest, "config must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return nil, errStatus(http.StatusBadRequest, "config may contain credential references, not inline secret values")
	}
	if err := sourcecatalog.ValidateConfig(req.Kind, cfg); err != nil {
		return nil, errStatus(http.StatusBadRequest, err.Error())
	}
	if req.Kind == "network" || req.Kind == "ssh" {
		if _, err := segmentscan.Resolve(req.Kind, cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == adcsdiscovery.SourceKind {
		if _, err := adcsdiscovery.ResolveInventoryIntent(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == nhi.SourceKind {
		if err := nhi.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == apikey.SourceKind {
		if err := apikey.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == oauthgrant.SourceKind {
		if err := oauthgrant.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == serviceaccount.SourceKind {
		if err := serviceaccount.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == nhibehavior.SourceKind {
		if err := nhibehavior.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == compromise.SourceKind {
		if err := compromise.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == k8stls.SourceKind {
		if err := k8stls.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	return append(json.RawMessage(nil), cfg...), nil
}

func validateDiscoverySegmentRequest(req discoverySegmentRequest) (store.DiscoverySegment, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 256 {
		return store.DiscoverySegment{}, errStatus(http.StatusBadRequest, "segment name is required and must be at most 256 bytes")
	}
	if len(req.Ranges) == 0 || len(req.Ranges) > 256 {
		return store.DiscoverySegment{}, errStatus(http.StatusBadRequest, "segment ranges must contain between 1 and 256 declarations")
	}
	ranges := make([]string, 0, len(req.Ranges))
	for _, value := range req.Ranges {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 4096 {
			return store.DiscoverySegment{}, errStatus(http.StatusBadRequest, "segment ranges must be non-empty and at most 4096 bytes each")
		}
		ranges = append(ranges, value)
	}
	if err := segmentscan.ValidateDeclarations(ranges); err != nil {
		return store.DiscoverySegment{}, errStatus(http.StatusBadRequest, err.Error())
	}
	staleness := req.StalenessHours
	if staleness == 0 {
		staleness = 168
	}
	if staleness < 1 || staleness > 8760 {
		return store.DiscoverySegment{}, errStatus(http.StatusBadRequest, "staleness_hours must be between 1 and 8760")
	}
	reason := strings.TrimSpace(req.ExclusionReason)
	if req.Excluded && reason == "" {
		return store.DiscoverySegment{}, errStatus(http.StatusBadRequest, "excluded segments require an exclusion_reason")
	}
	return store.DiscoverySegment{
		Name: name, Ranges: ranges, StalenessHours: staleness,
		Excluded: req.Excluded, ExclusionReason: reason,
	}, nil
}

func discoveryPrivateEgressRequested(cfg json.RawMessage) (bool, error) {
	var decoded any
	if err := json.Unmarshal(cfg, &decoded); err != nil {
		return false, errStatus(http.StatusBadRequest, "config must be a JSON object")
	}
	return discoveryPrivateEgressRequestedValue(decoded)
}

func (a *API) requireDiscoveryCredentialRefsAllowed(cfg json.RawMessage) error {
	var decoded any
	if err := json.Unmarshal(cfg, &decoded); err != nil {
		return errStatus(http.StatusBadRequest, "config must be a JSON object")
	}
	return a.requireDiscoveryCredentialRefsAllowedValue("config", decoded)
}

func (a *API) requireDiscoveryCredentialRefsAllowedValue(path string, v any) error {
	switch x := v.(type) {
	case map[string]any:
		for key, child := range x {
			childPath := path + "." + key
			if strings.HasSuffix(key, "_ref") {
				if ref, ok := child.(string); ok {
					if err := a.requireOutboundEnvCredentialRefAllowed(ref, childPath); err != nil {
						return err
					}
				}
			}
			if err := a.requireDiscoveryCredentialRefsAllowedValue(childPath, child); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range x {
			if err := a.requireDiscoveryCredentialRefsAllowedValue(fmt.Sprintf("%s[%d]", path, i), child); err != nil {
				return err
			}
		}
	}
	return nil
}

func discoveryPrivateEgressRequestedValue(v any) (bool, error) {
	switch x := v.(type) {
	case map[string]any:
		requested := false
		if raw, ok := x["allow_private_endpoint"]; ok {
			b, ok := raw.(bool)
			if !ok {
				return false, errStatus(http.StatusBadRequest, "allow_private_endpoint must be boolean")
			}
			if b {
				if err := validatePrivateEgressCIDRGrantValue(x["private_egress_cidrs"]); err != nil {
					return false, err
				}
				requested = true
			}
		}
		for _, child := range x {
			childRequested, err := discoveryPrivateEgressRequestedValue(child)
			if err != nil {
				return false, err
			}
			requested = requested || childRequested
		}
		return requested, nil
	case []any:
		requested := false
		for _, child := range x {
			childRequested, err := discoveryPrivateEgressRequestedValue(child)
			if err != nil {
				return false, err
			}
			requested = requested || childRequested
		}
		return requested, nil
	default:
		return false, nil
	}
}

func validatePrivateEgressCIDRGrantValue(raw any) error {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return errStatus(http.StatusBadRequest, "private_egress_cidrs is required when allow_private_endpoint is true")
	}
	cidrs := make([]string, 0, len(items))
	for _, item := range items {
		cidr, ok := item.(string)
		if !ok || strings.TrimSpace(cidr) == "" {
			return errStatus(http.StatusBadRequest, "private_egress_cidrs values must be non-empty strings")
		}
		cidrs = append(cidrs, cidr)
	}
	return validatePrivateEgressCIDRs(cidrs)
}

func validatePrivateEgressCIDRs(cidrs []string) error {
	if len(cidrs) == 0 {
		return errStatus(http.StatusBadRequest, "private_egress_cidrs is required when allow_private_endpoint is true")
	}
	for _, cidr := range cidrs {
		prefix, err := netsec.ParseEgressAllowPrefix(cidr)
		if err != nil {
			return errStatus(http.StatusBadRequest, "private_egress_cidrs contains invalid CIDR")
		}
		// Parsing is not validation here. 0.0.0.0/0 parses, and it turns this
		// allowlist into "reach anything", so the caller has to be told rather
		// than have the entry quietly ignored at dial time.
		if err := netsec.ValidateEgressAllowPrefix(prefix); err != nil {
			return errStatus(http.StatusBadRequest, "private_egress_cidrs entry is unusable: "+
				strings.TrimPrefix(err.Error(), "netsec: "))
		}
	}
	return nil
}

func containsInlineSecret(v any) bool {
	switch x := v.(type) {
	case map[string]json.RawMessage:
		for key, raw := range x {
			if inlineSecretKey(key) {
				return true
			}
			var nested any
			if err := json.Unmarshal(raw, &nested); err == nil && containsInlineSecret(nested) {
				return true
			}
		}
	case map[string]any:
		for key, val := range x {
			if inlineSecretKey(key) || containsInlineSecret(val) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if containsInlineSecret(val) {
				return true
			}
		}
	}
	return false
}

func inlineSecretKey(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if strings.Contains(k, "ref") || strings.Contains(k, "name") || strings.Contains(k, "id") {
		return false
	}
	if strings.Contains(k, "secret") || strings.Contains(k, "password") || strings.Contains(k, "passphrase") || strings.Contains(k, "token") {
		return true
	}
	switch k {
	case "password", "passphrase", "secret", "token", "private_key", "privatekey", "credential", "value":
		return true
	default:
		return strings.HasSuffix(k, "_secret") || strings.HasSuffix(k, "_token")
	}
}

func toDiscoverySourceResponse(src store.DiscoverySource) discoverySourceResponse {
	cfg := src.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	return discoverySourceResponse{
		ID: src.ID, TenantID: src.TenantID, Kind: src.Kind, Name: src.Name,
		Config: cfg, CreatedAt: src.CreatedAt, UpdatedAt: src.UpdatedAt,
	}
}

func toDiscoverySegmentResponse(segment store.DiscoverySegment) discoverySegmentResponse {
	return discoverySegmentResponse{
		ID: segment.ID, Name: segment.Name, Ranges: segment.Ranges,
		StalenessHours: segment.StalenessHours, Excluded: segment.Excluded,
		ExclusionReason: segment.ExclusionReason, LastSweptAt: segment.LastSweptAt,
		LastSweptBy: segment.LastSweptBy, LastFoundCount: segment.LastFoundCount,
		CreatedAt: segment.CreatedAt,
	}
}

func toDiscoveryScheduleResponse(s store.DiscoverySchedule) discoveryScheduleResponse {
	return discoveryScheduleResponse{
		ID: s.ID, TenantID: s.TenantID, SourceID: s.SourceID, Name: s.Name,
		IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

func toDiscoveryRunResponse(run store.DiscoveryRun) discoveryRunResponse {
	return discoveryRunResponse{
		ID: run.ID, TenantID: run.TenantID, SourceID: run.SourceID, ScheduleID: run.ScheduleID,
		Status: run.Status, DryRun: run.DryRun, RequestedBy: run.RequestedBy,
		Execution: run.Execution, Segment: run.Segment, RequiredAgentRole: run.RequiredAgentRole,
		RequiredAgentID: run.RequiredAgentID, ExecutedByAgentID: run.ExecutedByAgentID,
		Targets: run.Targets, Discovered: run.Discovered, Failed: run.Failed, Rejected: run.Rejected,
		Blocked: run.Blocked, Error: orchestrator.SanitizeDiscoveryRunError(run.Error), StartedAt: run.StartedAt, CompletedAt: run.CompletedAt, CreatedAt: run.CreatedAt,
	}
}

func toDiscoveryFindingResponse(f store.DiscoveryFinding) discoveryFindingResponse {
	meta := f.Metadata
	if len(meta) == 0 {
		meta = json.RawMessage(`{}`)
	}
	return discoveryFindingResponse{
		ID: f.ID, TenantID: f.TenantID, RunID: f.RunID, SourceID: f.SourceID,
		Kind: f.Kind, Ref: f.Ref, Provenance: f.Provenance, Fingerprint: f.Fingerprint,
		RiskScore: f.RiskScore, Metadata: meta, DiscoveredAt: f.DiscoveredAt,
		TriageStatus: f.TriageStatus, ManagedIdentityID: f.ManagedIdentityID,
		TriageActor: f.TriageActor, TriageReason: f.TriageReason, TriagedAt: f.TriagedAt,
	}
}

func toDiscoveryMonitoringSource(row store.DiscoveryMonitoringSource) DiscoveryMonitoringSource {
	item := DiscoveryMonitoringSource{
		SourceID: row.SourceID, Kind: row.Kind, Name: row.Name,
		Scheduled:  row.ScheduleID != "" && row.ScheduleEnabled,
		ScheduleID: row.ScheduleID, MonitoringIntervalSeconds: row.MonitoringIntervalSeconds,
		LastRunID: row.LastRunID, LastRunStatus: row.LastRunStatus, LastRunError: orchestrator.SanitizeDiscoveryRunError(row.LastRunError),
		LastRunCompletedAt: row.LastRunCompletedAt, LastDiscoveryAt: row.LastDiscoveryAt,
		RunCount: row.RunCount, CompletedRunCount: row.CompletedRunCount,
		FailedRunCount: row.FailedRunCount, FindingCount: row.FindingCount,
		OpenFindingCount: row.OpenFindingCount, CertificateInventoryCount: row.CertificateInventoryCount,
		RepositoryPath: "/api/v1/certificates", FindingsPath: "/api/v1/discovery/findings",
		UpdatedAt: row.UpdatedAt,
	}
	if row.LastRunID != "" {
		item.FindingsPath = "/api/v1/discovery/findings?run_id=" + url.QueryEscape(row.LastRunID)
	}
	return item
}

func discoveryMonitoringActive(item DiscoveryMonitoringSource) bool {
	if !item.Scheduled {
		return false
	}
	switch item.LastRunStatus {
	case "", "queued", "running", "succeeded", "partial":
		return true
	default:
		return false
	}
}
