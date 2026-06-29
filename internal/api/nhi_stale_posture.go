package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	nhiStaleActivityThresholdDays    = 90
	nhiDormantActivityThresholdDays  = 365
	nhiUnusedNoActivityThresholdDays = 90
)

var nhiStaleCoverage = []string{
	"managed_identities",
	"discovery_findings",
	"stale_activity",
	"unused_no_activity",
	"orphaned_detection",
	"dormant_detection",
	"remediation_recommendations",
}

var nhiActivityTimestampFields = []string{
	"last_used_at",
	"last_seen_at",
	"last_activity_at",
	"last_authenticated_at",
	"last_accessed_at",
	"last_observed_at",
}

var nhiCreatedTimestampFields = []string{
	"first_seen_at",
	"created_at",
	"discovered_at",
	"issued_at",
	"registered_at",
}

var nhiOwnerMetadataFields = []string{
	"owner_id",
	"owner",
	"owner_name",
	"owner_email",
	"service_owner",
	"human_owner",
	"team",
	"team_name",
	"vendor",
	"vendor_name",
}

type nhiStalePostureResponse struct {
	Capability  string                   `json:"capability"`
	GeneratedAt time.Time                `json:"generated_at"`
	Coverage    []string                 `json:"coverage"`
	Thresholds  nhiStaleThresholds       `json:"thresholds"`
	Summary     nhiStalePostureSummary   `json:"summary"`
	Findings    []nhiStalePostureFinding `json:"findings"`
}

type nhiStaleThresholds struct {
	StaleActivityDays    int `json:"stale_activity_days"`
	DormantActivityDays  int `json:"dormant_activity_days"`
	UnusedNoActivityDays int `json:"unused_no_activity_days"`
}

type nhiStalePostureSummary struct {
	TotalAnalyzed   int `json:"total_analyzed"`
	Findings        int `json:"findings"`
	Stale           int `json:"stale"`
	Dormant         int `json:"dormant"`
	Unused          int `json:"unused"`
	Orphaned        int `json:"orphaned"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	Recommendations int `json:"recommendations"`
}

type nhiStalePostureFinding struct {
	InventoryID     string     `json:"inventory_id"`
	Ref             string     `json:"ref,omitempty"`
	Kind            string     `json:"kind"`
	Source          string     `json:"source"`
	DisplayName     string     `json:"display_name"`
	OwnerID         string     `json:"owner_id,omitempty"`
	OwnerStatus     string     `json:"owner_status"`
	Status          string     `json:"status"`
	Severity        string     `json:"severity"`
	RiskScore       int        `json:"risk_score"`
	FindingTypes    []string   `json:"finding_types"`
	ActivityAgeDays int        `json:"activity_age_days"`
	CreatedAgeDays  int        `json:"created_age_days"`
	LastActivityAt  *time.Time `json:"last_activity_at,omitempty"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Recommendation  string     `json:"recommendation"`
	EvidenceRefs    []string   `json:"evidence_refs"`
}

func (a *API) listNHIStalePosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.nhiStalePosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) nhiStalePosture(ctx context.Context, tenantID string) (nhiStalePostureResponse, error) {
	inventory, err := a.nhiInventory(ctx, tenantID)
	if err != nil {
		return nhiStalePostureResponse{}, err
	}
	now := time.Now().UTC()
	out := nhiStalePostureResponse{
		Capability:  "CAP-POST-02",
		GeneratedAt: now,
		Coverage:    append([]string(nil), nhiStaleCoverage...),
		Thresholds: nhiStaleThresholds{
			StaleActivityDays:    nhiStaleActivityThresholdDays,
			DormantActivityDays:  nhiDormantActivityThresholdDays,
			UnusedNoActivityDays: nhiUnusedNoActivityThresholdDays,
		},
		Findings: []nhiStalePostureFinding{},
	}
	for _, item := range inventory.Items {
		if !nhiStaleAnalyzable(item) {
			continue
		}
		out.Summary.TotalAnalyzed++
		finding, ok := nhiStaleFindingForItem(item, now)
		if !ok {
			continue
		}
		out.Findings = append(out.Findings, finding)
		out.Summary.Findings++
		out.Summary.Recommendations++
		if nhiStringSliceContains(finding.FindingTypes, "stale_activity") {
			out.Summary.Stale++
		}
		if nhiStringSliceContains(finding.FindingTypes, "dormant_activity") {
			out.Summary.Dormant++
		}
		if nhiStringSliceContains(finding.FindingTypes, "unused_no_activity") {
			out.Summary.Unused++
		}
		if nhiStringSliceContains(finding.FindingTypes, "orphaned_nhi") {
			out.Summary.Orphaned++
		}
		switch finding.Severity {
		case "critical":
			out.Summary.Critical++
		case "high":
			out.Summary.High++
		case "medium":
			out.Summary.Medium++
		default:
			out.Summary.Low++
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		return a.DisplayName < b.DisplayName
	})
	return out, nil
}

func nhiStaleAnalyzable(item nhiInventoryItem) bool {
	switch strings.ToLower(strings.TrimSpace(item.Status)) {
	case "revoked", "retired", "deleted", "disabled", "decommissioned", "resolved", "closed":
		return false
	default:
		return true
	}
}

func nhiStaleFindingForItem(item nhiInventoryItem, now time.Time) (nhiStalePostureFinding, bool) {
	meta := decodeNHIInventoryMetadata(item.Metadata)
	lastActivity := latestNHIPostureTimestamp(meta, nhiActivityTimestampFields...)
	lastSeen := firstNHIPostureTimestamp(meta, "last_seen_at", "last_observed_at")
	lastUsed := firstNHIPostureTimestamp(meta, "last_used_at", "last_authenticated_at", "last_accessed_at")
	createdAt := nhiCreatedAt(item, meta)
	createdAge := daysSince(now, createdAt)
	ownerStatus := nhiOwnerStatus(item, meta)
	orphaned := ownerStatus == "orphaned" && createdAge >= nhiUnusedNoActivityThresholdDays

	activityAge := 0
	stale := false
	dormant := false
	if lastActivity != nil {
		activityAge = daysSince(now, *lastActivity)
		stale = activityAge >= nhiStaleActivityThresholdDays
		dormant = activityAge >= nhiDormantActivityThresholdDays
	}
	unused := lastActivity == nil && createdAge >= nhiUnusedNoActivityThresholdDays

	var findingTypes []string
	if stale {
		findingTypes = append(findingTypes, "stale_activity")
	}
	if dormant {
		findingTypes = append(findingTypes, "dormant_activity")
	}
	if unused {
		findingTypes = append(findingTypes, "unused_no_activity")
	}
	if orphaned {
		findingTypes = append(findingTypes, "orphaned_nhi")
	}
	if len(findingTypes) == 0 {
		return nhiStalePostureFinding{}, false
	}
	severity := nhiStaleSeverity(stale, dormant, unused, orphaned)
	riskScore := item.RiskScore
	if riskScore == 0 {
		riskScore = nhiStaleRiskScore(severity, activityAge, createdAge, len(findingTypes))
	}
	return nhiStalePostureFinding{
		InventoryID:     item.ID,
		Ref:             item.Ref,
		Kind:            item.Kind,
		Source:          item.Source,
		DisplayName:     item.DisplayName,
		OwnerID:         item.OwnerID,
		OwnerStatus:     ownerStatus,
		Status:          item.Status,
		Severity:        severity,
		RiskScore:       riskScore,
		FindingTypes:    findingTypes,
		ActivityAgeDays: activityAge,
		CreatedAgeDays:  createdAge,
		LastActivityAt:  lastActivity,
		LastSeenAt:      lastSeen,
		LastUsedAt:      lastUsed,
		CreatedAt:       createdAt,
		Recommendation:  nhiStaleRecommendation(findingTypes, ownerStatus),
		EvidenceRefs:    nhiStaleEvidence(item, meta, lastActivity != nil),
	}, true
}

func latestNHIPostureTimestamp(meta map[string]any, fields ...string) *time.Time {
	var latest *time.Time
	for _, field := range fields {
		t := firstNHIPostureTimestamp(meta, field)
		if t == nil {
			continue
		}
		if latest == nil || t.After(*latest) {
			utc := t.UTC()
			latest = &utc
		}
	}
	return latest
}

func nhiCreatedAt(item nhiInventoryItem, meta map[string]any) time.Time {
	if t := firstNHIPostureTimestamp(meta, nhiCreatedTimestampFields...); t != nil {
		return *t
	}
	if item.DiscoveredAt != nil {
		return item.DiscoveredAt.UTC()
	}
	if item.CreatedAt.IsZero() {
		return time.Now().UTC()
	}
	return item.CreatedAt.UTC()
}

func daysSince(now, then time.Time) int {
	if then.IsZero() || then.After(now) {
		return 0
	}
	return int(now.Sub(then.UTC()).Hours() / 24)
}

func nhiOwnerStatus(item nhiInventoryItem, meta map[string]any) string {
	if strings.TrimSpace(item.OwnerID) != "" {
		return "owned"
	}
	if item.Source == "access_api_token" && strings.TrimSpace(item.DisplayName) != "" {
		return "subject_bound"
	}
	for _, field := range nhiOwnerMetadataFields {
		if strings.TrimSpace(metadataString(meta, field)) != "" {
			return "owned"
		}
	}
	return "orphaned"
}

func nhiStaleSeverity(stale, dormant, unused, orphaned bool) string {
	switch {
	case dormant && (unused || orphaned):
		return "critical"
	case dormant:
		return "high"
	case stale && (unused || orphaned):
		return "high"
	case stale || unused || orphaned:
		return "medium"
	default:
		return "low"
	}
}

func nhiStaleRiskScore(severity string, activityAge, createdAge, types int) int {
	base := map[string]int{"critical": 92, "high": 78, "medium": 58, "low": 30}[severity]
	score := base + minInt(activityAge/60, 10) + minInt(createdAge/90, 8) + types*3
	if score > 100 {
		return 100
	}
	return score
}

func nhiStaleRecommendation(types []string, ownerStatus string) string {
	parts := map[string]bool{}
	for _, typ := range types {
		parts[typ] = true
	}
	switch {
	case parts["orphaned_nhi"] && parts["unused_no_activity"]:
		return "Assign an accountable owner, confirm business need, then revoke or retire the NHI if no owner accepts it."
	case parts["dormant_activity"]:
		return "Quarantine or revoke the dormant NHI unless the owner reattests a current workload dependency."
	case parts["stale_activity"]:
		return "Revalidate the owner and rotate or retire the stale NHI if the workload no longer depends on it."
	case parts["unused_no_activity"]:
		return "Confirm the NHI has ever been used; remove it if no production dependency exists."
	case parts["orphaned_nhi"] && ownerStatus == "orphaned":
		return "Assign ownership before the next rotation window or retire the ownerless credential."
	default:
		return "Review NHI lifecycle evidence and either reattest ownership or retire the credential."
	}
}

func nhiStaleEvidence(item nhiInventoryItem, meta map[string]any, hasActivity bool) []string {
	evidence := []string{"inventory:" + item.ID}
	for _, field := range nhiActivityTimestampFields {
		if _, ok := meta[field]; ok {
			evidence = append(evidence, "metadata:"+field)
			break
		}
	}
	if !hasActivity {
		for _, field := range nhiCreatedTimestampFields {
			if _, ok := meta[field]; ok {
				evidence = append(evidence, "metadata:"+field)
				break
			}
		}
	}
	for _, field := range nhiOwnerMetadataFields {
		if _, ok := meta[field]; ok {
			evidence = append(evidence, "metadata:"+field)
			break
		}
	}
	return evidence
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func nhiStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
