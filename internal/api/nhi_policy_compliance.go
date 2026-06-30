package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var nhiPolicyComplianceCoverage = []string{
	"managed_identities",
	"discovery_findings",
	"rotation_cadence",
	"allowed_scopes",
	"allowed_geographies",
	"expiry_policy",
	"business_purpose",
	"remediation_recommendations",
}

var nhiPolicyAllowedScopeFields = []string{
	"allowed_scopes",
	"allowed_permissions",
	"allowed_grants",
	"allowed_roles",
	"allowed_actions",
	"permitted_scopes",
}

var nhiPolicyAllowedGeoFields = []string{
	"allowed_geos",
	"allowed_geographies",
	"allowed_countries",
	"permitted_geos",
	"permitted_countries",
}

var nhiPolicyObservedGeoFields = []string{
	"observed_geos",
	"observed_geographies",
	"observed_countries",
	"last_seen_geos",
	"last_seen_countries",
	"access_geos",
	"access_countries",
}

type nhiPolicyComplianceResponse struct {
	Capability         string                       `json:"capability"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	Coverage           []string                     `json:"coverage"`
	Summary            nhiPolicyComplianceSummary   `json:"summary"`
	Findings           []nhiPolicyComplianceFinding `json:"findings"`
	RecommendedActions []string                     `json:"recommended_actions"`
	EvidenceRefs       []string                     `json:"evidence_refs"`
}

type nhiPolicyComplianceSummary struct {
	TotalAnalyzed          int `json:"total_analyzed"`
	Compliant              int `json:"compliant"`
	Violations             int `json:"violations"`
	RotationViolations     int `json:"rotation_violations"`
	ScopeViolations        int `json:"scope_violations"`
	GeoViolations          int `json:"geo_violations"`
	ExpiryViolations       int `json:"expiry_violations"`
	BusinessPurposeMissing int `json:"business_purpose_missing"`
	Critical               int `json:"critical"`
	High                   int `json:"high"`
	Medium                 int `json:"medium"`
	Low                    int `json:"low"`
}

type nhiPolicyComplianceFinding struct {
	InventoryID         string     `json:"inventory_id"`
	Kind                string     `json:"kind"`
	Source              string     `json:"source"`
	DisplayName         string     `json:"display_name"`
	OwnerID             string     `json:"owner_id,omitempty"`
	Status              string     `json:"status"`
	PolicyStatus        string     `json:"policy_status"`
	Severity            string     `json:"severity"`
	RiskScore           int        `json:"risk_score"`
	ViolationTypes      []string   `json:"violation_types"`
	RotationCadenceDays int        `json:"rotation_cadence_days,omitempty"`
	CredentialAgeDays   int        `json:"credential_age_days,omitempty"`
	MaxTTLDays          int        `json:"max_ttl_days,omitempty"`
	RemainingTTLDays    int        `json:"remaining_ttl_days,omitempty"`
	AllowedScopes       []string   `json:"allowed_scopes,omitempty"`
	GrantedScopes       []string   `json:"granted_scopes,omitempty"`
	DisallowedScopes    []string   `json:"disallowed_scopes,omitempty"`
	AllowedGeos         []string   `json:"allowed_geos,omitempty"`
	ObservedGeos        []string   `json:"observed_geos,omitempty"`
	DisallowedGeos      []string   `json:"disallowed_geos,omitempty"`
	BusinessPurpose     string     `json:"business_purpose,omitempty"`
	Recommendation      string     `json:"recommendation"`
	EvidenceRefs        []string   `json:"evidence_refs"`
	LastRotatedAt       *time.Time `json:"last_rotated_at,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
}

func (a *API) listNHIPolicyCompliance(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.nhiPolicyCompliance(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) nhiPolicyCompliance(ctx context.Context, tenantID string) (nhiPolicyComplianceResponse, error) {
	inventory, err := a.nhiInventory(ctx, tenantID)
	if err != nil {
		return nhiPolicyComplianceResponse{}, err
	}
	out := nhiPolicyComplianceResponse{
		Capability:  "CAP-GOV-03",
		GeneratedAt: time.Now().UTC(),
		Coverage:    append([]string(nil), nhiPolicyComplianceCoverage...),
		Findings:    []nhiPolicyComplianceFinding{},
		RecommendedActions: []string{
			"Rotate NHIs whose last rotation is older than the declared cadence.",
			"Remove scopes and geographies outside the allowed policy envelope.",
			"Add an expiry and business purpose before approving continued NHI use.",
		},
		EvidenceRefs: []string{"projection:nhi_inventory", "policy:metadata"},
	}
	now := out.GeneratedAt
	for _, item := range inventory.Items {
		finding, governed := nhiPolicyComplianceForItem(item, now)
		if !governed {
			continue
		}
		out.Summary.TotalAnalyzed++
		if len(finding.ViolationTypes) == 0 {
			out.Summary.Compliant++
			continue
		}
		out.Findings = append(out.Findings, finding)
		out.Summary.Violations++
		for _, violation := range finding.ViolationTypes {
			switch violation {
			case "rotation_overdue":
				out.Summary.RotationViolations++
			case "scope_out_of_policy":
				out.Summary.ScopeViolations++
			case "geo_out_of_policy":
				out.Summary.GeoViolations++
			case "expiry_missing", "expiry_expired", "expiry_ttl_exceeds_policy":
				out.Summary.ExpiryViolations++
			case "business_purpose_missing":
				out.Summary.BusinessPurposeMissing++
			}
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
		if len(a.ViolationTypes) != len(b.ViolationTypes) {
			return len(a.ViolationTypes) > len(b.ViolationTypes)
		}
		return a.DisplayName < b.DisplayName
	})
	return out, nil
}

func nhiPolicyComplianceForItem(item nhiInventoryItem, now time.Time) (nhiPolicyComplianceFinding, bool) {
	meta := decodeNHIInventoryMetadata(item.Metadata)
	if !nhiPolicyIsGoverned(item, meta) {
		return nhiPolicyComplianceFinding{}, false
	}
	allowedScopes := collectNHIPostureStrings(meta, nhiPolicyAllowedScopeFields)
	grantedScopes := collectNHIPostureStrings(meta, nhiPostureGrantedFields)
	disallowedScopes := diffNHIPostureStrings(grantedScopes, allowedScopes)
	if len(allowedScopes) == 0 || len(grantedScopes) == 0 {
		disallowedScopes = nil
	}
	allowedGeos := normalizeNHIPolicyGeos(collectNHIPostureStrings(meta, nhiPolicyAllowedGeoFields))
	observedGeos := normalizeNHIPolicyGeos(collectNHIPostureStrings(meta, nhiPolicyObservedGeoFields))
	disallowedGeos := diffNHIPostureStrings(observedGeos, allowedGeos)
	if len(allowedGeos) == 0 || len(observedGeos) == 0 {
		disallowedGeos = nil
	}

	rotationCadence, hasRotationCadence := firstNHIPolicyInt(meta, "rotation_cadence_days", "max_rotation_age_days", "rotation_days")
	lastRotated := firstNHIPostureTimestamp(meta, "last_rotated_at", "rotated_at", "last_rotation_at")
	if lastRotated == nil {
		lastRotated = nhiPolicyIssuedAt(item, meta)
	}
	credentialAgeDays := 0
	if lastRotated != nil {
		credentialAgeDays = daysBetween(*lastRotated, now)
	}

	maxTTL, hasMaxTTL := firstNHIPolicyInt(meta, "max_ttl_days", "max_lifetime_days", "maximum_ttl_days")
	issuedAt := nhiPolicyIssuedAt(item, meta)
	expiresAt := nhiPolicyExpiresAt(item, meta)
	remainingTTLDays := 0
	if expiresAt != nil {
		remainingTTLDays = daysBetween(now, *expiresAt)
	}

	businessPurpose := strings.TrimSpace(firstNonEmpty(
		metadataString(meta, "business_purpose"),
		metadataString(meta, "purpose"),
		metadataString(meta, "justification"),
	))

	var violations []string
	if hasRotationCadence && rotationCadence > 0 && lastRotated != nil && credentialAgeDays > rotationCadence {
		violations = append(violations, "rotation_overdue")
	}
	if len(disallowedScopes) > 0 {
		violations = append(violations, "scope_out_of_policy")
	}
	if len(disallowedGeos) > 0 {
		violations = append(violations, "geo_out_of_policy")
	}
	if hasMaxTTL || firstNHIPolicyBool(meta, "require_expiry", "expiry_required") {
		switch {
		case expiresAt == nil:
			violations = append(violations, "expiry_missing")
		case expiresAt.Before(now):
			violations = append(violations, "expiry_expired")
		case hasMaxTTL && maxTTL > 0 && issuedAt != nil && daysBetween(*issuedAt, *expiresAt) > maxTTL:
			violations = append(violations, "expiry_ttl_exceeds_policy")
		}
	}
	if businessPurpose == "" && firstNHIPolicyBool(meta, "policy_required", "require_business_purpose", "business_purpose_required") {
		violations = append(violations, "business_purpose_missing")
	}

	severity := nhiPolicySeverity(violations)
	riskScore := item.RiskScore
	if riskScore == 0 && len(violations) > 0 {
		riskScore = nhiPolicyRiskScore(severity, len(violations))
	}
	return nhiPolicyComplianceFinding{
		InventoryID:         item.ID,
		Kind:                item.Kind,
		Source:              item.Source,
		DisplayName:         item.DisplayName,
		OwnerID:             item.OwnerID,
		Status:              item.Status,
		PolicyStatus:        nhiPolicyStatus(violations),
		Severity:            severity,
		RiskScore:           riskScore,
		ViolationTypes:      violations,
		RotationCadenceDays: rotationCadence,
		CredentialAgeDays:   credentialAgeDays,
		MaxTTLDays:          maxTTL,
		RemainingTTLDays:    remainingTTLDays,
		AllowedScopes:       allowedScopes,
		GrantedScopes:       grantedScopes,
		DisallowedScopes:    disallowedScopes,
		AllowedGeos:         allowedGeos,
		ObservedGeos:        observedGeos,
		DisallowedGeos:      disallowedGeos,
		BusinessPurpose:     businessPurpose,
		Recommendation:      nhiPolicyRecommendation(violations, disallowedScopes, disallowedGeos),
		EvidenceRefs:        nhiPolicyEvidenceRefs(item, meta),
		LastRotatedAt:       lastRotated,
		ExpiresAt:           expiresAt,
	}, true
}

func nhiPolicyIsGoverned(item nhiInventoryItem, meta map[string]any) bool {
	if firstNHIPolicyBool(meta, "policy_required", "require_business_purpose", "business_purpose_required", "require_expiry", "expiry_required") {
		return true
	}
	if item.NotAfter != nil {
		return true
	}
	for _, field := range []string{
		"rotation_cadence_days", "max_rotation_age_days", "rotation_days",
		"max_ttl_days", "max_lifetime_days", "maximum_ttl_days",
		"business_purpose", "purpose", "justification",
		"expires_at", "expiration_at", "not_after", "issued_at", "last_rotated_at",
	} {
		if _, ok := meta[field]; ok {
			return true
		}
	}
	for _, fields := range [][]string{nhiPolicyAllowedScopeFields, nhiPolicyAllowedGeoFields, nhiPolicyObservedGeoFields, nhiPostureGrantedFields} {
		for _, field := range fields {
			if _, ok := meta[field]; ok {
				return true
			}
		}
	}
	return false
}

func normalizeNHIPolicyGeos(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		geo := strings.ToUpper(strings.TrimSpace(value))
		if geo == "" || seen[geo] {
			continue
		}
		seen[geo] = true
		out = append(out, geo)
	}
	return out
}

func firstNHIPolicyBool(meta map[string]any, fields ...string) bool {
	for _, field := range fields {
		value, ok := meta[field]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			if typed {
				return true
			}
		case string:
			switch strings.ToLower(strings.TrimSpace(typed)) {
			case "true", "yes", "1", "required":
				return true
			}
		}
	}
	return false
}

func firstNHIPolicyInt(meta map[string]any, fields ...string) (int, bool) {
	for _, field := range fields {
		value, ok := meta[field]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case int:
			return typed, true
		case int64:
			return int(typed), true
		case float64:
			return int(typed), true
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(typed))
			return n, err == nil
		}
	}
	return 0, false
}

func nhiPolicyIssuedAt(item nhiInventoryItem, meta map[string]any) *time.Time {
	if t := firstNHIPostureTimestamp(meta, "issued_at", "created_at", "not_before"); t != nil {
		return t
	}
	if item.NotBefore != nil {
		t := item.NotBefore.UTC()
		return &t
	}
	t := item.CreatedAt.UTC()
	return &t
}

func nhiPolicyExpiresAt(item nhiInventoryItem, meta map[string]any) *time.Time {
	if t := firstNHIPostureTimestamp(meta, "expires_at", "expiration_at", "not_after"); t != nil {
		return t
	}
	if item.NotAfter != nil {
		t := item.NotAfter.UTC()
		return &t
	}
	return nil
}

func daysBetween(start, end time.Time) int {
	return int(end.Sub(start).Hours() / 24)
}

func nhiPolicyStatus(violations []string) string {
	if len(violations) == 0 {
		return "compliant"
	}
	return "violating"
}

func nhiPolicySeverity(violations []string) string {
	if len(violations) >= 4 || containsNHIString(violations, "expiry_expired") {
		return "critical"
	}
	if len(violations) >= 2 || containsNHIString(violations, "scope_out_of_policy") || containsNHIString(violations, "geo_out_of_policy") {
		return "high"
	}
	if len(violations) == 1 {
		return "medium"
	}
	return "low"
}

func nhiPolicyRiskScore(severity string, violationCount int) int {
	base := map[string]int{"critical": 90, "high": 74, "medium": 52, "low": 20}[severity]
	score := base + violationCount*2
	if score > 100 {
		return 100
	}
	return score
}

func nhiPolicyRecommendation(violations, disallowedScopes, disallowedGeos []string) string {
	if len(violations) == 0 {
		return "Policy evidence is complete and observed use stays inside the allowed envelope."
	}
	parts := make([]string, 0, len(violations))
	if containsNHIString(violations, "rotation_overdue") {
		parts = append(parts, "rotate the credential")
	}
	if len(disallowedScopes) > 0 {
		parts = append(parts, "remove disallowed scopes "+strings.Join(disallowedScopes, ", "))
	}
	if len(disallowedGeos) > 0 {
		parts = append(parts, "block or investigate geographies "+strings.Join(disallowedGeos, ", "))
	}
	if containsNHIString(violations, "expiry_missing") {
		parts = append(parts, "set an expiry that meets the declared maximum TTL")
	}
	if containsNHIString(violations, "expiry_ttl_exceeds_policy") {
		parts = append(parts, "shorten the expiry to the declared maximum TTL")
	}
	if containsNHIString(violations, "expiry_expired") {
		parts = append(parts, "revoke or replace the expired credential")
	}
	if containsNHIString(violations, "business_purpose_missing") {
		parts = append(parts, "record a business purpose before approving continued use")
	}
	return "Bring the NHI back inside policy: " + strings.Join(parts, "; ") + "."
}

func containsNHIString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func nhiPolicyEvidenceRefs(item nhiInventoryItem, meta map[string]any) []string {
	out := []string{"inventory:" + item.ID}
	if strings.HasPrefix(item.ID, "finding/") {
		out = append(out, "discovery.finding:"+strings.TrimPrefix(item.ID, "finding/"))
	}
	for _, field := range []string{
		"policy_required", "rotation_cadence_days", "last_rotated_at", "issued_at", "expires_at", "max_ttl_days",
		"allowed_scopes", "granted_scopes", "allowed_geos", "observed_geos", "business_purpose",
	} {
		if _, ok := meta[field]; ok {
			out = append(out, "metadata:"+field)
		}
	}
	return out
}
