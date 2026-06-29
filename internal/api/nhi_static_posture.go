package api

import (
	"context"
	"net/http"
	"sort"
	"time"
)

const (
	nhiLongLivedCredentialDays = 365
	nhiRotationOverdueDays     = 180
	nhiNoExpiryMinimumAgeDays  = 90
)

var nhiStaticCoverage = []string{
	"managed_identities",
	"discovery_findings",
	"long_lived_credentials",
	"static_credential_detection",
	"no_expiry_detection",
	"rotation_age",
	"remediation_recommendations",
}

var nhiExpiryTimestampFields = []string{
	"expires_at",
	"not_after",
	"expiration_at",
	"valid_until",
	"expires",
}

var nhiRotationTimestampFields = []string{
	"last_rotated_at",
	"last_rotation_at",
	"rotated_at",
	"rotation_at",
}

var nhiStaticMarkerFields = []string{
	"credential_lifecycle",
	"credential_type",
	"secret_lifetime",
	"secret_type",
	"rotation_model",
	"lifecycle",
}

type nhiStaticPostureResponse struct {
	Capability  string                    `json:"capability"`
	GeneratedAt time.Time                 `json:"generated_at"`
	Coverage    []string                  `json:"coverage"`
	Thresholds  nhiStaticThresholds       `json:"thresholds"`
	Summary     nhiStaticPostureSummary   `json:"summary"`
	Findings    []nhiStaticPostureFinding `json:"findings"`
}

type nhiStaticThresholds struct {
	LongLivedCredentialDays int `json:"long_lived_credential_days"`
	RotationOverdueDays     int `json:"rotation_overdue_days"`
	NoExpiryMinimumAgeDays  int `json:"no_expiry_minimum_age_days"`
}

type nhiStaticPostureSummary struct {
	TotalAnalyzed     int `json:"total_analyzed"`
	Findings          int `json:"findings"`
	LongLived         int `json:"long_lived"`
	StaticCredentials int `json:"static_credentials"`
	NoExpiry          int `json:"no_expiry"`
	RotationOverdue   int `json:"rotation_overdue"`
	Critical          int `json:"critical"`
	High              int `json:"high"`
	Medium            int `json:"medium"`
	Low               int `json:"low"`
	Recommendations   int `json:"recommendations"`
}

type nhiStaticPostureFinding struct {
	InventoryID       string     `json:"inventory_id"`
	Ref               string     `json:"ref,omitempty"`
	Kind              string     `json:"kind"`
	Source            string     `json:"source"`
	DisplayName       string     `json:"display_name"`
	OwnerID           string     `json:"owner_id,omitempty"`
	OwnerStatus       string     `json:"owner_status"`
	Status            string     `json:"status"`
	Severity          string     `json:"severity"`
	RiskScore         int        `json:"risk_score"`
	FindingTypes      []string   `json:"finding_types"`
	CredentialAgeDays int        `json:"credential_age_days"`
	TTLDays           int        `json:"ttl_days"`
	RotationAgeDays   int        `json:"rotation_age_days"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	LastRotatedAt     *time.Time `json:"last_rotated_at,omitempty"`
	Recommendation    string     `json:"recommendation"`
	EvidenceRefs      []string   `json:"evidence_refs"`
}

func (a *API) listNHIStaticPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.nhiStaticPosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) nhiStaticPosture(ctx context.Context, tenantID string) (nhiStaticPostureResponse, error) {
	inventory, err := a.nhiInventory(ctx, tenantID)
	if err != nil {
		return nhiStaticPostureResponse{}, err
	}
	now := time.Now().UTC()
	out := nhiStaticPostureResponse{
		Capability:  "CAP-POST-03",
		GeneratedAt: now,
		Coverage:    append([]string(nil), nhiStaticCoverage...),
		Thresholds: nhiStaticThresholds{
			LongLivedCredentialDays: nhiLongLivedCredentialDays,
			RotationOverdueDays:     nhiRotationOverdueDays,
			NoExpiryMinimumAgeDays:  nhiNoExpiryMinimumAgeDays,
		},
		Findings: []nhiStaticPostureFinding{},
	}
	for _, item := range inventory.Items {
		if !nhiStaleAnalyzable(item) {
			continue
		}
		out.Summary.TotalAnalyzed++
		finding, ok := nhiStaticFindingForItem(item, now)
		if !ok {
			continue
		}
		out.Findings = append(out.Findings, finding)
		out.Summary.Findings++
		out.Summary.Recommendations++
		if nhiStringSliceContains(finding.FindingTypes, "long_lived_credential") {
			out.Summary.LongLived++
		}
		if nhiStringSliceContains(finding.FindingTypes, "static_credential") {
			out.Summary.StaticCredentials++
		}
		if nhiStringSliceContains(finding.FindingTypes, "no_expiry") {
			out.Summary.NoExpiry++
		}
		if nhiStringSliceContains(finding.FindingTypes, "rotation_overdue") {
			out.Summary.RotationOverdue++
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

func nhiStaticFindingForItem(item nhiInventoryItem, now time.Time) (nhiStaticPostureFinding, bool) {
	meta := decodeNHIInventoryMetadata(item.Metadata)
	createdAt := nhiCreatedAt(item, meta)
	credentialAge := daysSince(now, createdAt)
	expiresAt := nhiExpiryAt(item, meta)
	lastRotatedAt := firstNHIPostureTimestamp(meta, nhiRotationTimestampFields...)
	rotationAge := 0
	if lastRotatedAt != nil {
		rotationAge = daysSince(now, *lastRotatedAt)
	} else {
		rotationAge = credentialAge
	}
	ttlDays := 0
	if expiresAt != nil && !createdAt.IsZero() && expiresAt.After(createdAt) {
		ttlDays = int(expiresAt.Sub(createdAt).Hours() / 24)
	}

	marker := hasNHIStaticMarker(meta)
	staticKind := isNHIStaticCredentialKind(item.Kind)
	longLived := ttlDays >= nhiLongLivedCredentialDays
	noExpiry := expiresAt == nil && credentialAge >= nhiNoExpiryMinimumAgeDays && staticKind
	staticCredential := marker || (noExpiry && staticKind)
	rotationOverdue := rotationAge >= nhiRotationOverdueDays && (staticCredential || longLived || noExpiry)

	var findingTypes []string
	if longLived {
		findingTypes = append(findingTypes, "long_lived_credential")
	}
	if staticCredential {
		findingTypes = append(findingTypes, "static_credential")
	}
	if noExpiry {
		findingTypes = append(findingTypes, "no_expiry")
	}
	if rotationOverdue {
		findingTypes = append(findingTypes, "rotation_overdue")
	}
	if len(findingTypes) == 0 {
		return nhiStaticPostureFinding{}, false
	}
	severity := nhiStaticSeverity(longLived, staticCredential, noExpiry, rotationOverdue)
	riskScore := item.RiskScore
	if riskScore == 0 {
		riskScore = nhiStaticRiskScore(severity, credentialAge, ttlDays, rotationAge, len(findingTypes))
	}
	return nhiStaticPostureFinding{
		InventoryID:       item.ID,
		Ref:               item.Ref,
		Kind:              item.Kind,
		Source:            item.Source,
		DisplayName:       item.DisplayName,
		OwnerID:           item.OwnerID,
		OwnerStatus:       nhiOwnerStatus(item, meta),
		Status:            item.Status,
		Severity:          severity,
		RiskScore:         riskScore,
		FindingTypes:      findingTypes,
		CredentialAgeDays: credentialAge,
		TTLDays:           ttlDays,
		RotationAgeDays:   rotationAge,
		CreatedAt:         createdAt,
		ExpiresAt:         expiresAt,
		LastRotatedAt:     lastRotatedAt,
		Recommendation:    nhiStaticRecommendation(findingTypes),
		EvidenceRefs:      nhiStaticEvidence(item, meta, expiresAt != nil, lastRotatedAt != nil),
	}, true
}

func nhiExpiryAt(item nhiInventoryItem, meta map[string]any) *time.Time {
	if t := firstNHIPostureTimestamp(meta, nhiExpiryTimestampFields...); t != nil {
		return t
	}
	if item.NotAfter != nil {
		utc := item.NotAfter.UTC()
		return &utc
	}
	return nil
}

func hasNHIStaticMarker(meta map[string]any) bool {
	for _, value := range collectNHIPostureStrings(meta, nhiStaticMarkerFields) {
		switch normalizeNHIPostureString(value) {
		case "static", "long_lived", "long-lived", "never_expires", "never-expires", "permanent", "hardcoded", "shared_secret":
			return true
		}
	}
	return false
}

func isNHIStaticCredentialKind(kind string) bool {
	switch normalizeNHIInventoryKind(kind) {
	case "api_key", "token", "secret", "ssh_key", "service_account", "iam_role", "webhook", "oauth_app":
		return true
	default:
		return false
	}
}

func nhiStaticSeverity(longLived, staticCredential, noExpiry, rotationOverdue bool) string {
	switch {
	case rotationOverdue && staticCredential && (longLived || noExpiry):
		return "critical"
	case rotationOverdue && (longLived || staticCredential || noExpiry):
		return "high"
	case longLived || staticCredential || noExpiry:
		return "medium"
	default:
		return "low"
	}
}

func nhiStaticRiskScore(severity string, credentialAge, ttlDays, rotationAge, types int) int {
	base := map[string]int{"critical": 92, "high": 78, "medium": 58, "low": 30}[severity]
	score := base + minInt(credentialAge/120, 8) + minInt(ttlDays/365, 6) + minInt(rotationAge/180, 6) + types*3
	if score > 100 {
		return 100
	}
	return score
}

func nhiStaticRecommendation(types []string) string {
	parts := map[string]bool{}
	for _, typ := range types {
		parts[typ] = true
	}
	switch {
	case parts["no_expiry"] && parts["rotation_overdue"]:
		return "Replace the static credential with a short-lived credential or set an expiry, then rotate it immediately."
	case parts["long_lived_credential"] && parts["rotation_overdue"]:
		return "Shorten the credential lifetime and rotate it before reissuing with an expiry-bound profile."
	case parts["static_credential"]:
		return "Move this NHI to a managed rotation path or replace it with an ephemeral credential."
	case parts["long_lived_credential"]:
		return "Reduce the credential TTL and require renewal through the lifecycle engine."
	default:
		return "Review credential lifetime and rotation metadata before the next production use."
	}
}

func nhiStaticEvidence(item nhiInventoryItem, meta map[string]any, hasExpiry, hasRotation bool) []string {
	evidence := []string{"inventory:" + item.ID}
	for _, field := range nhiCreatedTimestampFields {
		if _, ok := meta[field]; ok {
			evidence = append(evidence, "metadata:"+field)
			break
		}
	}
	if hasExpiry {
		for _, field := range nhiExpiryTimestampFields {
			if _, ok := meta[field]; ok {
				evidence = append(evidence, "metadata:"+field)
				break
			}
		}
	}
	if hasRotation {
		for _, field := range nhiRotationTimestampFields {
			if _, ok := meta[field]; ok {
				evidence = append(evidence, "metadata:"+field)
				break
			}
		}
	}
	for _, field := range nhiStaticMarkerFields {
		if _, ok := meta[field]; ok {
			evidence = append(evidence, "metadata:"+field)
			break
		}
	}
	return evidence
}
