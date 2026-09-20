// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

var nhiOverPrivilegeCoverage = []string{
	"managed_identities",
	"discovery_findings",
	"usage_driven_scope_delta",
	"wildcard_admin_detection",
	"least_privilege_recommendations",
}

var nhiPostureGrantedFields = []string{
	"granted_scopes",
	"granted_permissions",
	"grants",
	"scopes",
	"permissions",
	"roles",
	"entitlements",
	"actions",
	"allowed_actions",
	"capabilities",
}

var nhiPostureUsedFields = []string{
	"used_scopes",
	"observed_scopes",
	"last_used_scopes",
	"used_permissions",
	"observed_permissions",
	"used_roles",
	"observed_roles",
	"used_actions",
	"observed_actions",
}

type nhiOverPrivilegeResponse struct {
	Capability  string                    `json:"capability"`
	GeneratedAt time.Time                 `json:"generated_at"`
	Coverage    []string                  `json:"coverage"`
	Summary     nhiOverPrivilegeSummary   `json:"summary"`
	Findings    []nhiOverPrivilegeFinding `json:"findings"`
}

type nhiOverPrivilegeSummary struct {
	TotalAnalyzed       int `json:"total_analyzed"`
	Overprivileged      int `json:"overprivileged"`
	Critical            int `json:"critical"`
	High                int `json:"high"`
	Medium              int `json:"medium"`
	Low                 int `json:"low"`
	LeastPrivilegePlans int `json:"least_privilege_plans"`
	UnusedGrants        int `json:"unused_grants"`
	WildcardGrants      int `json:"wildcard_grants"`
}

type nhiOverPrivilegeFinding struct {
	InventoryID       string     `json:"inventory_id"`
	Ref               string     `json:"ref,omitempty"`
	Kind              string     `json:"kind"`
	Source            string     `json:"source"`
	DisplayName       string     `json:"display_name"`
	OwnerID           string     `json:"owner_id,omitempty"`
	Status            string     `json:"status"`
	Severity          string     `json:"severity"`
	RiskScore         int        `json:"risk_score"`
	FindingTypes      []string   `json:"finding_types"`
	GrantedScopes     []string   `json:"granted_scopes"`
	UsedScopes        []string   `json:"used_scopes"`
	UnusedScopes      []string   `json:"unused_scopes"`
	RecommendedScopes []string   `json:"recommended_scopes"`
	UnusedRatio       float64    `json:"unused_ratio"`
	Recommendation    string     `json:"recommendation"`
	EvidenceRefs      []string   `json:"evidence_refs"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
}

func (a *API) listNHIOverPrivilegePosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.nhiOverPrivilegePosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) nhiOverPrivilegePosture(ctx context.Context, tenantID string) (nhiOverPrivilegeResponse, error) {
	inventory, err := a.nhiInventory(ctx, tenantID)
	if err != nil {
		return nhiOverPrivilegeResponse{}, err
	}
	out := nhiOverPrivilegeResponse{
		Capability:  "CAP-POST-01",
		GeneratedAt: time.Now().UTC(),
		Coverage:    append([]string(nil), nhiOverPrivilegeCoverage...),
		Findings:    []nhiOverPrivilegeFinding{},
	}
	for _, item := range inventory.Items {
		finding, ok := nhiOverPrivilegeForItem(item)
		if len(finding.GrantedScopes) > 0 && len(finding.UsedScopes) > 0 {
			out.Summary.TotalAnalyzed++
		}
		if !ok {
			continue
		}
		out.Findings = append(out.Findings, finding)
		out.Summary.Overprivileged++
		out.Summary.LeastPrivilegePlans++
		out.Summary.UnusedGrants += len(finding.UnusedScopes)
		out.Summary.WildcardGrants += countNHIWideGrants(finding.GrantedScopes)
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

func nhiOverPrivilegeForItem(item nhiInventoryItem) (nhiOverPrivilegeFinding, bool) {
	meta := decodeNHIInventoryMetadata(item.Metadata)
	granted := collectNHIPostureStrings(meta, nhiPostureGrantedFields)
	used := collectNHIPostureStrings(meta, nhiPostureUsedFields)
	unused := diffNHIPostureStrings(granted, used)
	if len(granted) == 0 || len(used) == 0 || len(unused) == 0 {
		return nhiOverPrivilegeFinding{GrantedScopes: granted, UsedScopes: used}, false
	}
	ratio := float64(len(unused)) / float64(len(granted))
	broad := countNHIWideGrants(granted)
	findingTypes := []string{"unused_grants"}
	if len(used) > 0 {
		findingTypes = append(findingTypes, "usage_driven_scope_delta")
	}
	if broad > 0 {
		findingTypes = append(findingTypes, "wildcard_or_admin_grant")
	}
	if ratio >= 0.5 {
		findingTypes = append(findingTypes, "excessive_scope")
	}
	severity := nhiOverPrivilegeSeverity(ratio, len(unused), broad)
	riskScore := item.RiskScore
	if riskScore == 0 {
		riskScore = nhiOverPrivilegeRiskScore(severity, ratio, broad)
	}
	lastUsed := firstNHIPostureTimestamp(meta, "last_used_at", "last_seen_at", "last_activity_at")
	recommended := used
	if len(recommended) == 0 {
		recommended = diffNHIPostureStrings(granted, unused)
	}
	return nhiOverPrivilegeFinding{
		InventoryID:       item.ID,
		Ref:               item.Ref,
		Kind:              item.Kind,
		Source:            item.Source,
		DisplayName:       item.DisplayName,
		OwnerID:           item.OwnerID,
		Status:            item.Status,
		Severity:          severity,
		RiskScore:         riskScore,
		FindingTypes:      findingTypes,
		GrantedScopes:     granted,
		UsedScopes:        used,
		UnusedScopes:      unused,
		RecommendedScopes: recommended,
		UnusedRatio:       ratio,
		Recommendation:    nhiOverPrivilegeRecommendation(unused, recommended),
		EvidenceRefs:      nhiOverPrivilegeEvidence(item, meta),
		LastUsedAt:        lastUsed,
	}, true
}

func collectNHIPostureStrings(meta map[string]any, fields []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, field := range fields {
		for _, value := range readNHIPostureStrings(meta[field]) {
			key := normalizeNHIPostureString(value)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}

func readNHIPostureStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, v := range typed {
			out = append(out, readNHIPostureStrings(v)...)
		}
		return out
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return keys
	case map[string]string:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return keys
	case json.RawMessage:
		var decoded any
		if err := json.Unmarshal(typed, &decoded); err != nil {
			return nil
		}
		return readNHIPostureStrings(decoded)
	case string:
		return splitNHIPostureString(typed)
	default:
		return nil
	}
}

func splitNHIPostureString(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.Contains(value, ",") {
		parts := strings.Split(value, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	}
	return []string{value}
}

func diffNHIPostureStrings(left, right []string) []string {
	used := map[string]bool{}
	for _, value := range right {
		if key := normalizeNHIPostureString(value); key != "" {
			used[key] = true
		}
	}
	var out []string
	for _, value := range left {
		key := normalizeNHIPostureString(value)
		if key == "" || used[key] {
			continue
		}
		out = append(out, value)
	}
	return out
}

func countNHIWideGrants(values []string) int {
	count := 0
	for _, value := range values {
		if isNHIWideGrant(value) {
			count++
		}
	}
	return count
}

func isNHIWideGrant(value string) bool {
	v := normalizeNHIPostureString(value)
	if v == "" {
		return false
	}
	switch v {
	case "*", "*:*", "admin", "administrator", "root", "owner", "superuser":
		return true
	}
	return strings.Contains(v, "*") ||
		strings.Contains(v, "admin:") ||
		strings.Contains(v, ":admin") ||
		strings.HasSuffix(v, ":write") ||
		strings.HasSuffix(v, ".write")
}

func normalizeNHIPostureString(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func nhiOverPrivilegeSeverity(unusedRatio float64, unusedCount, broadGrantCount int) string {
	switch {
	case (broadGrantCount > 0 && unusedRatio >= 0.5) || unusedCount >= 4:
		return "critical"
	case broadGrantCount > 0 || unusedRatio >= 0.5 || unusedCount >= 2:
		return "high"
	case unusedRatio > 0:
		return "medium"
	default:
		return "low"
	}
}

func nhiOverPrivilegeRiskScore(severity string, unusedRatio float64, broadGrantCount int) int {
	base := map[string]int{"critical": 90, "high": 75, "medium": 55, "low": 30}[severity]
	score := base + int(unusedRatio*10) + broadGrantCount*3
	if score > 100 {
		return 100
	}
	return score
}

func nhiOverPrivilegeRecommendation(unused, recommended []string) string {
	if len(recommended) == 0 {
		return "Review the standing grant and replace it with task-specific scopes; no usage evidence justifies the current breadth."
	}
	return "Remove unused grants " + strings.Join(unused, ", ") + "; keep observed least-privilege grants " + strings.Join(recommended, ", ") + "."
}

func nhiOverPrivilegeEvidence(item nhiInventoryItem, meta map[string]any) []string {
	evidence := []string{"inventory:" + item.ID}
	for _, field := range nhiPostureGrantedFields {
		if _, ok := meta[field]; ok {
			evidence = append(evidence, "metadata:"+field)
			break
		}
	}
	for _, field := range nhiPostureUsedFields {
		if _, ok := meta[field]; ok {
			evidence = append(evidence, "metadata:"+field)
			break
		}
	}
	return evidence
}

func firstNHIPostureTimestamp(meta map[string]any, fields ...string) *time.Time {
	for _, field := range fields {
		raw, ok := meta[field].(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw)); err == nil {
			utc := t.UTC()
			return &utc
		}
	}
	return nil
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
