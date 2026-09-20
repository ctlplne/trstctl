// SPDX-License-Identifier: BUSL-1.1

package risk

import "strings"

const (
	// UrgentSummaryComplete means every named projection was read successfully.
	// The API returns an error instead of this value when either read fails, so a
	// consumer can never turn missing authority into a reassuring zero.
	UrgentSummaryComplete = "complete"
	urgentScope           = "All served credential-risk and contextual-priority projections for this tenant; totals deduplicate credential_id."
)

// UrgentProjectionSummary keeps each source count visible. Operators can see
// why the union is non-zero without adding the two columns and double-counting
// a certificate that appears in both projections.
type UrgentProjectionSummary struct {
	Analyzed int `json:"analyzed"`
	Critical int `json:"critical"`
	High     int `json:"high"`
}

// UrgentSummary is the canonical headline contract shared by the API,
// Dashboard, Risk page, and risk-alert producer.
type UrgentSummary struct {
	Status               string                  `json:"status"`
	Scope                string                  `json:"scope"`
	IncludedProjections  []string                `json:"included_projections"`
	UniqueAnalyzed       int                     `json:"unique_analyzed"`
	Urgent               int                     `json:"urgent"`
	Critical             int                     `json:"critical"`
	High                 int                     `json:"high"`
	CredentialRisk       UrgentProjectionSummary `json:"credential_risk"`
	ContextualPriorities UrgentProjectionSummary `json:"contextual_priorities"`
}

const (
	urgencyNone = iota
	urgencyHigh
	urgencyCritical
)

// SummarizeUrgentRisk merges both served projections by credential identity.
// A contextual score may raise a certificate's urgency, but can never create a
// second headline record for the same credential_id.
func SummarizeUrgentRisk(base []CredentialRisk, contextual []ContextualPriority) UrgentSummary {
	summary := UrgentSummary{
		Status: UrgentSummaryComplete,
		Scope:  urgentScope,
		IncludedProjections: []string{
			"credential_risk_scores",
			"contextual_priorities",
		},
		CredentialRisk:       summarizeBaseProjection(base),
		ContextualPriorities: summarizeContextualProjection(contextual),
	}

	byCredential := make(map[string]int, len(base)+len(contextual))
	for _, row := range base {
		mergeUrgency(byCredential, urgentIdentity(row.CredentialID, row.Kind, row.Subject), baseUrgency(row.Score))
	}
	for _, row := range contextual {
		mergeUrgency(byCredential, urgentIdentity(row.CredentialID, row.Kind, row.Subject), contextualUrgency(row))
	}
	summary.UniqueAnalyzed = len(byCredential)
	for _, urgency := range byCredential {
		switch urgency {
		case urgencyCritical:
			summary.Critical++
		case urgencyHigh:
			summary.High++
		}
	}
	summary.Urgent = summary.Critical + summary.High
	return summary
}

func summarizeBaseProjection(rows []CredentialRisk) UrgentProjectionSummary {
	result := UrgentProjectionSummary{Analyzed: len(rows)}
	for _, row := range rows {
		switch baseUrgency(row.Score) {
		case urgencyCritical:
			result.Critical++
		case urgencyHigh:
			result.High++
		}
	}
	return result
}

func summarizeContextualProjection(rows []ContextualPriority) UrgentProjectionSummary {
	result := UrgentProjectionSummary{Analyzed: len(rows)}
	for _, row := range rows {
		switch contextualUrgency(row) {
		case urgencyCritical:
			result.Critical++
		case urgencyHigh:
			result.High++
		}
	}
	return result
}

func baseUrgency(score float64) int {
	switch {
	case score >= 90:
		return urgencyCritical
	case score >= 70:
		return urgencyHigh
	default:
		return urgencyNone
	}
}

func contextualUrgency(row ContextualPriority) int {
	switch strings.ToLower(strings.TrimSpace(row.Severity)) {
	case "critical":
		return urgencyCritical
	case "high":
		return urgencyHigh
	default:
		return urgencyNone
	}
}

func mergeUrgency(rows map[string]int, identity string, urgency int) {
	if current, ok := rows[identity]; !ok || urgency > current {
		rows[identity] = urgency
	}
}

func urgentIdentity(id, kind, subject string) string {
	if id = strings.TrimSpace(id); id != "" {
		return id
	}
	// Production rows always have IDs. This deterministic fallback keeps a
	// malformed legacy row visible without letting two blank IDs collapse.
	return strings.ToLower(strings.TrimSpace(kind)) + "\x1f" + strings.ToLower(strings.TrimSpace(subject))
}

// DiscoveryUrgency applies the contextual projection's already-published
// severity bands to one stored discovery score. The projector uses this same
// decision when it raises the durable operator alert; it does not invent a
// third set of headline thresholds.
func DiscoveryUrgency(score int) string {
	switch contextualSeverity(float64(score)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	default:
		return ""
	}
}
