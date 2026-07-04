// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/store"
)

var nhiShadowCoverage = []string{
	"discovery_findings",
	"unmanaged_triage",
	"investigating_triage",
	"unregistered_detection",
	"ownerless_detection",
	"cross_surface_nhi",
	"remediation_recommendations",
}

type nhiShadowPostureResponse struct {
	Capability         string                    `json:"capability"`
	GeneratedAt        time.Time                 `json:"generated_at"`
	Coverage           []string                  `json:"coverage"`
	Summary            nhiShadowPostureSummary   `json:"summary"`
	Findings           []nhiShadowPostureFinding `json:"findings"`
	RecommendedActions []string                  `json:"recommended_actions"`
	EvidenceRefs       []string                  `json:"evidence_refs"`
}

type nhiShadowPostureSummary struct {
	TotalAnalyzed int            `json:"total_analyzed"`
	Findings      int            `json:"findings"`
	Unmanaged     int            `json:"unmanaged"`
	Investigating int            `json:"investigating"`
	Unregistered  int            `json:"unregistered"`
	Ownerless     int            `json:"ownerless"`
	Critical      int            `json:"critical"`
	High          int            `json:"high"`
	Medium        int            `json:"medium"`
	Low           int            `json:"low"`
	KindCounts    map[string]int `json:"kind_counts"`
	SurfaceCounts map[string]int `json:"surface_counts"`
}

type nhiShadowPostureFinding struct {
	FindingID         string    `json:"finding_id"`
	SourceID          string    `json:"source_id"`
	RunID             string    `json:"run_id"`
	Kind              string    `json:"kind"`
	Ref               string    `json:"ref"`
	DisplayName       string    `json:"display_name"`
	Surface           string    `json:"surface,omitempty"`
	System            string    `json:"system,omitempty"`
	Provenance        string    `json:"provenance"`
	Fingerprint       string    `json:"fingerprint,omitempty"`
	TriageStatus      string    `json:"triage_status"`
	ManagedIdentityID string    `json:"managed_identity_id,omitempty"`
	OwnerStatus       string    `json:"owner_status"`
	Severity          string    `json:"severity"`
	RiskScore         int       `json:"risk_score"`
	Recommendation    string    `json:"recommendation"`
	EvidenceRefs      []string  `json:"evidence_refs"`
	DiscoveredAt      time.Time `json:"discovered_at"`
}

func (a *API) listNHIShadowPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.nhiShadowPosture(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) nhiShadowPosture(ctx context.Context, tenantID string) (nhiShadowPostureResponse, error) {
	out := nhiShadowPostureResponse{
		Capability:  "CAP-NHI-05",
		GeneratedAt: time.Now().UTC(),
		Coverage:    append([]string(nil), nhiShadowCoverage...),
		Summary: nhiShadowPostureSummary{
			KindCounts:    map[string]int{},
			SurfaceCounts: map[string]int{},
		},
		Findings: []nhiShadowPostureFinding{},
		RecommendedActions: []string{
			"Claim legitimate findings to managed identities, owners, or teams before dismissal.",
			"Rotate or revoke unmanaged credentials that lack a business owner or expected system provenance.",
			"Create a recurring discovery schedule for every source that produced shadow NHI evidence.",
		},
		EvidenceRefs: []string{"projection:discovery_findings"},
	}

	after := store.ZeroUUID
	for {
		rows, err := a.store.ListDiscoveryFindingsPage(ctx, tenantID, "", after, maxNHIInventoryRowsPerSource)
		if err != nil {
			return out, err
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			out.Summary.TotalAnalyzed++
			finding, ok := nhiShadowFindingForRow(row)
			if !ok {
				continue
			}
			out.Findings = append(out.Findings, finding)
			out.Summary.Findings++
			out.Summary.KindCounts[finding.Kind]++
			if finding.Surface != "" {
				out.Summary.SurfaceCounts[finding.Surface]++
			}
			switch finding.TriageStatus {
			case "investigating":
				out.Summary.Investigating++
			default:
				out.Summary.Unmanaged++
			}
			if finding.ManagedIdentityID == "" {
				out.Summary.Unregistered++
			}
			if finding.OwnerStatus == "ownerless" {
				out.Summary.Ownerless++
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
		if len(rows) < maxNHIInventoryRowsPerSource {
			break
		}
		after = rows[len(rows)-1].ID
	}

	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		if a.DisplayName != b.DisplayName {
			return a.DisplayName < b.DisplayName
		}
		return a.FindingID < b.FindingID
	})
	return out, nil
}

func nhiShadowFindingForRow(row store.DiscoveryFinding) (nhiShadowPostureFinding, bool) {
	status := strings.ToLower(strings.TrimSpace(row.TriageStatus))
	if status == "" {
		status = "unmanaged"
	}
	switch status {
	case "managed", "dismissed", "resolved", "closed":
		return nhiShadowPostureFinding{}, false
	}

	meta := decodeNHIInventoryMetadata(row.Metadata)
	kind := discoveryFindingToNHIKind(row.Kind, meta)
	displayName := firstNonEmpty(metadataString(meta, "display_name"), metadataString(meta, "principal"), row.Ref, row.ID)
	surface := metadataString(meta, "surface")
	if surface == "" && strings.HasPrefix(row.Provenance, "nhi_cross_surface:") {
		parts := strings.Split(row.Provenance, ":")
		if len(parts) >= 2 {
			surface = strings.TrimSpace(parts[1])
		}
	}
	system := metadataString(meta, "system")
	ownerStatus := nhiShadowOwnerStatus(meta)
	managedID := ""
	if row.ManagedIdentityID != nil {
		managedID = strings.TrimSpace(*row.ManagedIdentityID)
	}
	severity := nhiShadowSeverity(row.RiskScore, status, ownerStatus, managedID)
	return nhiShadowPostureFinding{
		FindingID:         row.ID,
		SourceID:          row.SourceID,
		RunID:             row.RunID,
		Kind:              kind,
		Ref:               row.Ref,
		DisplayName:       displayName,
		Surface:           surface,
		System:            system,
		Provenance:        row.Provenance,
		Fingerprint:       row.Fingerprint,
		TriageStatus:      status,
		ManagedIdentityID: managedID,
		OwnerStatus:       ownerStatus,
		Severity:          severity,
		RiskScore:         row.RiskScore,
		Recommendation:    nhiShadowRecommendation(status, ownerStatus, managedID),
		EvidenceRefs:      nhiShadowEvidenceRefs(row, meta),
		DiscoveredAt:      row.DiscoveredAt,
	}, true
}

func nhiShadowOwnerStatus(meta map[string]any) string {
	for _, field := range nhiOwnerMetadataFields {
		if strings.TrimSpace(metadataString(meta, field)) != "" {
			return "owned_metadata"
		}
	}
	return "ownerless"
}

func nhiShadowSeverity(riskScore int, status, ownerStatus, managedID string) string {
	switch {
	case riskScore >= 90 || (ownerStatus == "ownerless" && riskScore >= 70):
		return "critical"
	case riskScore >= 70 || (ownerStatus == "ownerless" && managedID == ""):
		return "high"
	case status == "investigating" || riskScore >= 40:
		return "medium"
	default:
		return "low"
	}
}

func nhiShadowRecommendation(status, ownerStatus, managedID string) string {
	if managedID != "" {
		return "Finish investigation and link the external evidence to the managed identity record."
	}
	if ownerStatus == "ownerless" {
		return "Assign an owner, claim to a managed identity, then rotate or revoke if the external record is unauthorized."
	}
	if status == "investigating" {
		return "Complete the investigation by claiming the finding or dismissing it with evidence."
	}
	return "Claim the finding to an existing identity or create one before allowing continued use."
}

func nhiShadowEvidenceRefs(row store.DiscoveryFinding, meta map[string]any) []string {
	out := []string{
		"discovery.finding:" + row.ID,
		"discovery.run:" + row.RunID,
		"discovery.source:" + row.SourceID,
	}
	for _, field := range []string{"surface", "system", "external_id", "credential_kind", "owner"} {
		if _, ok := meta[field]; ok {
			out = append(out, "metadata:"+field)
		}
	}
	return out
}
