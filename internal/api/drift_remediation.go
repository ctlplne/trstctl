package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/store"
)

const (
	driftDecisionInvestigate = "investigate"
	driftDecisionManaged     = "mark_managed"
	driftDecisionDismiss     = "dismiss"
)

type driftRemediationDecisionRequest struct {
	Decision          string   `json:"decision"`
	ManagedIdentityID string   `json:"managed_identity_id,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	Owner             *string  `json:"owner,omitempty"`
	Team              *string  `json:"team,omitempty"`
	Tags              []string `json:"tags,omitempty"`
}

type driftRemediationResponse struct {
	Capability    string                    `json:"capability"`
	DashboardPath string                    `json:"dashboard_path"`
	SourcesPath   string                    `json:"sources_path"`
	RunsPath      string                    `json:"runs_path"`
	FindingsPath  string                    `json:"findings_path"`
	Summary       driftRemediationSummary   `json:"summary"`
	Findings      []driftRemediationFinding `json:"findings"`
}

type driftRemediationSummary struct {
	SourceCount              int `json:"source_count"`
	FindingCount             int `json:"finding_count"`
	OpenFindingCount         int `json:"open_finding_count"`
	InvestigatingCount       int `json:"investigating_count"`
	RemediatedCount          int `json:"remediated_count"`
	DismissedCount           int `json:"dismissed_count"`
	RemediationDecisionCount int `json:"remediation_decision_count"`
	DeletedCount             int `json:"deleted_count"`
	ReplacedCount            int `json:"replaced_count"`
	RelocatedCount           int `json:"relocated_count"`
	PermissionChangedCount   int `json:"permission_changed_count"`
	CertificateCount         int `json:"certificate_count"`
	SSHKeyCount              int `json:"ssh_key_count"`
	SecretCount              int `json:"secret_count"`
}

type driftRemediationFinding struct {
	FindingID          string          `json:"finding_id"`
	RunID              string          `json:"run_id"`
	SourceID           string          `json:"source_id"`
	SourceName         string          `json:"source_name"`
	Ref                string          `json:"ref"`
	Provenance         string          `json:"provenance"`
	Fingerprint        string          `json:"fingerprint"`
	RiskScore          int             `json:"risk_score"`
	DriftType          string          `json:"drift_type"`
	CredentialClass    string          `json:"credential_class"`
	ExpectedMode       string          `json:"expected_mode,omitempty"`
	ActualMode         string          `json:"actual_mode,omitempty"`
	TriageStatus       string          `json:"triage_status"`
	TriageActor        string          `json:"triage_actor,omitempty"`
	TriageReason       string          `json:"triage_reason,omitempty"`
	TriagedAt          *time.Time      `json:"triaged_at,omitempty"`
	Metadata           json.RawMessage `json:"metadata"`
	RecommendedAction  string          `json:"recommended_action"`
	AvailableDecisions []string        `json:"available_decisions"`
	EvidenceRefs       []string        `json:"evidence_refs"`
}

type driftRemediationDecisionResponse struct {
	Decision     string                  `json:"decision"`
	EvidenceRefs []string                `json:"evidence_refs"`
	Finding      driftRemediationFinding `json:"finding"`
}

type driftFindingMetadata struct {
	Type       string `json:"type"`
	Class      string `json:"class"`
	Expected   string `json:"expected"`
	Actual     string `json:"actual"`
	ExpectedAt string `json:"expected_at"`
	ActualAt   string `json:"actual_at"`
	Mode       string `json:"mode"`
	ActualMode string `json:"actual_mode"`
}

func (a *API) getDriftRemediation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.driftRemediationStatus(r.Context(), tenantID, nil)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

//trstctl:mutation
func (a *API) decideDriftRemediation(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req driftRemediationDecisionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		current, err := a.store.GetDiscoveryFinding(ctx, tenantID, r.PathValue("id"))
		if err != nil {
			return 0, nil, discoveryTriageError(err)
		}
		if current.Kind != "credential_drift" {
			return 0, nil, errStatus(http.StatusConflict, "finding is not a credential_drift finding")
		}
		source, err := a.store.GetDiscoverySource(ctx, tenantID, current.SourceID)
		if err != nil {
			return 0, nil, err
		}
		if source.Kind != "drift" {
			return 0, nil, errStatus(http.StatusConflict, "finding is not from a drift discovery source")
		}

		decision := strings.TrimSpace(req.Decision)
		triage := discovery.TriageStatus("")
		var managedID *string
		switch decision {
		case driftDecisionInvestigate:
			triage = discovery.TriageInvestigating
		case driftDecisionManaged:
			triage = discovery.TriageManaged
			if strings.TrimSpace(req.ManagedIdentityID) != "" {
				id := strings.TrimSpace(req.ManagedIdentityID)
				managedID = &id
			}
		case driftDecisionDismiss:
			triage = discovery.TriageDismissed
		default:
			return 0, nil, errStatus(http.StatusBadRequest, "decision must be one of investigate, mark_managed, dismiss")
		}

		patch := driftDecisionMetadataPatch(req)
		start := time.Now()
		finding, err := a.orch.TriageDiscoveryFinding(ctx, tenantID, current.ID, triage, managedID, req.Reason, patch)
		a.observeFeature("discovery", "drift_remediation_decision", start, err)
		if err != nil {
			return 0, nil, discoveryTriageError(err)
		}
		resp := a.toDriftRemediationFinding(finding, source)
		resp.EvidenceRefs = append(resp.EvidenceRefs, "event:discovery.finding.triage_changed")
		return http.StatusOK, driftRemediationDecisionResponse{
			Decision:     decision,
			EvidenceRefs: []string{"event:discovery.finding.triage_changed", "discovery.finding:" + finding.ID},
			Finding:      resp,
		}, nil
	})
}

func driftDecisionMetadataPatch(req driftRemediationDecisionRequest) json.RawMessage {
	patch := map[string]any{
		"remediation_decision": strings.TrimSpace(req.Decision),
	}
	if req.Owner != nil {
		patch["owner"] = strings.TrimSpace(*req.Owner)
	}
	if req.Team != nil {
		patch["team"] = strings.TrimSpace(*req.Team)
	}
	if req.Tags != nil {
		patch["tags"] = cleanDiscoveryFindingTags(req.Tags)
	}
	b, err := json.Marshal(patch)
	if err != nil {
		return nil
	}
	return b
}

func (a *API) driftRemediationStatus(ctx context.Context, tenantID string, selected *store.DiscoveryFinding) (driftRemediationResponse, error) {
	out := driftRemediationResponse{
		Capability:    "F18",
		DashboardPath: "/api/v1/discovery/drift-remediation",
		SourcesPath:   "/api/v1/discovery/sources",
		RunsPath:      "/api/v1/discovery/runs",
		FindingsPath:  "/api/v1/discovery/findings",
		Findings:      []driftRemediationFinding{},
	}

	sources, err := a.store.ListDiscoverySourcesPage(ctx, tenantID, store.ZeroUUID, 100)
	if err != nil {
		return out, err
	}
	sourceByID := map[string]store.DiscoverySource{}
	for _, src := range sources {
		if src.Kind != "drift" {
			continue
		}
		sourceByID[src.ID] = src
		out.Summary.SourceCount++
	}

	findings, err := a.store.ListDiscoveryFindingsPage(ctx, tenantID, "", store.ZeroUUID, 100)
	if err != nil {
		return out, err
	}
	for _, f := range findings {
		src, ok := sourceByID[f.SourceID]
		if !ok || f.Kind != "credential_drift" {
			continue
		}
		out.addFinding(a.toDriftRemediationFinding(f, src))
	}
	if selected != nil {
		if src, ok := sourceByID[selected.SourceID]; ok && selected.Kind == "credential_drift" {
			found := false
			for _, item := range out.Findings {
				if item.FindingID == selected.ID {
					found = true
					break
				}
			}
			if !found {
				out.addFinding(a.toDriftRemediationFinding(*selected, src))
			}
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].RiskScore == out.Findings[j].RiskScore {
			return out.Findings[i].FindingID < out.Findings[j].FindingID
		}
		return out.Findings[i].RiskScore > out.Findings[j].RiskScore
	})
	return out, nil
}

func (out *driftRemediationResponse) addFinding(item driftRemediationFinding) {
	out.Findings = append(out.Findings, item)
	out.Summary.FindingCount++
	switch item.TriageStatus {
	case "", string(discovery.TriageUnmanaged):
		out.Summary.OpenFindingCount++
	case string(discovery.TriageInvestigating):
		out.Summary.InvestigatingCount++
		out.Summary.RemediationDecisionCount++
	case string(discovery.TriageManaged):
		out.Summary.RemediatedCount++
		out.Summary.RemediationDecisionCount++
	case string(discovery.TriageDismissed):
		out.Summary.DismissedCount++
		out.Summary.RemediationDecisionCount++
	}
	switch item.DriftType {
	case "deleted":
		out.Summary.DeletedCount++
	case "replaced":
		out.Summary.ReplacedCount++
	case "relocated":
		out.Summary.RelocatedCount++
	case "permission_changed":
		out.Summary.PermissionChangedCount++
	}
	switch item.CredentialClass {
	case "certificate":
		out.Summary.CertificateCount++
	case "ssh_key":
		out.Summary.SSHKeyCount++
	case "secret":
		out.Summary.SecretCount++
	}
}

func (a *API) toDriftRemediationFinding(f store.DiscoveryFinding, src store.DiscoverySource) driftRemediationFinding {
	meta := decodeDriftFindingMetadata(f.Metadata)
	status := f.TriageStatus
	if status == "" {
		status = string(discovery.TriageUnmanaged)
	}
	item := driftRemediationFinding{
		FindingID:          f.ID,
		RunID:              f.RunID,
		SourceID:           f.SourceID,
		SourceName:         src.Name,
		Ref:                f.Ref,
		Provenance:         f.Provenance,
		Fingerprint:        f.Fingerprint,
		RiskScore:          f.RiskScore,
		DriftType:          firstNonEmpty(meta.Type, "unknown"),
		CredentialClass:    firstNonEmpty(meta.Class, "credential"),
		ExpectedMode:       firstNonEmpty(meta.Mode, meta.Expected),
		ActualMode:         firstNonEmpty(meta.ActualMode, meta.Actual),
		TriageStatus:       status,
		TriageActor:        f.TriageActor,
		TriageReason:       f.TriageReason,
		TriagedAt:          f.TriagedAt,
		Metadata:           f.Metadata,
		RecommendedAction:  driftRecommendedAction(meta.Type, meta.Class),
		AvailableDecisions: driftAvailableDecisions(status),
		EvidenceRefs:       []string{"discovery.finding:" + f.ID, "discovery.run:" + f.RunID, "discovery.source:" + f.SourceID},
	}
	if f.TriagedAt != nil {
		item.EvidenceRefs = append(item.EvidenceRefs, "event:discovery.finding.triage_changed")
	}
	return item
}

func decodeDriftFindingMetadata(raw json.RawMessage) driftFindingMetadata {
	var out driftFindingMetadata
	_ = json.Unmarshal(raw, &out)
	return out
}

func driftRecommendedAction(driftType, class string) string {
	class = firstNonEmpty(class, "credential")
	switch driftType {
	case "deleted":
		return "restore or redeploy the watched " + class + ", then mark the finding managed"
	case "replaced":
		return "rotate and redeploy the expected " + class + ", or mark the new fingerprint managed with change evidence"
	case "relocated":
		return "move the " + class + " back to its watched path or update the discovery source after approval"
	case "permission_changed":
		return "restore the expected file mode before accepting the " + class + " as managed"
	default:
		return "investigate the watched " + class + " before accepting or dismissing the drift finding"
	}
}

func driftAvailableDecisions(status string) []string {
	switch discovery.TriageStatus(status) {
	case discovery.TriageUnmanaged, "":
		return []string{driftDecisionInvestigate, driftDecisionManaged, driftDecisionDismiss}
	case discovery.TriageInvestigating:
		return []string{driftDecisionManaged, driftDecisionDismiss}
	default:
		return []string{}
	}
}
