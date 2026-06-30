package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

const ownerRemediationCapability = "CAP-REM-02"

type ownerRemediationQueueResponse struct {
	Capability  string                   `json:"capability"`
	Status      string                   `json:"status"`
	GeneratedAt time.Time                `json:"generated_at"`
	Summary     ownerRemediationSummary  `json:"summary"`
	Items       []ownerRemediationAction `json:"items"`
	Evidence    []string                 `json:"evidence_refs"`
}

type ownerRemediationSummary struct {
	Total    int `json:"total"`
	Open     int `json:"open"`
	Accepted int `json:"accepted"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type ownerRemediationAction struct {
	ID                  string   `json:"id"`
	OwnerID             string   `json:"owner_id"`
	OwnerName           string   `json:"owner_name"`
	OwnerEmail          string   `json:"owner_email,omitempty"`
	InventoryID         string   `json:"inventory_id"`
	TargetIdentityID    string   `json:"target_identity_id,omitempty"`
	DisplayName         string   `json:"display_name"`
	Kind                string   `json:"kind"`
	Source              string   `json:"source"`
	PlaybookID          string   `json:"playbook_id"`
	Action              string   `json:"action"`
	Status              string   `json:"status"`
	Severity            string   `json:"severity"`
	RiskScore           int      `json:"risk_score"`
	Connector           string   `json:"connector"`
	Target              string   `json:"target"`
	Reason              string   `json:"reason"`
	Recommendation      string   `json:"recommendation"`
	RemoveScopes        []string `json:"remove_scopes"`
	RecommendedScopes   []string `json:"recommended_scopes"`
	EvidenceRefs        []string `json:"evidence_refs"`
	RollbackRef         string   `json:"rollback_ref"`
	RemediationRunID    string   `json:"remediation_run_id,omitempty"`
	ConnectorDeliveryID string   `json:"connector_delivery_id,omitempty"`
}

type ownerRemediationAcceptRequest struct {
	Reason            string   `json:"reason"`
	Connector         string   `json:"connector"`
	Target            string   `json:"target"`
	RemoveScopes      []string `json:"remove_scopes"`
	RecommendedScopes []string `json:"recommended_scopes"`
	RollbackRef       string   `json:"rollback_ref"`
}

type ownerRemediationRunResponse struct {
	Capability     string                         `json:"capability"`
	Status         string                         `json:"status"`
	Action         ownerRemediationAction         `json:"action"`
	RemediationRun remediationPlaybookRunResponse `json:"remediation_run"`
}

func (a *API) listOwnerRemediationActions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	ownerIDFilter := strings.TrimSpace(r.URL.Query().Get("owner_id"))
	actions, err := a.ownerRemediationActions(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	visible := make([]ownerRemediationAction, 0, len(actions))
	for _, action := range actions {
		if ownerIDFilter != "" && action.OwnerID != ownerIDFilter {
			continue
		}
		owner, err := a.store.GetOwner(r.Context(), tenantID, action.OwnerID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		if !ownerRemediationAuthorized(principal, tenantID, owner, false) {
			if ownerIDFilter != "" {
				a.writeError(w, errStatus(http.StatusForbidden, "owner remediation actions are visible only to the bound owner or incident operators"))
				return
			}
			continue
		}
		visible = append(visible, action)
	}
	a.writeJSON(w, http.StatusOK, ownerRemediationQueueResponse{
		Capability:  ownerRemediationCapability,
		Status:      "served",
		GeneratedAt: time.Now().UTC(),
		Summary:     ownerRemediationSummaryFor(visible),
		Items:       visible,
		Evidence: []string{
			"GET /api/v1/nhi/posture/overprivilege",
			"remediation.playbook_run.recorded",
			orchestrator.DestinationConnectorRightSize + " outbox",
		},
	})
}

//trstctl:mutation
func (a *API) acceptOwnerRemediationAction(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	actionID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req ownerRemediationAcceptRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		action, owner, err := a.ownerRemediationActionByID(ctx, tenantID, actionID)
		if err != nil {
			return 0, nil, err
		}
		if !ownerRemediationAuthorized(principal, tenantID, owner, true) {
			return 0, nil, errStatus(http.StatusForbidden, "owner remediation action can be accepted only by the bound owner or incident operators")
		}
		runReq := remediationPlaybookRunRequest{
			TargetIdentityID:  action.TargetIdentityID,
			InventoryID:       action.InventoryID,
			Reason:            firstNonEmpty(strings.TrimSpace(req.Reason), action.Reason),
			Connector:         firstNonEmpty(strings.TrimSpace(req.Connector), action.Connector),
			Target:            firstNonEmpty(strings.TrimSpace(req.Target), action.Target),
			RemoveScopes:      normalizedScopeSelection(req.RemoveScopes, action.RemoveScopes),
			RecommendedScopes: normalizedScopeSelection(req.RecommendedScopes, action.RecommendedScopes),
			RollbackRef:       firstNonEmpty(strings.TrimSpace(req.RollbackRef), action.RollbackRef),
		}
		run, err := a.runRightSizePlaybook(ctx, tenantID, principal, runReq, idempotencyKey)
		if err != nil {
			return 0, nil, err
		}
		action.Status = "accepted"
		action.RemediationRunID = run.ID
		if run.ConnectorDeliveryID != nil {
			action.ConnectorDeliveryID = *run.ConnectorDeliveryID
		}
		return http.StatusCreated, ownerRemediationRunResponse{
			Capability:     ownerRemediationCapability,
			Status:         "accepted",
			Action:         action,
			RemediationRun: a.remediationPlaybookRunResponse(ctx, tenantID, run),
		}, nil
	})
}

func (a *API) ownerRemediationActionByID(ctx context.Context, tenantID, id string) (ownerRemediationAction, store.Owner, error) {
	actions, err := a.ownerRemediationActions(ctx, tenantID)
	if err != nil {
		return ownerRemediationAction{}, store.Owner{}, err
	}
	for _, action := range actions {
		if action.ID != id {
			continue
		}
		owner, err := a.store.GetOwner(ctx, tenantID, action.OwnerID)
		if err != nil {
			return ownerRemediationAction{}, store.Owner{}, err
		}
		return action, owner, nil
	}
	return ownerRemediationAction{}, store.Owner{}, errStatus(http.StatusNotFound, "owner remediation action not found")
}

func (a *API) ownerRemediationActions(ctx context.Context, tenantID string) ([]ownerRemediationAction, error) {
	posture, err := a.nhiOverPrivilegePosture(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	owners, err := a.store.ListOwners(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	ownerByID := make(map[string]store.Owner, len(owners))
	for _, owner := range owners {
		ownerByID[owner.ID] = owner
	}
	accepted, err := a.acceptedOwnerRemediationRuns(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	actions := make([]ownerRemediationAction, 0, len(posture.Findings))
	for _, finding := range posture.Findings {
		owner, ok := ownerByID[finding.OwnerID]
		if !ok || owner.ID == "" {
			continue
		}
		action := ownerRemediationActionFromFinding(finding, owner)
		if run, ok := accepted[action.InventoryID]; ok {
			action.Status = "accepted"
			action.RemediationRunID = run.ID
			if run.ConnectorDeliveryID != nil {
				action.ConnectorDeliveryID = *run.ConnectorDeliveryID
			}
		}
		actions = append(actions, action)
	}
	return actions, nil
}

func (a *API) acceptedOwnerRemediationRuns(ctx context.Context, tenantID string) (map[string]store.RemediationPlaybookRun, error) {
	runs, err := a.store.ListRemediationPlaybookRunsPage(ctx, tenantID, remediationPlaybookRightSizeNHI, store.ZeroUUID, 200)
	if err != nil {
		return nil, err
	}
	out := make(map[string]store.RemediationPlaybookRun, len(runs))
	for _, run := range runs {
		if run.InventoryID != "" {
			out[run.InventoryID] = run
		}
	}
	return out, nil
}

func ownerRemediationActionFromFinding(finding nhiOverPrivilegeFinding, owner store.Owner) ownerRemediationAction {
	identityID := ""
	if strings.HasPrefix(finding.InventoryID, "identity/") {
		identityID = strings.TrimPrefix(finding.InventoryID, "identity/")
	}
	target := firstNonEmpty(finding.Ref, finding.InventoryID)
	return ownerRemediationAction{
		ID:                ownerRemediationActionID(finding),
		OwnerID:           owner.ID,
		OwnerName:         owner.Name,
		OwnerEmail:        owner.Email,
		InventoryID:       finding.InventoryID,
		TargetIdentityID:  identityID,
		DisplayName:       finding.DisplayName,
		Kind:              finding.Kind,
		Source:            finding.Source,
		PlaybookID:        remediationPlaybookRightSizeNHI,
		Action:            "right_size",
		Status:            "open",
		Severity:          finding.Severity,
		RiskScore:         finding.RiskScore,
		Connector:         "least-privilege",
		Target:            target,
		Reason:            "owner accepted least-privilege right-size remediation",
		Recommendation:    finding.Recommendation,
		RemoveScopes:      append([]string(nil), finding.UnusedScopes...),
		RecommendedScopes: append([]string(nil), finding.RecommendedScopes...),
		EvidenceRefs:      append([]string{"nhi_posture:CAP-POST-01"}, finding.EvidenceRefs...),
		RollbackRef:       "restore prior grants " + strings.Join(finding.UnusedScopes, ","),
	}
}

func ownerRemediationActionID(finding nhiOverPrivilegeFinding) string {
	source := firstNonEmpty(finding.InventoryID, finding.Ref, finding.DisplayName)
	return "right-size-" + base64.RawURLEncoding.EncodeToString([]byte(source))
}

func ownerRemediationAuthorized(principal authz.Principal, tenantID string, owner store.Owner, accept bool) bool {
	scope := authz.Scope{TenantID: tenantID}
	if accept && principal.Can(authz.IncidentsWrite, scope) {
		return true
	}
	if !accept && principal.Can(authz.IncidentsRead, scope) {
		return true
	}
	return ownerPrincipalMatches(principal.Subject, owner)
}

func ownerPrincipalMatches(subject string, owner store.Owner) bool {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if subject == "" {
		return false
	}
	for _, candidate := range []string{owner.Email, owner.Name, owner.ID} {
		if subject == strings.ToLower(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func ownerRemediationSummaryFor(actions []ownerRemediationAction) ownerRemediationSummary {
	var summary ownerRemediationSummary
	for _, action := range actions {
		summary.Total++
		switch action.Status {
		case "accepted":
			summary.Accepted++
		default:
			summary.Open++
		}
		switch action.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		default:
			summary.Low++
		}
	}
	return summary
}
