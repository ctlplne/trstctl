// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

const (
	remediationPlaybookRevokeIdentity = "identity-revoke"
	remediationPlaybookRotateIdentity = "credential-rotate"
	remediationPlaybookRightSizeNHI   = "nhi-right-size"
)

type remediationPlaybookCatalogResponse struct {
	Capability  string                `json:"capability"`
	Status      string                `json:"status"`
	GeneratedAt time.Time             `json:"generated_at"`
	Items       []remediationPlaybook `json:"items"`
}

type remediationPlaybook struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Action          string   `json:"action"`
	Status          string   `json:"status"`
	Capability      string   `json:"capability"`
	Summary         string   `json:"summary"`
	ExternalEffect  string   `json:"external_effect"`
	RequiredInputs  []string `json:"required_inputs"`
	EvidenceSources []string `json:"evidence_sources"`
}

type remediationPlaybookRunRequest struct {
	TargetIdentityID  string   `json:"target_identity_id"`
	InventoryID       string   `json:"inventory_id"`
	Reason            string   `json:"reason"`
	Connector         string   `json:"connector"`
	Target            string   `json:"target"`
	ReplacementName   string   `json:"replacement_name"`
	RemoveScopes      []string `json:"remove_scopes"`
	RecommendedScopes []string `json:"recommended_scopes"`
	RollbackRef       string   `json:"rollback_ref"`
}

type remediationPlaybookRunResponse struct {
	ID                  string                     `json:"id"`
	TenantID            string                     `json:"tenant_id"`
	PlaybookID          string                     `json:"playbook_id"`
	TargetIdentityID    string                     `json:"target_identity_id"`
	InventoryID         string                     `json:"inventory_id"`
	Status              string                     `json:"status"`
	Phase               string                     `json:"phase"`
	Action              string                     `json:"action"`
	Reason              string                     `json:"reason"`
	Connector           string                     `json:"connector"`
	Target              string                     `json:"target"`
	OutboxID            *int64                     `json:"outbox_id,omitempty"`
	ConnectorDeliveryID *string                    `json:"connector_delivery_id,omitempty"`
	ScopeDelta          json.RawMessage            `json:"scope_delta"`
	EvidenceRefs        []string                   `json:"evidence_refs"`
	RollbackRefs        []string                   `json:"rollback_refs"`
	IdempotencyKey      string                     `json:"idempotency_key"`
	CreatedBy           string                     `json:"created_by"`
	CreatedAt           time.Time                  `json:"created_at"`
	UpdatedAt           time.Time                  `json:"updated_at"`
	ConnectorDelivery   *connectorDeliveryResponse `json:"connector_delivery,omitempty"`
}

func remediationPlaybookCatalog() remediationPlaybookCatalogResponse {
	return remediationPlaybookCatalogResponse{
		Capability:  "CAP-REM-01",
		Status:      "served",
		GeneratedAt: time.Now().UTC(),
		Items: []remediationPlaybook{
			{
				ID: remediationPlaybookRevokeIdentity, Name: "Revoke identity",
				Action: "revoke", Status: "served", Capability: "CAP-REM-01",
				Summary:        "Revokes an issued, deployed, or renewing identity through the lifecycle state machine.",
				ExternalEffect: "revocation.publish outbox",
				RequiredInputs: []string{"target_identity_id"},
				EvidenceSources: []string{
					"identity lifecycle transition",
					"remediation.playbook_run.recorded event",
				},
			},
			{
				ID: remediationPlaybookRotateIdentity, Name: "Rotate credential",
				Action: "rotate", Status: "served", Capability: "CAP-REM-01",
				Summary:        "Issues and deploys a replacement before revoking the compromised identity.",
				ExternalEffect: "ca.issue, connector.deploy, revocation.publish outbox",
				RequiredInputs: []string{"target_identity_id"},
				EvidenceSources: []string{
					"replacement identity lifecycle transitions",
					"connector delivery receipt",
					"remediation.playbook_run.recorded event",
				},
			},
			{
				ID: remediationPlaybookRightSizeNHI, Name: "Right-size NHI grants",
				Action: "right_size", Status: "served", Capability: "CAP-REM-01",
				Summary:        "Queues a least-privilege connector intent from usage-backed NHI over-privilege evidence.",
				ExternalEffect: orchestrator.DestinationConnectorRightSize + " outbox",
				RequiredInputs: []string{"inventory_id or target_identity_id"},
				EvidenceSources: []string{
					"GET /api/v1/nhi/posture/overprivilege",
					"connector delivery receipt",
					"remediation.playbook_run.recorded event",
				},
			},
		},
	}
}

func (a *API) listRemediationPlaybooks(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, http.StatusOK, remediationPlaybookCatalog())
}

//trstctl:mutation
func (a *API) runRemediationPlaybook(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	playbookID := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req remediationPlaybookRunRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		switch playbookID {
		case remediationPlaybookRevokeIdentity:
			run, err := a.runRevokePlaybook(ctx, tenantID, principal, req, idempotencyKey)
			if err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, a.remediationPlaybookRunResponse(ctx, tenantID, run), nil
		case remediationPlaybookRotateIdentity:
			if !principal.Can(authz.CertsIssue, authz.Scope{TenantID: tenantID}) {
				return 0, nil, errStatus(http.StatusForbidden, "forbidden: rotate playbook requires "+string(authz.CertsIssue))
			}
			run, err := a.runRotatePlaybook(ctx, tenantID, principal, req, idempotencyKey)
			if err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, a.remediationPlaybookRunResponse(ctx, tenantID, run), nil
		case remediationPlaybookRightSizeNHI:
			run, err := a.runRightSizePlaybook(ctx, tenantID, principal, req, idempotencyKey)
			if err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, a.remediationPlaybookRunResponse(ctx, tenantID, run), nil
		default:
			return 0, nil, errStatus(http.StatusNotFound, "unknown remediation playbook")
		}
	})
}

func (a *API) listRemediationPlaybookRuns(w http.ResponseWriter, r *http.Request) {
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
	playbookID := strings.TrimSpace(r.URL.Query().Get("playbook_id"))
	rows, err := a.store.ListRemediationPlaybookRunsPage(r.Context(), tenantID, playbookID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]remediationPlaybookRunResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, a.remediationPlaybookRunResponse(r.Context(), tenantID, row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getRemediationPlaybookRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	row, err := a.store.GetRemediationPlaybookRun(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, a.remediationPlaybookRunResponse(r.Context(), tenantID, row))
}

func (a *API) runRevokePlaybook(ctx context.Context, tenantID string, principal authz.Principal, req remediationPlaybookRunRequest, idempotencyKey string) (store.RemediationPlaybookRun, error) {
	identityID := strings.TrimSpace(req.TargetIdentityID)
	if identityID == "" {
		return store.RemediationPlaybookRun{}, errStatus(http.StatusBadRequest, "target_identity_id is required")
	}
	identity, err := a.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if !incidentRevocable(orchestrator.State(identity.Status)) {
		return store.RemediationPlaybookRun{}, errStatus(http.StatusConflict, "revoke playbook requires an issued, deployed, or renewing identity")
	}
	reason := remediationReason(req.Reason, "revoke playbook")
	if err := a.orch.Transition(ctx, tenantID, identityID, orchestrator.StateRevoked, "remediation playbook revoke: "+reason); err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	return a.orch.RecordRemediationPlaybookRun(ctx, tenantID, store.RemediationPlaybookRun{
		ID: guuid.NewString(), PlaybookID: remediationPlaybookRevokeIdentity, TargetIdentityID: identityID,
		InventoryID: "identity/" + identityID, Status: "executed", Phase: "identity_revoked",
		Action: "revoke", Reason: reason, ScopeDelta: json.RawMessage(`{}`),
		EvidenceRefs:   []string{"identity:" + identityID, "state:" + string(orchestrator.StateRevoked)},
		RollbackRefs:   remediationRollbackRefs(req.RollbackRef, "restore prior credential binding after revocation rollback approval"),
		IdempotencyKey: idempotencyKey, CreatedBy: principal.Subject,
	}, "")
}

func (a *API) runRotatePlaybook(ctx context.Context, tenantID string, principal authz.Principal, req remediationPlaybookRunRequest, idempotencyKey string) (store.RemediationPlaybookRun, error) {
	identityID := strings.TrimSpace(req.TargetIdentityID)
	if identityID == "" {
		return store.RemediationPlaybookRun{}, errStatus(http.StatusBadRequest, "target_identity_id is required")
	}
	compromised, err := a.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if !incidentRevocable(orchestrator.State(compromised.Status)) {
		return store.RemediationPlaybookRun{}, errStatus(http.StatusConflict, "rotate playbook requires an issued, deployed, or renewing identity")
	}
	reason := remediationReason(req.Reason, "rotate playbook")
	replacementName := strings.TrimSpace(req.ReplacementName)
	if replacementName == "" {
		replacementName = compromised.Name + "-replacement"
	}
	replacement, err := a.orch.CreateIdentity(ctx, tenantID, store.Identity{
		Kind: compromised.Kind, Name: replacementName, OwnerID: compromised.OwnerID,
		IssuerID: compromised.IssuerID, Attributes: incidentReplacementAttributes(compromised.ID, compromised.Attributes),
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if err := a.orch.Transition(ctx, tenantID, replacement.ID, orchestrator.StateIssued, "remediation playbook replacement issued: "+reason); err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if err := a.orch.Transition(ctx, tenantID, replacement.ID, orchestrator.StateDeployed, "remediation playbook replacement deployed: "+reason); err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if err := a.orch.Transition(ctx, tenantID, compromised.ID, orchestrator.StateRevoked, "remediation playbook compromised identity revoked: "+reason); err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	deliveryReq := incidentExecutionRequest{
		Connector: strings.TrimSpace(req.Connector), Target: strings.TrimSpace(req.Target),
		DeliveryRollback: strings.TrimSpace(req.RollbackRef),
	}
	delivery, err := a.recordIncidentDelivery(ctx, tenantID, replacement.ID, deliveryReq, reason, idempotencyKey)
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	deliveryID := delivery.ID
	scopeDelta, err := json.Marshal(map[string]any{
		"replaced_identity_id":    compromised.ID,
		"replacement_identity_id": replacement.ID,
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	return a.orch.RecordRemediationPlaybookRun(ctx, tenantID, store.RemediationPlaybookRun{
		ID: guuid.NewString(), PlaybookID: remediationPlaybookRotateIdentity, TargetIdentityID: compromised.ID,
		InventoryID: "identity/" + compromised.ID, Status: "executed", Phase: "replacement_deployed_and_original_revoked",
		Action: "rotate", Reason: reason, Connector: delivery.Connector, Target: delivery.Target,
		ConnectorDeliveryID: &deliveryID, ScopeDelta: scopeDelta,
		EvidenceRefs:   []string{"identity:" + compromised.ID, "replacement:" + replacement.ID, "connector_delivery:" + delivery.ID},
		RollbackRefs:   incidentRollbackRefs(compromised.ID, replacement.ID, delivery.RollbackRef),
		IdempotencyKey: idempotencyKey, CreatedBy: principal.Subject,
	}, "")
}

func (a *API) runRightSizePlaybook(ctx context.Context, tenantID string, principal authz.Principal, req remediationPlaybookRunRequest, idempotencyKey string) (store.RemediationPlaybookRun, error) {
	finding, err := a.rightSizeFinding(ctx, tenantID, req)
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	if len(req.RemoveScopes) > 0 && !scopeSelectionAllowed(req.RemoveScopes, finding.UnusedScopes) {
		return store.RemediationPlaybookRun{}, errStatus(http.StatusBadRequest, "remove_scopes must be a subset of the usage-backed unused scopes")
	}
	if len(req.RecommendedScopes) > 0 && !scopeSelectionAllowed(req.RecommendedScopes, finding.RecommendedScopes) {
		return store.RemediationPlaybookRun{}, errStatus(http.StatusBadRequest, "recommended_scopes must be a subset of the usage-backed recommended scopes")
	}
	remove := normalizedScopeSelection(req.RemoveScopes, finding.UnusedScopes)
	recommended := normalizedScopeSelection(req.RecommendedScopes, finding.RecommendedScopes)
	reason := remediationReason(req.Reason, "right-size NHI grants")
	connector := strings.TrimSpace(req.Connector)
	if connector == "" {
		connector = "least-privilege"
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = firstNonEmpty(finding.Ref, finding.InventoryID)
	}
	identityID := ""
	if strings.HasPrefix(finding.InventoryID, "identity/") {
		identityID = strings.TrimPrefix(finding.InventoryID, "identity/")
	}
	var identityIDPtr *string
	if identityID != "" {
		identityIDPtr = &identityID
	}
	scopeDelta, err := json.Marshal(map[string]any{
		"inventory_id":       finding.InventoryID,
		"ref":                finding.Ref,
		"kind":               finding.Kind,
		"source":             finding.Source,
		"granted_scopes":     finding.GrantedScopes,
		"used_scopes":        finding.UsedScopes,
		"remove_scopes":      remove,
		"recommended_scopes": recommended,
		"unused_ratio":       finding.UnusedRatio,
		"risk_score":         finding.RiskScore,
		"posture_capability": "CAP-POST-01",
		"remediation_action": "right_size",
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	delivery, err := a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
		ID: guuid.NewString(), IdentityID: identityIDPtr, Destination: orchestrator.DestinationConnectorRightSize,
		Connector: connector, Target: target, Status: "queued", Attempts: 1,
		Reason:         "least_privilege_right_size_queued",
		Detail:         "usage-backed right-size playbook queued removal of unused grants: " + strings.Join(remove, ","),
		RollbackRef:    firstNonEmpty(strings.TrimSpace(req.RollbackRef), "restore prior grants "+strings.Join(remove, ",")),
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return store.RemediationPlaybookRun{}, err
	}
	deliveryID := delivery.ID
	return a.orch.RecordRemediationPlaybookRun(ctx, tenantID, store.RemediationPlaybookRun{
		ID: guuid.NewString(), PlaybookID: remediationPlaybookRightSizeNHI, TargetIdentityID: identityID,
		InventoryID: finding.InventoryID, Status: "queued", Phase: "right_size_connector_intent_queued",
		Action: "right_size", Reason: reason, Connector: connector, Target: target,
		ConnectorDeliveryID: &deliveryID, ScopeDelta: scopeDelta,
		EvidenceRefs:   append([]string{"nhi_posture:CAP-POST-01", "connector_delivery:" + delivery.ID}, finding.EvidenceRefs...),
		RollbackRefs:   remediationRollbackRefs(req.RollbackRef, "restore prior grants "+strings.Join(remove, ",")),
		IdempotencyKey: idempotencyKey, CreatedBy: principal.Subject,
	}, orchestrator.DestinationConnectorRightSize)
}

func (a *API) rightSizeFinding(ctx context.Context, tenantID string, req remediationPlaybookRunRequest) (nhiOverPrivilegeFinding, error) {
	inventoryID := strings.TrimSpace(req.InventoryID)
	identityID := strings.TrimSpace(req.TargetIdentityID)
	if inventoryID == "" && identityID != "" {
		inventoryID = "identity/" + identityID
	}
	if inventoryID == "" {
		return nhiOverPrivilegeFinding{}, errStatus(http.StatusBadRequest, "inventory_id or target_identity_id is required")
	}
	posture, err := a.nhiOverPrivilegePosture(ctx, tenantID)
	if err != nil {
		return nhiOverPrivilegeFinding{}, err
	}
	for _, finding := range posture.Findings {
		if finding.InventoryID == inventoryID || (finding.Ref != "" && finding.Ref == identityID) {
			return finding, nil
		}
	}
	return nhiOverPrivilegeFinding{}, errStatus(http.StatusConflict, "right-size playbook requires usage-backed over-privilege posture evidence")
}

func (a *API) remediationPlaybookRunResponse(ctx context.Context, tenantID string, r store.RemediationPlaybookRun) remediationPlaybookRunResponse {
	delta := r.ScopeDelta
	if len(delta) == 0 {
		delta = json.RawMessage("{}")
	}
	if r.EvidenceRefs == nil {
		r.EvidenceRefs = []string{}
	}
	if r.RollbackRefs == nil {
		r.RollbackRefs = []string{}
	}
	resp := remediationPlaybookRunResponse{
		ID: r.ID, TenantID: r.TenantID, PlaybookID: r.PlaybookID,
		TargetIdentityID: r.TargetIdentityID, InventoryID: r.InventoryID,
		Status: r.Status, Phase: r.Phase, Action: r.Action, Reason: r.Reason,
		Connector: r.Connector, Target: r.Target, OutboxID: r.OutboxID,
		ConnectorDeliveryID: r.ConnectorDeliveryID, ScopeDelta: delta,
		EvidenceRefs: r.EvidenceRefs, RollbackRefs: r.RollbackRefs,
		IdempotencyKey: r.IdempotencyKey, CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	if r.ConnectorDeliveryID != nil {
		if delivery, err := a.store.GetConnectorDeliveryReceipt(ctx, tenantID, *r.ConnectorDeliveryID); err == nil {
			dr := toConnectorDeliveryResponse(delivery)
			resp.ConnectorDelivery = &dr
		}
	}
	return resp
}

func remediationReason(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func remediationRollbackRefs(value, fallback string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	return []string{value}
}

func normalizedScopeSelection(selected, fallback []string) []string {
	source := selected
	if len(source) == 0 {
		source = fallback
	}
	out := make([]string, 0, len(source))
	seen := map[string]bool{}
	for _, item := range source {
		trimmed := strings.TrimSpace(item)
		key := normalizeNHIPostureString(trimmed)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, trimmed)
	}
	return out
}

func scopeSelectionAllowed(selected, allowed []string) bool {
	allowedSet := map[string]bool{}
	for _, item := range allowed {
		key := normalizeNHIPostureString(item)
		if key != "" {
			allowedSet[key] = true
		}
	}
	for _, item := range selected {
		key := normalizeNHIPostureString(item)
		if key == "" {
			continue
		}
		if !allowedSet[key] {
			return false
		}
	}
	return true
}
