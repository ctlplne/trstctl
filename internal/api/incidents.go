package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type incidentExecutionRequest struct {
	IdentityID       string `json:"identity_id"`
	Reason           string `json:"reason"`
	ReplacementName  string `json:"replacement_name"`
	Connector        string `json:"connector"`
	Target           string `json:"target"`
	DeliveryRollback string `json:"delivery_rollback_ref"`
}

type incidentExecutionResponse struct {
	ID                    string                     `json:"id"`
	TenantID              string                     `json:"tenant_id"`
	CompromisedIdentityID string                     `json:"compromised_identity_id"`
	ReplacementIdentityID *string                    `json:"replacement_identity_id,omitempty"`
	ConnectorDeliveryID   *string                    `json:"connector_delivery_id,omitempty"`
	Status                string                     `json:"status"`
	Phase                 string                     `json:"phase"`
	Reason                string                     `json:"reason"`
	BlastRadius           json.RawMessage            `json:"blast_radius"`
	RevocationStatus      string                     `json:"revocation_status"`
	EvidenceBundleFormat  string                     `json:"evidence_bundle_format"`
	EvidenceBundle        string                     `json:"evidence_bundle"`
	FailedTargets         []string                   `json:"failed_targets"`
	RollbackRefs          []string                   `json:"rollback_refs"`
	IdempotencyKey        string                     `json:"idempotency_key"`
	CreatedBy             string                     `json:"created_by"`
	CreatedAt             time.Time                  `json:"created_at"`
	UpdatedAt             time.Time                  `json:"updated_at"`
	ReplacementIdentity   *identityResponse          `json:"replacement_identity,omitempty"`
	ConnectorDelivery     *connectorDeliveryResponse `json:"connector_delivery,omitempty"`
}

func toIncidentExecutionResponse(r store.IncidentExecution) incidentExecutionResponse {
	blast := r.BlastRadius
	if len(blast) == 0 {
		blast = json.RawMessage("{}")
	}
	if r.FailedTargets == nil {
		r.FailedTargets = []string{}
	}
	if r.RollbackRefs == nil {
		r.RollbackRefs = []string{}
	}
	return incidentExecutionResponse{
		ID: r.ID, TenantID: r.TenantID, CompromisedIdentityID: r.CompromisedIdentityID,
		ReplacementIdentityID: r.ReplacementIdentityID, ConnectorDeliveryID: r.ConnectorDeliveryID,
		Status: r.Status, Phase: r.Phase, Reason: r.Reason, BlastRadius: blast,
		RevocationStatus: r.RevocationStatus, EvidenceBundleFormat: r.EvidenceBundleFormat,
		EvidenceBundle: r.EvidenceBundle, FailedTargets: r.FailedTargets, RollbackRefs: r.RollbackRefs,
		IdempotencyKey: r.IdempotencyKey, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

//trstctl:mutation
func (a *API) executeIncident(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req incidentExecutionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.IdentityID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "identity_id is required")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if !principal.Can(authz.CertsIssue, authz.Scope{TenantID: tenantID}) {
			return 0, nil, errStatus(http.StatusForbidden, "forbidden: incident execution that issues replacements requires "+string(authz.CertsIssue))
		}

		compromised, err := a.store.GetIdentity(ctx, tenantID, req.IdentityID)
		if err != nil {
			return 0, nil, err
		}
		if !incidentRevocable(orchestrator.State(compromised.Status)) {
			return 0, nil, errStatus(http.StatusConflict, "incident execution requires an issued, deployed, or renewing compromised identity")
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "served incident execution"
		}

		impact, err := a.incidentBlastRadius(ctx, tenantID, compromised.ID)
		if err != nil {
			return 0, nil, err
		}
		impactJSON, err := json.Marshal(impact)
		if err != nil {
			return 0, nil, err
		}

		replacementName := strings.TrimSpace(req.ReplacementName)
		if replacementName == "" {
			replacementName = compromised.Name + "-replacement"
		}
		replacement, err := a.orch.CreateIdentity(ctx, tenantID, store.Identity{
			Kind: compromised.Kind, Name: replacementName, OwnerID: compromised.OwnerID,
			IssuerID: compromised.IssuerID, Attributes: incidentReplacementAttributes(compromised.ID, compromised.Attributes),
		})
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.Transition(ctx, tenantID, replacement.ID, orchestrator.StateIssued, "incident replacement issued before revocation: "+reason); err != nil {
			return 0, nil, err
		}
		if err := a.orch.Transition(ctx, tenantID, replacement.ID, orchestrator.StateDeployed, "incident replacement deployed before revocation: "+reason); err != nil {
			return 0, nil, err
		}
		if err := a.orch.Transition(ctx, tenantID, compromised.ID, orchestrator.StateRevoked, "incident compromised identity revoked after replacement: "+reason); err != nil {
			return 0, nil, err
		}

		delivery, err := a.recordIncidentDelivery(ctx, tenantID, replacement.ID, req, reason, idempotencyKey)
		if err != nil {
			return 0, nil, err
		}
		deliveryID := delivery.ID
		failedTargets := incidentFailedTargets(delivery)
		rollbackRefs := incidentRollbackRefs(compromised.ID, replacement.ID, delivery.RollbackRef)
		evidenceFormat, evidenceBundle, err := a.incidentEvidenceBundle(ctx, tenantID, compromised.ID)
		if err != nil {
			return 0, nil, err
		}

		exec, err := a.orch.RecordIncidentExecution(ctx, tenantID, store.IncidentExecution{
			ID: guuid.NewString(), CompromisedIdentityID: compromised.ID,
			ReplacementIdentityID: &replacement.ID, ConnectorDeliveryID: &deliveryID,
			Status: "executed", Phase: "replacement_deployed_and_compromised_revoked",
			Reason: reason, BlastRadius: impactJSON, RevocationStatus: "revocation_publish_queued",
			EvidenceBundleFormat: evidenceFormat, EvidenceBundle: evidenceBundle,
			FailedTargets: failedTargets, RollbackRefs: rollbackRefs,
			IdempotencyKey: idempotencyKey, CreatedBy: principal.Subject,
		})
		if err != nil {
			return 0, nil, err
		}

		resp := toIncidentExecutionResponse(exec)
		reloadedReplacement, err := a.store.GetIdentity(ctx, tenantID, replacement.ID)
		if err == nil {
			ri := toIdentityResponse(reloadedReplacement)
			resp.ReplacementIdentity = &ri
		}
		dr := toConnectorDeliveryResponse(delivery)
		resp.ConnectorDelivery = &dr
		return http.StatusCreated, resp, nil
	})
}

func (a *API) listIncidentExecutions(w http.ResponseWriter, r *http.Request) {
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
	identityID := r.URL.Query().Get("identity_id")
	rows, err := a.store.ListIncidentExecutionsPage(r.Context(), tenantID, identityID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]incidentExecutionResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toIncidentExecutionResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getIncidentExecution(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	row, err := a.store.GetIncidentExecution(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	resp := toIncidentExecutionResponse(row)
	if row.ConnectorDeliveryID != nil {
		if delivery, err := a.store.GetConnectorDeliveryReceipt(r.Context(), tenantID, *row.ConnectorDeliveryID); err == nil {
			dr := toConnectorDeliveryResponse(delivery)
			resp.ConnectorDelivery = &dr
		}
	}
	if row.ReplacementIdentityID != nil {
		if ident, err := a.store.GetIdentity(r.Context(), tenantID, *row.ReplacementIdentityID); err == nil {
			ri := toIdentityResponse(ident)
			resp.ReplacementIdentity = &ri
		}
	}
	a.writeJSON(w, http.StatusOK, resp)
}

func (a *API) incidentBlastRadius(ctx context.Context, tenantID, identityID string) (graph.Impact, error) {
	g, err := graph.Build(ctx, a.store, tenantID)
	if err != nil {
		return graph.Impact{}, err
	}
	nodeID := "id:" + identityID
	if _, ok := g.Node(nodeID); !ok {
		return graph.Impact{}, errStatus(http.StatusNotFound, "graph node not found for compromised identity")
	}
	return g.BlastRadius(nodeID), nil
}

func (a *API) recordIncidentDelivery(ctx context.Context, tenantID, replacementIdentityID string, req incidentExecutionRequest, reason, idempotencyKey string) (store.ConnectorDeliveryReceipt, error) {
	connector := strings.TrimSpace(req.Connector)
	if connector == "" {
		connector = "incident-remediation"
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = "unconfigured-target"
	}
	rollback := strings.TrimSpace(req.DeliveryRollback)
	if rollback == "" {
		rollback = "restore previous credential binding if replacement health checks fail"
	}
	identityID := replacementIdentityID
	return a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
		ID: guuid.NewString(), IdentityID: &identityID, Destination: "connector.deploy",
		Connector: connector, Target: target, Status: "unrouted", Attempts: 1,
		Reason:      "incident replacement deployment requires connector worker confirmation",
		Detail:      "served incident execution queued replacement deploy before compromised identity revocation: " + reason,
		RollbackRef: rollback, IdempotencyKey: idempotencyKey,
	})
}

func (a *API) incidentEvidenceBundle(ctx context.Context, tenantID, identityID string) (format string, bundle string, err error) {
	if a.audit == nil {
		return "unavailable", "audit export service is not configured", nil
	}
	b, err := a.audit.Export(ctx, audit.Query{TenantID: tenantID, Contains: identityID, Limit: 100})
	if err != nil {
		return "", "", err
	}
	return "jws", b, nil
}

func incidentRevocable(s orchestrator.State) bool {
	return s == orchestrator.StateIssued || s == orchestrator.StateDeployed || s == orchestrator.StateRenewing
}

func incidentReplacementAttributes(replaces string, existing json.RawMessage) json.RawMessage {
	out := map[string]any{"incident_replaces_identity_id": replaces}
	if len(existing) > 0 {
		var base map[string]any
		if err := json.Unmarshal(existing, &base); err == nil {
			for k, v := range base {
				out[k] = v
			}
			out["incident_replaces_identity_id"] = replaces
		}
	}
	b, _ := json.Marshal(out)
	return b
}

func incidentFailedTargets(delivery store.ConnectorDeliveryReceipt) []string {
	if delivery.Status == "delivered" {
		return []string{}
	}
	target := delivery.Target
	if target == "" {
		target = "unconfigured-target"
	}
	return []string{fmt.Sprintf("%s:%s:%s", delivery.Connector, target, delivery.Status)}
}

func incidentRollbackRefs(compromisedID, replacementID, deliveryRollback string) []string {
	refs := []string{"identity:" + compromisedID, "replacement:" + replacementID}
	if strings.TrimSpace(deliveryRollback) != "" {
		refs = append(refs, deliveryRollback)
	}
	return refs
}
