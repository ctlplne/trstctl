// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type fleetReissuanceRequest struct {
	IssuerID     string                            `json:"issuer_id"`
	Reason       string                            `json:"reason"`
	BatchSize    int                               `json:"batch_size"`
	Connector    string                            `json:"connector"`
	Target       string                            `json:"target"`
	RollbackRef  string                            `json:"rollback_ref"`
	HealthGates  []store.FleetReissuanceHealthGate `json:"health_gates"`
	EvidenceHint string                            `json:"evidence_hint"`
}

type fleetReissuanceActionRequest struct {
	Reason      string `json:"reason"`
	RollbackRef string `json:"rollback_ref"`
}

type fleetReissuanceRunResponse struct {
	ID                     string                            `json:"id"`
	TenantID               string                            `json:"tenant_id"`
	IssuerID               string                            `json:"issuer_id"`
	Status                 string                            `json:"status"`
	Phase                  string                            `json:"phase"`
	Reason                 string                            `json:"reason"`
	BatchSize              int                               `json:"batch_size"`
	BatchCount             int                               `json:"batch_count"`
	Connector              string                            `json:"connector"`
	Target                 string                            `json:"target"`
	GraphImpact            json.RawMessage                   `json:"graph_impact"`
	AffectedIdentityIDs    []string                          `json:"affected_identity_ids"`
	ReplacementIdentityIDs []string                          `json:"replacement_identity_ids"`
	RevokedIdentityIDs     []string                          `json:"revoked_identity_ids"`
	ConnectorDeliveryIDs   []string                          `json:"connector_delivery_ids"`
	Batches                []store.FleetReissuanceBatch      `json:"batches"`
	HealthGates            []store.FleetReissuanceHealthGate `json:"health_gates"`
	FailedTargets          []string                          `json:"failed_targets"`
	RollbackRefs           []string                          `json:"rollback_refs"`
	EvidenceBundleFormat   string                            `json:"evidence_bundle_format"`
	EvidenceBundle         string                            `json:"evidence_bundle"`
	IdempotencyKey         string                            `json:"idempotency_key"`
	CreatedBy              string                            `json:"created_by"`
	CreatedAt              time.Time                         `json:"created_at"`
	UpdatedAt              time.Time                         `json:"updated_at"`
	ReplacementIdentities  []identityResponse                `json:"replacement_identities,omitempty"`
	ConnectorDeliveries    []connectorDeliveryResponse       `json:"connector_deliveries,omitempty"`
}

type fleetReissuanceEvidenceResponse struct {
	RunID                string    `json:"run_id"`
	EvidenceBundleFormat string    `json:"evidence_bundle_format"`
	EvidenceBundle       string    `json:"evidence_bundle"`
	RollbackRefs         []string  `json:"rollback_refs"`
	FailedTargets        []string  `json:"failed_targets"`
	ExportedAt           time.Time `json:"exported_at"`
}

func toFleetReissuanceRunResponse(r store.IncidentFleetReissuanceRun) fleetReissuanceRunResponse {
	graphImpact := r.GraphImpact
	if len(graphImpact) == 0 {
		graphImpact = json.RawMessage("{}")
	}
	if r.AffectedIdentityIDs == nil {
		r.AffectedIdentityIDs = []string{}
	}
	if r.ReplacementIdentityIDs == nil {
		r.ReplacementIdentityIDs = []string{}
	}
	if r.RevokedIdentityIDs == nil {
		r.RevokedIdentityIDs = []string{}
	}
	if r.ConnectorDeliveryIDs == nil {
		r.ConnectorDeliveryIDs = []string{}
	}
	if r.Batches == nil {
		r.Batches = []store.FleetReissuanceBatch{}
	}
	if r.HealthGates == nil {
		r.HealthGates = []store.FleetReissuanceHealthGate{}
	}
	if r.FailedTargets == nil {
		r.FailedTargets = []string{}
	}
	if r.RollbackRefs == nil {
		r.RollbackRefs = []string{}
	}
	return fleetReissuanceRunResponse{
		ID: r.ID, TenantID: r.TenantID, IssuerID: r.IssuerID,
		Status: r.Status, Phase: r.Phase, Reason: r.Reason, BatchSize: r.BatchSize,
		BatchCount: len(r.Batches), Connector: r.Connector, Target: r.Target,
		GraphImpact: graphImpact, AffectedIdentityIDs: r.AffectedIdentityIDs,
		ReplacementIdentityIDs: r.ReplacementIdentityIDs, RevokedIdentityIDs: r.RevokedIdentityIDs,
		ConnectorDeliveryIDs: r.ConnectorDeliveryIDs, Batches: r.Batches, HealthGates: r.HealthGates,
		FailedTargets: r.FailedTargets, RollbackRefs: r.RollbackRefs,
		EvidenceBundleFormat: r.EvidenceBundleFormat, EvidenceBundle: r.EvidenceBundle,
		IdempotencyKey: r.IdempotencyKey, CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

//trstctl:mutation
func (a *API) startFleetReissuance(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req fleetReissuanceRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.IssuerID = strings.TrimSpace(req.IssuerID)
		if req.IssuerID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "issuer_id is required")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if !principal.Can(authz.CertsIssue, authz.Scope{TenantID: tenantID}) {
			return 0, nil, errStatus(http.StatusForbidden, "forbidden: fleet reissuance that mints replacements requires "+string(authz.CertsIssue))
		}
		if _, err := a.store.GetIssuer(ctx, tenantID, req.IssuerID); err != nil {
			return 0, nil, err
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "served compromised issuer fleet reissuance"
		}
		batchSize := req.BatchSize
		if batchSize <= 0 {
			batchSize = 25
		}
		if batchSize > 100 {
			batchSize = 100
		}
		affected, err := a.store.ListRevocableIdentitiesByIssuer(ctx, tenantID, req.IssuerID)
		if err != nil {
			return 0, nil, err
		}
		if len(affected) == 0 {
			return 0, nil, errStatus(http.StatusConflict, "fleet reissuance requires at least one issued, deployed, or renewing identity for the issuer")
		}
		impact, err := a.issuerBlastRadius(ctx, tenantID, req.IssuerID)
		if err != nil {
			return 0, nil, err
		}
		impactJSON, err := json.Marshal(impact)
		if err != nil {
			return 0, nil, err
		}

		runID := guuid.NewString()
		connector := strings.TrimSpace(req.Connector)
		if connector == "" {
			connector = "incident-remediation"
		}
		target := strings.TrimSpace(req.Target)
		if target == "" {
			target = "unconfigured-target"
		}
		rollbackRef := strings.TrimSpace(req.RollbackRef)
		if rollbackRef == "" {
			rollbackRef = "restore previous credential binding if fleet health checks fail"
		}
		healthGates := normalizeFleetHealthGates(req.HealthGates)

		affectedIDs := make([]string, 0, len(affected))
		replacementIDs := make([]string, 0, len(affected))
		revokedIDs := make([]string, 0, len(affected))
		deliveryIDs := make([]string, 0, len(affected))
		failedTargets := make([]string, 0, len(affected))
		rollbackRefs := []string{"run:" + runID, "issuer:" + req.IssuerID, rollbackRef}
		for i, compromised := range affected {
			affectedIDs = append(affectedIDs, compromised.ID)
			replacement, err := a.orch.CreateIdentity(ctx, tenantID, store.Identity{
				Kind: compromised.Kind, Name: fleetReplacementName(compromised.Name, i), OwnerID: compromised.OwnerID,
				IssuerID: compromised.IssuerID, Attributes: fleetReplacementAttributes(runID, compromised.ID, compromised.Attributes),
			})
			if err != nil {
				return 0, nil, err
			}
			if err := a.orch.Transition(ctx, tenantID, replacement.ID, orchestrator.StateIssued, "fleet replacement issued before compromised issuer revocation: "+reason); err != nil {
				return 0, nil, err
			}
			if err := a.orch.Transition(ctx, tenantID, replacement.ID, orchestrator.StateDeployed, "fleet replacement deployed before compromised issuer revocation: "+reason); err != nil {
				return 0, nil, err
			}
			if err := a.orch.Transition(ctx, tenantID, compromised.ID, orchestrator.StateRevoked, "fleet compromised issuer identity revoked after replacement: "+reason); err != nil {
				return 0, nil, err
			}
			delivery, err := a.recordFleetReissuanceDelivery(ctx, tenantID, replacement.ID, connector, target, rollbackRef, reason, idempotencyKey)
			if err != nil {
				return 0, nil, err
			}
			replacementIDs = append(replacementIDs, replacement.ID)
			revokedIDs = append(revokedIDs, compromised.ID)
			deliveryIDs = append(deliveryIDs, delivery.ID)
			failedTargets = append(failedTargets, incidentFailedTargets(delivery)...)
			rollbackRefs = append(rollbackRefs, "identity:"+compromised.ID, "replacement:"+replacement.ID, "delivery:"+delivery.ID+":"+delivery.RollbackRef)
		}
		batches := buildFleetBatches(affectedIDs, replacementIDs, batchSize, healthGates)
		evidenceFormat, evidenceBundle, err := a.incidentEvidenceBundle(ctx, tenantID, req.IssuerID)
		if err != nil {
			return 0, nil, err
		}
		run, err := a.orch.RecordIncidentFleetReissuance(ctx, tenantID, store.IncidentFleetReissuanceRun{
			ID: runID, IssuerID: req.IssuerID, Status: "executed", Phase: "fleet_reissued_and_compromised_revoked",
			Reason: reason, BatchSize: batchSize, Connector: connector, Target: target, GraphImpact: impactJSON,
			AffectedIdentityIDs: affectedIDs, ReplacementIdentityIDs: replacementIDs, RevokedIdentityIDs: revokedIDs,
			ConnectorDeliveryIDs: deliveryIDs, Batches: batches, HealthGates: healthGates,
			FailedTargets: failedTargets, RollbackRefs: rollbackRefs,
			EvidenceBundleFormat: evidenceFormat, EvidenceBundle: evidenceBundle,
			IdempotencyKey: idempotencyKey, CreatedBy: principal.Subject,
		})
		if err != nil {
			return 0, nil, err
		}
		resp := toFleetReissuanceRunResponse(run)
		a.hydrateFleetReissuanceResponse(ctx, tenantID, &resp)
		return http.StatusCreated, resp, nil
	})
}

func (a *API) listFleetReissuanceRuns(w http.ResponseWriter, r *http.Request) {
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
	issuerID := r.URL.Query().Get("issuer_id")
	rows, err := a.store.ListIncidentFleetReissuanceRunsPage(r.Context(), tenantID, issuerID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]fleetReissuanceRunResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toFleetReissuanceRunResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) getFleetReissuanceRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	run, err := a.store.GetIncidentFleetReissuanceRun(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	resp := toFleetReissuanceRunResponse(run)
	a.hydrateFleetReissuanceResponse(r.Context(), tenantID, &resp)
	a.writeJSON(w, http.StatusOK, resp)
}

//trstctl:mutation
func (a *API) pauseFleetReissuance(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, a.fleetReissuanceStateMutation(r, idempotencyKey, "paused", "operator_paused"))
}

//trstctl:mutation
func (a *API) resumeFleetReissuance(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, a.fleetReissuanceStateMutation(r, idempotencyKey, "executed", "resume_recorded"))
}

//trstctl:mutation
func (a *API) rollbackFleetReissuance(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, a.fleetReissuanceStateMutation(r, idempotencyKey, "rollback_recorded", "rollback_evidence_recorded"))
}

func (a *API) fleetReissuanceStateMutation(r *http.Request, idempotencyKey, status, phase string) func(context.Context, string) (int, any, error) {
	runID := r.PathValue("id")
	return func(ctx context.Context, tenantID string) (int, any, error) {
		var req fleetReissuanceActionRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		run, err := a.store.GetIncidentFleetReissuanceRun(ctx, tenantID, runID)
		if err != nil {
			return 0, nil, err
		}
		run.Status = status
		run.Phase = phase
		if reason := strings.TrimSpace(req.Reason); reason != "" {
			run.Reason = run.Reason + "; " + phase + ": " + reason
		}
		if rollbackRef := strings.TrimSpace(req.RollbackRef); rollbackRef != "" {
			run.RollbackRefs = append(run.RollbackRefs, rollbackRef)
		}
		run.IdempotencyKey = idempotencyKey
		updated, err := a.orch.RecordIncidentFleetReissuance(ctx, tenantID, run)
		if err != nil {
			return 0, nil, err
		}
		resp := toFleetReissuanceRunResponse(updated)
		a.hydrateFleetReissuanceResponse(ctx, tenantID, &resp)
		return http.StatusOK, resp, nil
	}
}

func (a *API) exportFleetReissuanceEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	run, err := a.store.GetIncidentFleetReissuanceRun(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, fleetReissuanceEvidenceResponse{
		RunID: run.ID, EvidenceBundleFormat: run.EvidenceBundleFormat,
		EvidenceBundle: run.EvidenceBundle, RollbackRefs: run.RollbackRefs,
		FailedTargets: run.FailedTargets, ExportedAt: run.UpdatedAt,
	})
}

func (a *API) issuerBlastRadius(ctx context.Context, tenantID, issuerID string) (graph.Impact, error) {
	g, err := graph.Build(ctx, a.store, tenantID)
	if err != nil {
		return graph.Impact{}, err
	}
	nodeID := "iss:" + issuerID
	if _, ok := g.Node(nodeID); !ok {
		return graph.Impact{}, errStatus(http.StatusNotFound, "graph node not found for compromised issuer")
	}
	return g.BlastRadius(nodeID), nil
}

func (a *API) recordFleetReissuanceDelivery(ctx context.Context, tenantID, replacementIdentityID, connector, target, rollbackRef, reason, idempotencyKey string) (store.ConnectorDeliveryReceipt, error) {
	identityID := replacementIdentityID
	return a.orch.RecordConnectorDelivery(ctx, tenantID, store.ConnectorDeliveryReceipt{
		ID: guuid.NewString(), IdentityID: &identityID, Destination: "connector.deploy",
		Connector: connector, Target: target, Status: "queued", Attempts: 0,
		Reason:      "fleet replacement deployment requires connector worker confirmation",
		Detail:      "served compromised issuer fleet reissuance queued replacement deploy before revocation: " + reason,
		RollbackRef: rollbackRef, IdempotencyKey: idempotencyKey,
	})
}

func (a *API) hydrateFleetReissuanceResponse(ctx context.Context, tenantID string, resp *fleetReissuanceRunResponse) {
	for _, id := range resp.ReplacementIdentityIDs {
		if ident, err := a.store.GetIdentity(ctx, tenantID, id); err == nil {
			resp.ReplacementIdentities = append(resp.ReplacementIdentities, toIdentityResponse(ident))
		}
	}
	for _, id := range resp.ConnectorDeliveryIDs {
		if delivery, err := a.store.GetConnectorDeliveryReceipt(ctx, tenantID, id); err == nil {
			resp.ConnectorDeliveries = append(resp.ConnectorDeliveries, toConnectorDeliveryResponse(delivery))
		}
	}
}

func normalizeFleetHealthGates(in []store.FleetReissuanceHealthGate) []store.FleetReissuanceHealthGate {
	if len(in) == 0 {
		return []store.FleetReissuanceHealthGate{
			{Name: "graph enumeration", Status: "passed"},
			{Name: "replacement deployment", Status: "passed"},
			{Name: "revocation publication", Status: "passed"},
		}
	}
	out := make([]store.FleetReissuanceHealthGate, 0, len(in))
	for _, gate := range in {
		name := strings.TrimSpace(gate.Name)
		if name == "" {
			name = "operator health gate"
		}
		status := strings.TrimSpace(gate.Status)
		if status == "" {
			status = "passed"
		}
		out = append(out, store.FleetReissuanceHealthGate{Name: name, Status: status})
	}
	return out
}

func buildFleetBatches(identityIDs, replacementIDs []string, batchSize int, gates []store.FleetReissuanceHealthGate) []store.FleetReissuanceBatch {
	if batchSize <= 0 {
		batchSize = 25
	}
	var batches []store.FleetReissuanceBatch
	for start, index := 0, 1; start < len(identityIDs); start, index = start+batchSize, index+1 {
		end := start + batchSize
		if end > len(identityIDs) {
			end = len(identityIDs)
		}
		gate := "passed"
		if len(gates) > 0 {
			g := gates[(index-1)%len(gates)]
			gate = strings.TrimSpace(g.Name + ":" + g.Status)
		}
		batches = append(batches, store.FleetReissuanceBatch{
			Index: index, Status: "completed", IdentityIDs: append([]string(nil), identityIDs[start:end]...),
			ReplacementIdentityIDs: append([]string(nil), replacementIDs[start:end]...), HealthGate: gate,
		})
	}
	return batches
}

func fleetReplacementName(name string, index int) string {
	base := strings.TrimSpace(name)
	if base == "" {
		base = "identity"
	}
	return fmt.Sprintf("%s-fleet-reissue-%d", base, index+1)
}

func fleetReplacementAttributes(runID, replaces string, existing json.RawMessage) json.RawMessage {
	attrs := map[string]any{
		"fleet_reissuance_run_id":       runID,
		"incident_replaces_identity_id": replaces,
	}
	if len(existing) > 0 {
		var base map[string]any
		if err := json.Unmarshal(existing, &base); err == nil {
			for k, v := range base {
				attrs[k] = v
			}
			attrs["fleet_reissuance_run_id"] = runID
			attrs["incident_replaces_identity_id"] = replaces
		}
	}
	b, _ := json.Marshal(attrs)
	return b
}
