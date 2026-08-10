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
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/servedstatus"
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
	NextBatchIndex         int                               `json:"next_batch_index"`
	HaltedReason           string                            `json:"halted_reason,omitempty"`
	Connector              string                            `json:"connector"`
	Target                 string                            `json:"target"`
	GraphImpact            json.RawMessage                   `json:"graph_impact"`
	AffectedIdentityIDs    []string                          `json:"affected_identity_ids"`
	ReplacementIdentityIDs []string                          `json:"replacement_identity_ids"`
	RevokedIdentityIDs     []string                          `json:"revoked_identity_ids"`
	ConnectorDeliveryIDs   []string                          `json:"connector_delivery_ids"`
	Batches                []store.FleetReissuanceBatch      `json:"batches"`
	HealthGates            []store.FleetReissuanceHealthGate `json:"health_gates"`
	// D6: how many replacements are actually being served. These are the
	// numbers behind the replacement-deployment gate, exposed so an operator
	// can see WHY it reads as it does rather than having to trust the verdict.
	VerifiedReplacements int `json:"verified_replacements"`
	FailedReplacements   int `json:"failed_replacements"`
	// UnverifiedReplacements is what keeps a gate at not_evaluated. A run that
	// is 99% verified has one endpoint nobody looked at, and during an incident
	// that is exactly the endpoint worth knowing about.
	UnverifiedReplacements int `json:"unverified_replacements"`
	// CanaryState is "pending", "healthy" or "failed" (epic D6). The first
	// batch gates the rest: a canary that is not being served halts the
	// remainder before it can propagate to the whole estate.
	CanaryState           string                      `json:"canary_state,omitempty"`
	CanaryDetail          string                      `json:"canary_detail,omitempty"`
	FailedTargets         []string                    `json:"failed_targets"`
	RollbackRefs          []string                    `json:"rollback_refs"`
	EvidenceBundleFormat  string                      `json:"evidence_bundle_format"`
	EvidenceBundle        string                      `json:"evidence_bundle"`
	IdempotencyKey        string                      `json:"idempotency_key"`
	CreatedBy             string                      `json:"created_by"`
	CreatedAt             time.Time                   `json:"created_at"`
	UpdatedAt             time.Time                   `json:"updated_at"`
	ReplacementIdentities []identityResponse          `json:"replacement_identities,omitempty"`
	ConnectorDeliveries   []connectorDeliveryResponse `json:"connector_deliveries,omitempty"`
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
		NextBatchIndex: r.NextBatchIndex, HaltedReason: r.HaltedReason,
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
		plannedReplacementIDs := make([]string, 0, len(affected))
		rollbackRefs := []string{"run:" + runID, "issuer:" + req.IssuerID, rollbackRef}
		for _, compromised := range affected {
			affectedIDs = append(affectedIDs, compromised.ID)
			plannedReplacementIDs = append(plannedReplacementIDs, fleetReplacementID(runID, compromised.ID))
			rollbackRefs = append(rollbackRefs, "identity:"+compromised.ID)
		}
		batches := buildFleetBatches(affectedIDs, plannedReplacementIDs, batchSize)
		batches[0].Status = servedstatus.FleetBatchQueued
		evidenceFormat, evidenceBundle, err := a.incidentEvidenceBundle(ctx, tenantID, req.IssuerID)
		if err != nil {
			return 0, nil, err
		}
		run, err := a.orch.RecordIncidentFleetReissuanceAndEnqueueBatch(ctx, tenantID, store.IncidentFleetReissuanceRun{
			ID: runID, IssuerID: req.IssuerID, Status: "running", Phase: "canary_queued",
			Reason: reason, BatchSize: batchSize, Connector: connector, Target: target, GraphImpact: impactJSON,
			AffectedIdentityIDs: affectedIDs, Batches: batches, HealthGates: healthGates,
			NextBatchIndex: 1, RollbackRefs: rollbackRefs,
			EvidenceBundleFormat: evidenceFormat, EvidenceBundle: evidenceBundle,
			IdempotencyKey: idempotencyKey, CreatedBy: principal.Subject,
		}, 1)
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
	a.mutate(w, r, idempotencyKey, a.fleetReissuanceStateMutation(r, idempotencyKey, "running", "batch_resumed"))
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
		if status == "running" {
			if run.NextBatchIndex <= 0 || run.NextBatchIndex > len(run.Batches) {
				return 0, nil, errStatus(http.StatusConflict, "fleet reissuance has no paused or halted batch to resume")
			}
			run.HaltedReason = ""
			for i := range run.Batches {
				switch {
				case run.Batches[i].Index == run.NextBatchIndex:
					run.Batches[i].Status = servedstatus.FleetBatchQueued
					run.Batches[i].HealthGate = servedstatus.FleetGateNotEvaluated
				case run.Batches[i].Index > run.NextBatchIndex && run.Batches[i].Status == servedstatus.FleetBatchHalted:
					run.Batches[i].Status = servedstatus.FleetBatchPlanned
				}
			}
		}
		if reason := strings.TrimSpace(req.Reason); reason != "" {
			run.Reason = run.Reason + "; " + phase + ": " + reason
		}
		if rollbackRef := strings.TrimSpace(req.RollbackRef); rollbackRef != "" {
			run.RollbackRefs = append(run.RollbackRefs, rollbackRef)
		}
		run.IdempotencyKey = idempotencyKey
		var updated store.IncidentFleetReissuanceRun
		if status == "running" {
			updated, err = a.orch.RecordIncidentFleetReissuanceAndEnqueueBatch(ctx, tenantID, run, run.NextBatchIndex)
		} else {
			updated, err = a.orch.RecordIncidentFleetReissuance(ctx, tenantID, run)
		}
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
	// D6: derive the replacement-deployment gate from what the endpoints are
	// actually serving. Computed at READ time rather than frozen at run time,
	// because verification is a loop — an endpoint that was serving correctly
	// when the run finished can stop, and a gate that never re-evaluated would
	// go on showing a pass for a fleet that has since diverged.
	if a.store != nil {
		plannedReplacementIDs := fleetPlannedReplacementIDs(resp.Batches)
		if len(plannedReplacementIDs) > 0 {
			outcome, err := a.store.SummarizeFleetVerification(ctx, tenantID, plannedReplacementIDs)
			if err == nil {
				resp.HealthGates = evaluateFleetDeploymentGate(resp.HealthGates, operatorAssertedGates(resp.HealthGates), outcome)
				resp.VerifiedReplacements = outcome.Verified
				resp.FailedReplacements = outcome.Failed
				resp.UnverifiedReplacements = outcome.Unverified
			}
		}
		// H3: each batch's gate is recomputed from ITS OWN replacements before
		// anything is reported. Done here, on the read, so a gate reflects what
		// verification says NOW rather than what it said when the run was
		// recorded — during an incident the two diverge constantly, and the
		// stale one is the one that gets acted on.
		resp.Batches = evaluateFleetBatchGates(ctx, a.store, tenantID, resp.Batches)

		// This read may explain the durable canary state, but it never rewrites
		// batch labels. Halting is a worker-side event-sourced mutation.
		switch {
		case resp.HaltedReason != "":
			resp.CanaryState = "failed"
			resp.CanaryDetail = resp.HaltedReason
		case evaluateCanary(ctx, a.store, tenantID, resp.Batches) == canaryFailed:
			resp.CanaryState = "failed"
			resp.CanaryDetail = "signed canary verification failed; the worker has not yet persisted the halt"
		case evaluateCanary(ctx, a.store, tenantID, resp.Batches) == canaryHealthy:
			resp.CanaryState = "healthy"
		default:
			// Pending. The rest waits rather than proceeding on silence: "we
			// have not looked" and "it is fine" are the two things this
			// workstream exists to keep apart.
			resp.CanaryState = "pending"
			resp.CanaryDetail = "the canary batch has not been verified yet; the remaining " +
				"batches wait rather than proceeding on an unverified first batch"
		}
	}
}

func fleetPlannedReplacementIDs(batches []store.FleetReissuanceBatch) []string {
	var ids []string
	for _, batch := range batches {
		ids = append(ids, batch.ReplacementIdentityIDs...)
	}
	return ids
}

// operatorAssertedGates records which gates an operator set explicitly at
// creation time, so a computed verdict never overwrites an attestation.
//
// A gate that is anything other than not_evaluated when the run is read was put
// there by a person. That person may have inspected something this control
// plane cannot see, which makes them the better authority — replacing their
// answer with a derived one would discard the more informed of the two.
func operatorAssertedGates(gates []store.FleetReissuanceHealthGate) map[string]bool {
	out := map[string]bool{}
	for _, g := range gates {
		if strings.TrimSpace(g.Status) != "" && strings.TrimSpace(g.Status) != servedstatus.FleetGateNotEvaluated {
			out[strings.ToLower(strings.TrimSpace(g.Name))] = true
		}
	}
	return out
}

// normalizeFleetHealthGates fills in the gate set for a run. trstctl evaluates
// D6 changed what this can honestly say. The replacement-deployment gate is now
// COMPUTED from verification receipts: D2 re-reads endpoints and D3 records the
// verdict, so there is finally evidence to derive a verdict from.
//
// The rule that matters is the one an operator relies on mid-incident: any
// failed verification fails the gate, and any replacement nobody verified keeps
// it not_evaluated. A run cannot display all-green while one of its
// replacements is not being served, and silence never reads as success — a
// verdict nobody computed is still not a pass (truth-integrity 2).
//
// The other two gates stay not_evaluated because nothing computes them yet:
// graph enumeration has no completeness oracle, and revocation publication is
// R1's CRL/OCSP freshness signal, which is not wired to this run. Saying so is
// better than deriving them from something adjacent and calling it proof.
//
// An operator may still assert any gate explicitly. That is an attestation and
// is recorded as theirs — an asserted gate is never overwritten by a computed
// one, because an operator who has looked at something this control plane
// cannot see is the better authority.
func normalizeFleetHealthGates(in []store.FleetReissuanceHealthGate) []store.FleetReissuanceHealthGate {
	if len(in) == 0 {
		return []store.FleetReissuanceHealthGate{
			{Name: "graph enumeration", Status: servedstatus.FleetGateNotEvaluated},
			{Name: fleetDeploymentGateName, Status: servedstatus.FleetGateNotEvaluated},
			{Name: "revocation publication", Status: servedstatus.FleetGateNotEvaluated},
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
			status = servedstatus.FleetGateNotEvaluated
		}
		out = append(out, store.FleetReissuanceHealthGate{Name: name, Status: status})
	}
	return out
}

// buildFleetBatches creates the durable execution plan. The request path changes
// only batch one from planned to queued; the fleet worker is the sole publisher
// of every later batch.
// fleetDeploymentGateName is the gate D6 computes from verification receipts.
const fleetDeploymentGateName = "replacement deployment"

// evaluateFleetDeploymentGate replaces the not_evaluated placeholder with a
// verdict derived from what endpoints are actually serving.
//
// Never overwrites a gate an OPERATOR asserted. An operator who has inspected
// something this control plane cannot see is the better authority, and silently
// replacing their attestation with a computed value would discard the more
// informed answer.
func evaluateFleetDeploymentGate(
	gates []store.FleetReissuanceHealthGate,
	operatorAsserted map[string]bool,
	outcome store.FleetVerificationOutcome,
) []store.FleetReissuanceHealthGate {
	for i, gate := range gates {
		if !strings.EqualFold(strings.TrimSpace(gate.Name), fleetDeploymentGateName) {
			continue
		}
		if operatorAsserted[strings.ToLower(strings.TrimSpace(gate.Name))] {
			continue
		}
		gates[i].Status = fleetDeploymentVerdict(outcome)
	}
	return gates
}

// fleetDeploymentVerdict maps verification counts onto the gate vocabulary.
//
// Failure dominates, and absence beats success. Those two rules are the whole
// point: an operator reading a green run during an incident must be able to
// trust that nothing in it is known-broken and that nothing in it is merely
// unlooked-at.
func fleetDeploymentVerdict(o store.FleetVerificationOutcome) string {
	switch {
	case o.Failed > 0:
		return servedstatus.FleetGateFailed
	case o.Unverified > 0 || o.Verified == 0:
		// Even one unverified replacement keeps the gate unevaluated. A run
		// that is 99% verified is not a run that passed — it is a run with an
		// endpoint nobody looked at, and during an incident that is exactly the
		// endpoint worth knowing about.
		return servedstatus.FleetGateNotEvaluated
	default:
		return servedstatus.FleetGatePassed
	}
}

func buildFleetBatches(identityIDs, replacementIDs []string, batchSize int) []store.FleetReissuanceBatch {
	if batchSize <= 0 {
		batchSize = 25
	}
	var batches []store.FleetReissuanceBatch
	for start, index := 0, 1; start < len(identityIDs); start, index = start+batchSize, index+1 {
		end := start + batchSize
		if end > len(identityIDs) {
			end = len(identityIDs)
		}
		// Not evaluated until this batch's OWN replacements have been observed.
		//
		// This used to round-robin the run's gate list across batches —
		// gates[(index-1)%len(gates)] — so batch 1 wore the first gate's label,
		// batch 2 the second, and it wrapped. A batch's health gate therefore
		// said nothing whatever about that batch, which is worse than showing
		// nothing: during an incident it reads as per-batch evidence, and an
		// operator deciding whether to continue a fleet reissue is exactly the
		// reader who would act on it.
		//
		// The per-batch verdict is computed by evaluateFleetBatchGates below,
		// from the batch's own replacement identities. Planned batches start
		// unevaluated because nothing has been looked at yet, which is the true
		// statement.
		gate := servedstatus.FleetGateNotEvaluated
		batches = append(batches, store.FleetReissuanceBatch{
			Index: index, Status: servedstatus.FleetBatchPlanned, IdentityIDs: append([]string(nil), identityIDs[start:end]...),
			ReplacementIdentityIDs: append([]string(nil), replacementIDs[start:end]...), HealthGate: gate,
		})
	}
	return batches
}

// evaluateFleetBatchGates gives each batch a verdict from ITS OWN replacements
// (epic H3).
//
// Per batch rather than per run, because the decision a fleet reissue asks an
// operator to make is per batch: continue, halt, or roll back. A run-wide gate
// answers a question nobody is asking at that moment — it tells you the estate
// is imperfect without telling you whether THIS wave landed.
//
// Batches that have not executed are left alone. A planned batch has nothing to
// verify, and stamping it with a verdict derived from an empty set would make
// "not evaluated" and "evaluated and found nothing" the same string.
func evaluateFleetBatchGates(
	ctx context.Context,
	st *store.Store,
	tenantID string,
	batches []store.FleetReissuanceBatch,
) []store.FleetReissuanceBatch {
	if st == nil {
		return batches
	}
	for i := range batches {
		if batches[i].Status == servedstatus.FleetBatchPlanned ||
			batches[i].Status == servedstatus.FleetBatchQueued ||
			batches[i].Status == servedstatus.FleetBatchHalted {
			continue
		}
		if len(batches[i].ReplacementIdentityIDs) == 0 {
			continue
		}
		outcome, err := st.SummarizeFleetVerification(ctx, tenantID, batches[i].ReplacementIdentityIDs)
		if err != nil {
			// A read failure is not a verdict. Leaving the gate as it stands is
			// the only honest option: reporting passed would be a lie and
			// reporting failed would halt a healthy run over a transient error.
			continue
		}
		batches[i].HealthGate = fleetDeploymentVerdict(outcome)
	}
	return batches
}

func fleetReplacementID(runID, replaces string) string {
	return guuid.NewSHA1(guuid.NameSpaceOID, []byte("fleet-replacement\x00"+runID+"\x00"+replaces)).String()
}
