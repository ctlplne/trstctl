// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/servedstatus"
	"trstctl.com/trstctl/internal/store"
)

type fleetReissuanceRequest struct {
	IssuerID               string                 `json:"issuer_id"`
	ReplacementAuthorityID string                 `json:"replacement_authority_id"`
	Mode                   migration.IncidentMode `json:"mode"`
	Reason                 string                 `json:"reason"`
	Cohorts                []migrationStartWave   `json:"cohorts"`
	RollbackRef            string                 `json:"rollback_ref"`
}

type fleetReissuanceActionRequest struct {
	Reason      string `json:"reason"`
	RollbackRef string `json:"rollback_ref"`
}

type fleetReissuanceRunResponse struct {
	ID                     string                            `json:"id"`
	TenantID               string                            `json:"tenant_id"`
	IssuerID               string                            `json:"issuer_id"`
	MigrationRunID         string                            `json:"migration_run_id,omitempty"`
	ReplacementAuthorityID string                            `json:"replacement_authority_id,omitempty"`
	Mode                   string                            `json:"mode"`
	PlanDigest             string                            `json:"plan_digest,omitempty"`
	ExactTrustStoreIDs     []string                          `json:"exact_trust_store_ids"`
	ExactTrustHosts        []string                          `json:"exact_trust_hosts"`
	CandidateTrustStoreIDs []string                          `json:"candidate_trust_store_ids"`
	CandidateTrustHosts    []string                          `json:"candidate_trust_hosts"`
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
	if r.ExactTrustStoreIDs == nil {
		r.ExactTrustStoreIDs = []string{}
	}
	if r.ExactTrustHosts == nil {
		r.ExactTrustHosts = []string{}
	}
	if r.CandidateTrustStoreIDs == nil {
		r.CandidateTrustStoreIDs = []string{}
	}
	if r.CandidateTrustHosts == nil {
		r.CandidateTrustHosts = []string{}
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
		MigrationRunID: r.MigrationRunID, ReplacementAuthorityID: r.ReplacementAuthorityID,
		Mode: r.Mode, PlanDigest: r.PlanDigest,
		ExactTrustStoreIDs: r.ExactTrustStoreIDs, ExactTrustHosts: r.ExactTrustHosts,
		CandidateTrustStoreIDs: r.CandidateTrustStoreIDs, CandidateTrustHosts: r.CandidateTrustHosts,
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
	var req fleetReissuanceRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error()))
		return
	}
	canonical, err := json.Marshal(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	principalSubject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("incident-fleet-start\x00" + principalSubject + "\x00" + string(canonical)))
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		req.IssuerID = strings.TrimSpace(req.IssuerID)
		req.ReplacementAuthorityID = strings.TrimSpace(req.ReplacementAuthorityID)
		if req.IssuerID == "" || req.ReplacementAuthorityID == "" || len(req.Cohorts) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "issuer_id, replacement_authority_id, and at least one cohort are required")
		}
		if req.Mode != migration.IncidentModeLive && req.Mode != migration.IncidentModeGameDay {
			return 0, nil, errStatus(http.StatusBadRequest, "mode must be live or game_day")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if !principal.Can(authz.CertsIssue, authz.Scope{TenantID: tenantID}) {
			return 0, nil, errStatus(http.StatusForbidden, "forbidden: fleet reissuance that mints replacements requires "+string(authz.CertsIssue))
		}
		if req.Mode == migration.IncidentModeGameDay && !principal.Can(authz.IncidentsGameDay, authz.Scope{TenantID: tenantID}) {
			return 0, nil, errStatus(http.StatusForbidden, "forbidden: incident rehearsal requires "+string(authz.IncidentsGameDay))
		}
		if _, err := a.store.GetIssuer(ctx, tenantID, req.IssuerID); err != nil {
			return 0, nil, err
		}

		// Freeze both the affected certificate set and H1's exact public-key
		// relationships before publishing any estate effect. Subject-only
		// candidates remain visible guidance, but never enter execution authority.
		g, err := graph.Build(ctx, a.store, tenantID)
		if err != nil {
			return 0, nil, err
		}
		issuerNodeID := "iss:" + req.IssuerID
		if _, ok := g.Node(issuerNodeID); !ok {
			return 0, nil, errStatus(http.StatusNotFound, "graph node not found for compromised issuer")
		}
		exactStores, exactHosts := g.TrustStoresForIssuer(issuerNodeID)
		candidateStores, candidateHosts := g.TrustCandidatesForIssuer(issuerNodeID)
		if len(exactStores) == 0 || len(exactHosts) == 0 {
			return 0, nil, errStatus(http.StatusConflict, "incident execution requires at least one exact certificate/SPKI trust-store relationship and host")
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "verified compromised issuer fleet reissuance"
		}
		affected, err := a.store.ListRevocableIdentitiesByIssuer(ctx, tenantID, req.IssuerID)
		if err != nil {
			return 0, nil, err
		}
		if len(affected) == 0 {
			return 0, nil, errStatus(http.StatusConflict, "fleet reissuance requires at least one issued, deployed, or renewing identity for the issuer")
		}
		impact := g.BlastRadius(issuerNodeID)
		impactJSON, err := json.Marshal(impact)
		if err != nil {
			return 0, nil, err
		}

		migrationReq := migrationStartRequest{
			PlanID:         "incident:" + req.IssuerID,
			NewAuthorityID: req.ReplacementAuthorityID,
			Waves:          req.Cohorts,
		}
		run, err := a.buildMigrationRun(ctx, tenantID, idempotencyKey, migrationReq)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		exactStoreIDs, exactHostIDs := graphNodeIDs(exactStores), graphNodeNames(exactHosts)
		candidateStoreIDs, candidateHostIDs := graphNodeIDs(candidateStores), graphNodeNames(candidateHosts)
		affectedIDs := make([]string, 0, len(affected))
		for _, identity := range affected {
			affectedIDs = append(affectedIDs, identity.ID)
		}
		if err := a.bindIncidentMigrationMembers(ctx, tenantID, exactHostIDs, &run); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		run.Incident = &migration.IncidentPlan{
			Mode: req.Mode, CompromisedIssuerID: req.IssuerID,
			ReplacementAuthorityID: req.ReplacementAuthorityID,
			ExactTrustStoreIDs:     exactStoreIDs, ExactTrustHosts: exactHostIDs,
			AffectedIdentityIDs: affectedIDs,
		}
		if err := migration.ValidateExecutableRunForStart(run); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		planBytes, err := json.Marshal(run)
		if err != nil {
			return 0, nil, err
		}
		planDigest := crypto.SHA256Hex(planBytes)
		started, actions, err := migration.StartRun(run)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}

		rollbackRef := strings.TrimSpace(req.RollbackRef)
		if rollbackRef == "" {
			rollbackRef = "H2 automatically restores the failed cohort before any predecessor revocation"
		}
		rollbackRefs := []string{"run:" + run.ID, "issuer:" + req.IssuerID, rollbackRef}
		for _, identityID := range affectedIDs {
			rollbackRefs = append(rollbackRefs, "identity:"+identityID)
		}
		incident := store.IncidentFleetReissuanceRun{
			ID: run.ID, IssuerID: req.IssuerID, MigrationRunID: run.ID,
			ReplacementAuthorityID: req.ReplacementAuthorityID, Mode: string(req.Mode), PlanDigest: planDigest,
			ExactTrustStoreIDs: exactStoreIDs, ExactTrustHosts: exactHostIDs,
			CandidateTrustStoreIDs: candidateStoreIDs, CandidateTrustHosts: candidateHostIDs,
			Status: "planned", Phase: "plan_persisted_before_estate_work", Reason: reason,
			BatchSize: largestIncidentCohort(started.Waves), GraphImpact: impactJSON,
			AffectedIdentityIDs: affectedIDs, Batches: incidentBatches(started),
			HealthGates: incidentHealthGates(started), NextBatchIndex: 1, RollbackRefs: rollbackRefs,
			IdempotencyKey: idempotencyKey, CreatedBy: principal.Subject,
		}
		// This event/projection is deliberately first. If the process dies after
		// it, a retry sees the same immutable digest. Only the following H2 event
		// may atomically publish trust-distribution intents.
		planned, err := a.orch.RecordIncidentFleetReissuanceWithEventID(ctx, tenantID,
			orchestrator.MigrationEventID(tenantID, incident.ID, "incident-plan"), incident)
		if err != nil {
			return 0, nil, err
		}
		incident.CreatedAt = planned.CreatedAt
		recorded, err := a.orch.RecordMigrationRun(ctx, tenantID,
			orchestrator.MigrationEventID(tenantID, started.ID, "start"), started, actions)
		if err != nil {
			return 0, nil, err
		}
		applyMigrationRunToIncident(&incident, recorded.Run)
		incident, err = a.orch.RecordIncidentFleetReissuanceWithEventID(ctx, tenantID,
			orchestrator.MigrationEventID(tenantID, incident.ID,
				fmt.Sprintf("incident-mirror:%d", recorded.LastEventSequence)), incident)
		if err != nil {
			return 0, nil, err
		}
		resp := toFleetReissuanceRunResponse(incident)
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
		if run.MigrationRunID != "" {
			principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
			if run.Mode == string(migration.IncidentModeGameDay) &&
				!principal.Can(authz.IncidentsGameDay, authz.Scope{TenantID: tenantID}) {
				return 0, nil, errStatus(http.StatusForbidden, "forbidden: incident rehearsal requires "+string(authz.IncidentsGameDay))
			}
			operation := "pause"
			switch status {
			case "running":
				operation = "resume"
				if err := requireMigrationIssuePermission(ctx, tenantID); err != nil {
					return 0, nil, err
				}
			case "rollback_recorded":
				operation = "rollback"
			}
			updatedMigration, err := a.orch.UpdateMigrationRun(ctx, tenantID, run.MigrationRunID,
				orchestrator.MigrationEventID(tenantID, run.MigrationRunID, "incident-"+operation+":"+idempotencyKey),
				func(current migration.Run) (migration.Run, []migration.Action, error) {
					switch operation {
					case "pause":
						next, pauseErr := migration.PauseRun(current, req.Reason)
						return next, nil, pauseErr
					case "resume":
						return migration.ResumeRun(current)
					case "rollback":
						return migration.StartRollback(current)
					default:
						return current, nil, errors.New("unsupported incident migration operation")
					}
				})
			if err != nil {
				return 0, nil, errStatus(http.StatusConflict, err.Error())
			}
			applyMigrationRunToIncident(&run, updatedMigration.Run)
			if reason := strings.TrimSpace(req.Reason); reason != "" {
				run.Reason += "; " + operation + ": " + reason
			}
			if rollbackRef := strings.TrimSpace(req.RollbackRef); rollbackRef != "" {
				run.RollbackRefs = append(run.RollbackRefs, rollbackRef)
			}
			run.IdempotencyKey = idempotencyKey
			if err := a.sealTerminalIncidentEvidence(ctx, tenantID, updatedMigration.Run, &run); err != nil {
				return 0, nil, err
			}
			updated, err := a.orch.RecordIncidentFleetReissuanceWithEventID(ctx, tenantID,
				orchestrator.MigrationEventID(tenantID, run.ID,
					fmt.Sprintf("incident-mirror:%d", updatedMigration.LastEventSequence)), run)
			if err != nil {
				return 0, nil, err
			}
			resp := toFleetReissuanceRunResponse(updated)
			a.hydrateFleetReissuanceResponse(ctx, tenantID, &resp)
			return http.StatusOK, resp, nil
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
	if run.MigrationRunID != "" && (run.EvidenceBundleFormat != "jws" || strings.TrimSpace(run.EvidenceBundle) == "") {
		a.writeError(w, errStatus(http.StatusConflict, "incident evidence is sealed only after verified completion or completed rollback"))
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

func graphNodeIDs(nodes []graph.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, node.ID)
	}
	return out
}

func graphNodeNames(nodes []graph.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, node.Name)
	}
	return out
}

// bindIncidentMigrationMembers adds the incident-only immutable facts H2 does
// not require for an ordinary CA rollover: the exact old revocation authority,
// the H1-observed host that owns the trust relationship, and the frozen
// environment used by the game-day production fence.
func (a *API) bindIncidentMigrationMembers(ctx context.Context, tenantID string, exactHosts []string, run *migration.Run) error {
	if a.store == nil || run == nil {
		return errors.New("incident migration execution is not configured")
	}
	hosts := make(map[string]bool, len(exactHosts))
	for _, host := range exactHosts {
		hosts[strings.ToLower(strings.TrimSpace(host))] = true
	}
	for waveIndex := range run.Waves {
		for memberIndex := range run.Waves[waveIndex].Members {
			member := &run.Waves[waveIndex].Members[memberIndex]
			agent, err := a.store.GetAgent(ctx, tenantID, member.Binding.RequiredAgentID)
			if err != nil || !hosts[strings.ToLower(strings.TrimSpace(agent.Name))] {
				return errors.New("each incident cohort agent must be an exact H1 trust host for the compromised issuer")
			}
			cert, err := a.store.GetCertificate(ctx, tenantID, member.Binding.PredecessorCertificateID)
			if err != nil {
				return errors.New("incident predecessor certificate is no longer inventoried")
			}
			caID, err := a.store.ExactIssuedCertificateAuthority(ctx, tenantID, cert.Serial)
			if err != nil {
				return errors.New("incident predecessor does not resolve to exactly one internal revocation authority")
			}
			identity, err := a.store.GetIdentity(ctx, tenantID, member.IdentityID)
			if err != nil {
				return errors.New("incident cohort identity is no longer inventoried")
			}
			owner, err := a.store.GetOwner(ctx, tenantID, identity.OwnerID)
			if err != nil {
				return errors.New("incident cohort identity has no readable owner environment")
			}
			ownerEnvironment := strings.ToLower(strings.TrimSpace(owner.Environment))
			targetEnvironment := incidentTargetEnvironment(member.Binding.TargetConfig)
			if ownerEnvironment != "" && targetEnvironment != "" && ownerEnvironment != targetEnvironment {
				return errors.New("incident cohort owner and deployment target environments conflict")
			}
			environment := ownerEnvironment
			if targetEnvironment != "" {
				environment = targetEnvironment
			}
			member.Binding.PredecessorCAID = caID
			member.Binding.Environment = environment
		}
	}
	return nil
}

func incidentTargetEnvironment(raw json.RawMessage) string {
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil {
		return ""
	}
	for _, key := range []string{"environment", "env"} {
		if value, ok := cfg[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

func largestIncidentCohort(waves []migration.RunWave) int {
	largest := 0
	for _, wave := range waves {
		if len(wave.Members) > largest {
			largest = len(wave.Members)
		}
	}
	return largest
}

func incidentBatches(run migration.Run) []store.FleetReissuanceBatch {
	batches := make([]store.FleetReissuanceBatch, 0, len(run.Waves))
	for index, wave := range run.Waves {
		batch := store.FleetReissuanceBatch{
			Index: index + 1, Status: servedstatus.FleetBatchPlanned,
			HealthGate: servedstatus.FleetGateNotEvaluated,
		}
		if wave.Started {
			batch.Status = servedstatus.FleetBatchWaitingVerification
		}
		if wave.Phase == migration.PhaseComplete {
			batch.Status = servedstatus.FleetBatchExecuted
			batch.HealthGate = servedstatus.FleetGatePassed
		}
		if wave.Phase == migration.PhaseRolledBack || strings.TrimSpace(wave.HaltReason) != "" {
			batch.Status = servedstatus.FleetBatchFailed
			batch.HealthGate = servedstatus.FleetGateFailed
		}
		for _, member := range wave.Members {
			batch.IdentityIDs = append(batch.IdentityIDs, member.IdentityID)
		}
		batches = append(batches, batch)
	}
	return batches
}

func incidentHealthGates(run migration.Run) []store.FleetReissuanceHealthGate {
	trust, live, revoked := servedstatus.FleetGatePassed, servedstatus.FleetGatePassed, servedstatus.FleetGatePassed
	for _, wave := range run.Waves {
		for _, member := range wave.Members {
			trust = incidentVerdictGate(trust, member.TrustVerdict)
			live = incidentVerdictGate(live, member.SuccessorVerdict)
			revoked = incidentVerdictGate(revoked, member.RevocationVerdict)
		}
	}
	return []store.FleetReissuanceHealthGate{
		{Name: "signed_trust_distribution", Status: trust},
		{Name: "signed_live_serving", Status: live},
		{Name: "exact_predecessor_revocation", Status: revoked},
	}
}

func incidentVerdictGate(current string, verdict migration.Verdict) string {
	if current == servedstatus.FleetGateFailed || verdict == migration.VerdictFailed {
		return servedstatus.FleetGateFailed
	}
	if current == servedstatus.FleetGateNotEvaluated || verdict == "" {
		return servedstatus.FleetGateNotEvaluated
	}
	return servedstatus.FleetGatePassed
}

func applyMigrationRunToIncident(incident *store.IncidentFleetReissuanceRun, run migration.Run) {
	if incident == nil {
		return
	}
	incident.Status = string(run.Status)
	incident.Phase = "planned"
	incident.HaltedReason = run.HaltReason
	incident.NextBatchIndex = len(run.Waves) + 1
	for index, wave := range run.Waves {
		if wave.Started && wave.Phase != migration.PhaseComplete && wave.Phase != migration.PhaseRolledBack {
			incident.Phase = wave.ID + ":" + string(wave.Phase)
			incident.NextBatchIndex = index + 1
			break
		}
		if wave.Started {
			incident.Phase = wave.ID + ":" + string(wave.Phase)
		}
	}
	if run.Status == migration.RunComplete {
		incident.Status = "executed"
		incident.Phase = "fleet_reissued_verified_and_predecessors_revoked"
	}
	if run.Status == migration.RunRolledBack {
		incident.Status = "rolled_back"
		incident.Phase = "failed_cohort_rolled_back"
	}
	incident.Batches = incidentBatches(run)
	incident.HealthGates = incidentHealthGates(run)
}

func (a *API) sealTerminalIncidentEvidence(ctx context.Context, tenantID string, run migration.Run, incident *store.IncidentFleetReissuanceRun) error {
	if run.Status != migration.RunComplete && run.Status != migration.RunRolledBack {
		return nil
	}
	if incident == nil || a.audit == nil {
		return errors.New("terminal incident migration cannot be recorded without the audit signer")
	}
	if incident.EvidenceBundleFormat == "jws" && strings.TrimSpace(incident.EvidenceBundle) != "" {
		return nil
	}
	bundle, err := a.audit.Export(ctx, audit.Query{TenantID: tenantID, Contains: run.ID})
	if err != nil {
		return err
	}
	incident.EvidenceBundleFormat = "jws"
	incident.EvidenceBundle = bundle
	return nil
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
	// H3 rows are projections of H2's signed gate receipts. The legacy D6 read
	// hydration below derives synthetic batch labels from replacement identities;
	// applying it here would overwrite the authoritative H2 cursor.
	if resp.MigrationRunID != "" {
		return
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
