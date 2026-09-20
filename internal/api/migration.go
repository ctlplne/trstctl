// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// The migration wave surface (epic H2).
//
// Two routes, and the split between them is the point. Assess is read-only and
// says what a migration WOULD touch and what is unknown about it; the plan
// routes are what actually runs. Keeping them apart in the API — rather than a
// dry_run flag on one endpoint — means a caller cannot accidentally execute by
// omitting a parameter, which is the failure mode a boolean invites.

// migrationAssessRequest names the cohort an operator wants assessed.
type migrationAssessRequest struct {
	PlanID string `json:"plan_id"`
	// Waves are ordered cohorts of identity IDs.
	Waves []struct {
		ID      string   `json:"id"`
		Ordinal int      `json:"ordinal"`
		Members []string `json:"members"`
	} `json:"waves"`
	RequireFullTrust bool `json:"require_full_trust"`
	MinTrustPercent  int  `json:"min_trust_percent"`
}

type migrationStartRequest struct {
	PlanID         string               `json:"plan_id"`
	NewAuthorityID string               `json:"new_authority_id"`
	Waves          []migrationStartWave `json:"waves"`
}

type migrationStartWave struct {
	ID      string                 `json:"id"`
	Ordinal int                    `json:"ordinal"`
	Members []migrationStartMember `json:"members"`
}

type migrationStartMember struct {
	IdentityID      string `json:"identity_id"`
	AgentID         string `json:"agent_id"`
	TrustAnchorPath string `json:"trust_anchor_path"`
}

type migrationActionRequest struct {
	Reason string `json:"reason,omitempty"`
}

// assessMigration enumerates what a migration would touch, mutating nothing.
func (a *API) assessMigration(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req migrationAssessRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error()))
		return
	}
	plan := migration.Plan{
		ID: req.PlanID, RequireFullTrust: req.RequireFullTrust,
		MinTrustPercent: req.MinTrustPercent,
	}
	for _, wv := range req.Waves {
		plan.Waves = append(plan.Waves, migration.Wave{
			ID: wv.ID, Ordinal: wv.Ordinal, Members: wv.Members, Phase: migration.PhasePlanned,
		})
	}
	if err := migration.ValidatePlan(plan); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}

	facts, err := a.migrationFacts(r, tenantID, plan)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, migration.Assess(plan, facts))
}

// migrationFacts gathers what is already known about each member.
//
// It reads the trust graph (H1) and the deployment targets, and it is the reason
// the assessment can distinguish "no trust store" from "an empty trust store":
// the graph records what was OBSERVED, so a member whose host has no store node
// is a member nobody scanned, not a member confirmed bare.
func (a *API) migrationFacts(r *http.Request, tenantID string, plan migration.Plan) (map[string]migration.MemberFacts, error) {
	out := map[string]migration.MemberFacts{}
	if a.store == nil {
		return out, nil
	}
	g, err := graph.Build(r.Context(), a.store, tenantID)
	if err != nil {
		return nil, err
	}
	targets, err := a.store.ListDeploymentTargets(r.Context(), tenantID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]store.DeploymentTarget, len(targets))
	for _, t := range targets {
		byID[t.ID] = t
	}

	// Count trust stores per host once, rather than per member: a wave of a
	// hundred identities on ten hosts should walk the graph once.
	storesByHost := map[string]int{}
	for _, n := range g.Nodes() {
		if n.Kind == graph.KindTrustStore {
			storesByHost[n.Attrs["host"]]++
		}
	}

	for _, wv := range plan.Waves {
		for _, m := range wv.Members {
			ident, identErr := a.store.GetIdentity(r.Context(), tenantID, m)
			if identErr != nil {
				// An identity we cannot read stays ABSENT from the facts map, so
				// Assess reports it as unknown rather than as assessed-and-fine.
				continue
			}
			f := migration.MemberFacts{Member: m}
			if t, found := byID[targetIDFromIdentityAttrs(ident.Attributes)]; found {
				f.HasDeploymentTarget = true
				f.HasVerifyAddress = targetHasVerifyAddress(t.Config)
				f.TrustStoresObserved = storesByHost[t.Name]
			}
			out[m] = f
		}
	}
	return out, nil
}

// targetIDFromIdentityAttrs reads the deployment target an identity is bound to.
func targetIDFromIdentityAttrs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return ""
	}
	id, _ := attrs["deployment_target_id"].(string)
	return id
}

// targetHasVerifyAddress reports whether a target can ever satisfy the live gate.
//
// Absent means it cannot: D2's verification only runs against a configured
// listener, so a member without one would sit unobserved forever rather than
// failing — which is exactly the kind of silent stall the assessment exists to
// surface before the migration starts rather than during it.
func targetHasVerifyAddress(cfg json.RawMessage) bool {
	if len(cfg) == 0 {
		return false
	}
	var fields map[string]any
	if err := json.Unmarshal(cfg, &fields); err != nil {
		return false
	}
	addr, _ := fields["verify_address"].(string)
	return strings.TrimSpace(addr) != ""
}

//trstctl:mutation
func (a *API) startMigrationRun(w http.ResponseWriter, r *http.Request) {
	var req migrationStartRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error()))
		return
	}
	canonical, err := json.Marshal(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex(append(append([]byte("migration-start\x00"+principal+"\x00"), canonical...), '\n'))
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutateDurableBound(w, r, idempotencyKey, binding,
		func(ctx context.Context, tenantID string) (int, any, error) {
			if a.orch == nil || a.store == nil {
				return 0, nil, errStatus(http.StatusServiceUnavailable, "migration execution is not configured")
			}
			if err := requireMigrationIssuePermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
			run, err := a.buildMigrationRun(ctx, tenantID, idempotencyKey, req)
			if err != nil {
				return 0, nil, errStatus(http.StatusBadRequest, err.Error())
			}
			started, actions, err := migration.StartRun(run)
			if err != nil {
				return 0, nil, errStatus(http.StatusBadRequest, err.Error())
			}
			recorded, err := a.orch.RecordMigrationRun(ctx, tenantID,
				orchestrator.MigrationEventID(tenantID, started.ID, "start"), started, actions)
			if err != nil {
				return 0, nil, err
			}
			return http.StatusCreated, recorded.Run, nil
		})
}

func (a *API) buildMigrationRun(ctx context.Context, tenantID, idempotencyKey string, req migrationStartRequest) (migration.Run, error) {
	req.PlanID = strings.TrimSpace(req.PlanID)
	req.NewAuthorityID = strings.TrimSpace(req.NewAuthorityID)
	if req.PlanID == "" || len(req.Waves) == 0 || guuid.Validate(req.NewAuthorityID) != nil {
		return migration.Run{}, errors.New("plan_id, new_authority_id, and at least one wave are required")
	}
	authority, err := a.store.GetCAAuthority(ctx, tenantID, req.NewAuthorityID)
	if err != nil || authority.Status != "active" || strings.TrimSpace(authority.SignerHandle) == "" {
		return migration.Run{}, errors.New("new_authority_id must name an active signer-backed CA authority in this tenant")
	}
	anchorPEM := []byte(strings.TrimSpace(authority.CertificatePEM))
	if len(anchorPEM) == 0 || len(anchorPEM) > 64<<10 {
		return migration.Run{}, errors.New("new_authority_id has no bounded public CA certificate")
	}
	anchor, err := certinfo.Inspect(anchorPEM)
	if err != nil || !anchor.IsCA {
		return migration.Run{}, errors.New("new_authority_id has no parseable CA certificate")
	}
	run := migration.Run{ID: orchestrator.MigrationRunID(tenantID, idempotencyKey), PlanID: req.PlanID}
	for _, requestedWave := range req.Waves {
		wave := migration.RunWave{ID: strings.TrimSpace(requestedWave.ID), Ordinal: requestedWave.Ordinal}
		for _, requestedMember := range requestedWave.Members {
			member, err := a.buildMigrationMember(ctx, tenantID, authority.ID, anchorPEM, anchor.SHA256Fingerprint,
				requestedMember.IdentityID, requestedMember.AgentID, requestedMember.TrustAnchorPath)
			if err != nil {
				return migration.Run{}, err
			}
			wave.Members = append(wave.Members, member)
		}
		run.Waves = append(run.Waves, wave)
	}
	if err := migration.ValidateExecutableRunForStart(run); err != nil {
		return migration.Run{}, err
	}
	return run, nil
}

func (a *API) buildMigrationMember(
	ctx context.Context,
	tenantID string,
	authorityID string,
	anchorPEM []byte,
	anchorFingerprint, identityID, agentID, anchorPath string,
) (migration.RunMember, error) {
	identityID, agentID, anchorPath = strings.TrimSpace(identityID), strings.TrimSpace(agentID), strings.TrimSpace(anchorPath)
	if identityID == "" || anchorPath == "" || guuid.Validate(agentID) != nil {
		return migration.RunMember{}, errors.New("each migration member requires identity_id, enrolled agent_id, and trust_anchor_path")
	}
	ident, err := a.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return migration.RunMember{}, errors.New("migration member identity does not exist in this tenant")
	}
	if ident.Kind != store.KindX509Certificate {
		return migration.RunMember{}, errors.New("migration members must be X.509 certificate identities")
	}
	if ident.Status != string(orchestrator.StateDeployed) {
		return migration.RunMember{}, errors.New("migration members must already be deployed")
	}
	targetID := targetIDFromIdentityAttrs(ident.Attributes)
	if targetID == "" {
		return migration.RunMember{}, errors.New("migration member has no deployment target binding")
	}
	target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
	if err != nil || !target.Enabled || !custody.TargetExecutorIsAgent(target.Config) || !relay.ExecutesOnHost(target.Type) {
		return migration.RunMember{}, errors.New("migration member target must be an enabled host-agent connector")
	}
	agent, err := a.store.GetAgent(ctx, tenantID, agentID)
	if err != nil || agent.Status != "active" || !sourceKindsContain(agent.Roles, mtls.AgentRoleHost) {
		return migration.RunMember{}, errors.New("agent_id must name an active host-role agent in this tenant")
	}
	certs, err := a.store.ListActiveIssuedCertificatesForIdentity(ctx, tenantID, ident.OwnerID, ident.Name)
	if err != nil || len(certs) != 1 {
		return migration.RunMember{}, errors.New("migration member must have exactly one active internally issued predecessor certificate")
	}
	predecessor := certs[0]
	info, err := certinfo.Inspect(predecessor.CertificateDER)
	if err != nil || len(info.DNSNames) == 0 || len(info.IPAddresses) > 0 || len(info.EmailAddresses) > 0 || len(info.URIs) > 0 {
		return migration.RunMember{}, errors.New("migration member predecessor must carry DNS identifiers only")
	}
	verifyAddress, verifyServerName := migrationVerifyTarget(target.Config)
	if verifyAddress == "" {
		return migration.RunMember{}, errors.New("migration member target must configure verify_address")
	}
	connectorName, routed := migrationRoutingAttrs(ident.Attributes)
	if connectorName != "" && connectorName != target.Type {
		return migration.RunMember{}, errors.New("identity connector binding conflicts with its deployment target")
	}
	if routed == "" {
		routed = target.Name
	}
	return migration.RunMember{IdentityID: identityID, Binding: migration.MemberBinding{
		IssuingAuthorityID: authorityID,
		TargetID:           target.ID, TargetRevision: target.RevisionID, Connector: target.Type,
		Target: routed, TargetConfig: append(json.RawMessage(nil), target.Config...), RequiredAgentID: agentID,
		TrustAnchorPath: anchorPath, TrustAnchorPEM: append([]byte(nil), anchorPEM...),
		TrustAnchorFingerprint: cleanMigrationFingerprint(anchorFingerprint),
		VerifyAddress:          verifyAddress, VerifyServerName: verifyServerName,
		SubjectCommonName: info.DNSNames[0], SubjectDNSNames: append([]string(nil), info.DNSNames...),
		PredecessorCertificateID: predecessor.ID,
		PredecessorFingerprint:   cleanMigrationFingerprint(predecessor.Fingerprint),
	}}, nil
}

func migrationVerifyTarget(cfg json.RawMessage) (string, string) {
	var fields map[string]any
	if json.Unmarshal(cfg, &fields) != nil {
		return "", ""
	}
	address, _ := fields["verify_address"].(string)
	serverName, _ := fields["verify_server_name"].(string)
	return strings.TrimSpace(address), strings.TrimSpace(serverName)
}

func migrationRoutingAttrs(raw json.RawMessage) (string, string) {
	var attrs map[string]any
	if json.Unmarshal(raw, &attrs) != nil {
		return "", ""
	}
	first := func(keys ...string) string {
		for _, key := range keys {
			if value, ok := attrs[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	return first("connector", "deployment_connector", "connector_name"),
		first("deployment_route", "target", "deployment_target", "deployment_location")
}

func cleanMigrationFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "sha256:")
	return strings.ReplaceAll(value, ":", "")
}

func (a *API) listMigrationRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rows, err := a.store.ListMigrationRuns(r.Context(), tenantID, 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]migration.Run, 0, len(rows))
	for _, row := range rows {
		items = append(items, row.Run)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func (a *API) getMigrationRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	run, err := a.store.GetMigrationRun(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, run.Run)
}

//trstctl:mutation
func (a *API) pauseMigrationRun(w http.ResponseWriter, r *http.Request) {
	a.mutateMigrationRun(w, r, r.Header.Get("Idempotency-Key"), "pause")
}

//trstctl:mutation
func (a *API) resumeMigrationRun(w http.ResponseWriter, r *http.Request) {
	a.mutateMigrationRun(w, r, r.Header.Get("Idempotency-Key"), "resume")
}

//trstctl:mutation
func (a *API) rollbackMigrationRun(w http.ResponseWriter, r *http.Request) {
	a.mutateMigrationRun(w, r, r.Header.Get("Idempotency-Key"), "rollback")
}

func (a *API) mutateMigrationRun(w http.ResponseWriter, r *http.Request, idempotencyKey, operation string) {
	var req migrationActionRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error()))
			return
		}
	}
	canonical, err := json.Marshal(req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	runID := r.PathValue("id")
	binding := crypto.SHA256Hex([]byte("migration-action\x00" + principal + "\x00" + operation + "\x00" + runID + "\x00" + string(canonical)))
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		// Resume can release a retained trust-gate receipt and immediately
		// publish successor issuance. Starting the run required certs:issue;
		// resuming it must not become a lower-privilege route around that gate.
		if operation == "resume" {
			if err := requireMigrationIssuePermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
		}
		updated, err := a.orch.UpdateMigrationRun(ctx, tenantID, runID,
			orchestrator.MigrationEventID(tenantID, runID, operation+":"+idempotencyKey),
			func(current migration.Run) (migration.Run, []migration.Action, error) {
				switch operation {
				case "pause":
					next, err := migration.PauseRun(current, req.Reason)
					return next, nil, err
				case "resume":
					return migration.ResumeRun(current)
				case "rollback":
					return migration.StartRollback(current)
				default:
					return current, nil, errors.New("unsupported migration operation")
				}
			})
		if err != nil {
			return 0, nil, errStatus(http.StatusConflict, err.Error())
		}
		return http.StatusOK, updated.Run, nil
	})
}

func requireMigrationIssuePermission(ctx context.Context, tenantID string) error {
	principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if !principal.Can(authz.CertsIssue, authz.Scope{TenantID: tenantID}) {
		return errStatus(http.StatusForbidden, "forbidden: CA migration that mints successors requires "+string(authz.CertsIssue))
	}
	return nil
}
