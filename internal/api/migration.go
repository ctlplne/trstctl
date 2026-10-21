// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/connector"
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
				f.TrustStoresObserved = observedMigrationTrustStores(g, t)
			}
			out[m] = f
		}
	}
	return out, nil
}

// observedMigrationTrustStores accepts only stores reported by the target's
// assigned, certificate-authenticated host agent. A target display name may
// differ from the agent name or collide with another machine's name.
func observedMigrationTrustStores(g *graph.Graph, target store.DeploymentTarget) int {
	agentID, err := connector.TargetHostAgentID(target.Config)
	if err != nil || agentID == "" {
		return 0
	}
	count := 0
	for _, n := range g.Nodes() {
		if n.Kind == graph.KindTrustStore && n.Attrs["agent_id"] == agentID {
			count++
		}
	}
	return count
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
	if err != nil || authority.Status != "active" {
		return migration.Run{}, errors.New("new_authority_id must name an active CA authority in this tenant")
	}
	// The named authority is the anchor hosts will trust. It is also the
	// issuer, unless it is an imported offline root (A36): that key never
	// enters the signer, so successors are minted by its one active
	// signer-backed intermediate while the root certificate stays the anchor.
	issuer := authority
	if strings.TrimSpace(authority.SignerHandle) == "" {
		authorities, err := a.store.ListCAAuthorities(ctx, tenantID)
		if err != nil {
			return migration.Run{}, err
		}
		if issuer, err = migrationIssuingAuthority(authority, authorities); err != nil {
			return migration.Run{}, err
		}
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
			member, err := a.buildMigrationMember(ctx, tenantID, issuer.ID, anchorPEM, anchor.SHA256Fingerprint,
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
	profileRequirement, err := a.orch.ProfileApprovalRequirement(ctx, tenantID, identityID)
	if err != nil {
		return migration.RunMember{}, err
	}
	if profileRequirement.ProfileName == "" && a.gate.Profile != "" {
		profileRequirement, err = a.orch.ProfileApprovalRequirementByName(ctx, tenantID, a.gate.Profile)
		if err != nil {
			return migration.RunMember{}, err
		}
	}
	if profileRequirement.RequiresApproval {
		return migration.RunMember{}, errors.New("migration member profile requires distinct issuance approval; this run cannot start without an exact approved issuance binding")
	}
	issuance := profileRequirement.IssuanceBinding()
	targetID := targetIDFromIdentityAttrs(ident.Attributes)
	if targetID == "" {
		return migration.RunMember{}, errors.New("migration member has no deployment target binding")
	}
	target, err := a.store.GetDeploymentTarget(ctx, tenantID, targetID)
	if err != nil || !target.Enabled || !custody.TargetExecutorIsAgent(target.Config) || !relay.ExecutesOnHost(target.Type) {
		return migration.RunMember{}, errors.New("migration member target must be an enabled host-agent connector")
	}
	assignedAgentID, err := connector.TargetHostAgentID(target.Config)
	if err != nil || assignedAgentID == "" || assignedAgentID != agentID {
		return migration.RunMember{}, errors.New("migration member agent_id must match the target's assigned host agent")
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
	if err != nil {
		return migration.RunMember{}, errors.New("migration member predecessor certificate could not be read")
	}
	subjectCommonName, subjectDNSNames, subjectIPAddresses, err := migrationMemberSubject(info)
	if err != nil {
		return migration.RunMember{}, err
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
		Issuance: &migration.IssuanceBinding{
			ProfileName: issuance.ProfileName, ProfileID: issuance.ProfileID,
			ProfileVersion: issuance.ProfileVersion, ProfileSpecDigest: issuance.ProfileSpecDigest,
			RequestedTTLSeconds: issuance.RequestedTTLSeconds, EffectiveTTLSeconds: issuance.EffectiveTTLSeconds,
		},
		TargetID: target.ID, TargetRevision: target.RevisionID, Connector: target.Type,
		Target: routed, TargetConfig: append(json.RawMessage(nil), target.Config...), RequiredAgentID: agentID,
		TrustAnchorPath: anchorPath, TrustAnchorPEM: append([]byte(nil), anchorPEM...),
		TrustAnchorFingerprint: cleanMigrationFingerprint(anchorFingerprint),
		VerifyAddress:          verifyAddress, VerifyServerName: verifyServerName,
		SubjectCommonName: subjectCommonName, SubjectDNSNames: subjectDNSNames, SubjectIPAddresses: subjectIPAddresses,
		PredecessorCertificateID: predecessor.ID,
		PredecessorFingerprint:   cleanMigrationFingerprint(predecessor.Fingerprint),
	}}, nil
}

// migrationIssuingAuthority picks the authority that signs successors for a
// run whose new authority is the given one (A36).
//
// A signer-backed authority issues for itself. An imported offline root has no
// signer handle, so it can be the anchor but never the issuer; the run then
// issues under the root's one active signer-backed intermediate, imported
// through the offline-intermediate ceremony. Two such intermediates make the
// choice an operator's, not a guess: they name the issuing intermediate
// instead, which also makes that intermediate the distributed anchor. An
// intermediate without a signer key, or any inactive authority, cannot issue.
func migrationIssuingAuthority(authority store.CAAuthority, authorities []store.CAAuthority) (store.CAAuthority, error) {
	if authority.Status != "active" {
		return store.CAAuthority{}, errors.New("new_authority_id must name an active CA authority in this tenant")
	}
	if strings.TrimSpace(authority.SignerHandle) != "" {
		return authority, nil
	}
	if authority.Kind != "root" {
		return store.CAAuthority{}, errors.New("new_authority_id names an intermediate with no signer key; only a signer-backed authority or an imported offline root with a signer-backed intermediate can issue successors")
	}
	var issuers []store.CAAuthority
	for _, candidate := range authorities {
		if candidate.Status != "active" || strings.TrimSpace(candidate.SignerHandle) == "" ||
			candidate.ParentID == nil || *candidate.ParentID != authority.ID {
			continue
		}
		issuers = append(issuers, candidate)
	}
	switch len(issuers) {
	case 0:
		return store.CAAuthority{}, errors.New("new_authority_id names an offline root with no active signer-backed intermediate; import one through the offline-intermediate ceremony before migrating to this root")
	case 1:
		return issuers[0], nil
	default:
		return store.CAAuthority{}, errors.New("new_authority_id names an offline root with more than one active signer-backed intermediate; name the issuing intermediate as the new authority instead")
	}
}

// migrationMemberSubject freezes what the successor may certify from the
// predecessor's identifiers (A35). DNS names and IP addresses are the two
// kinds a host listener binding can express; an rfc822Name or URI predecessor
// is refused rather than silently narrowed, because the successor would stop
// asserting an identity some client relies on. The common name follows the
// first DNS name, else the first address, so the name set the host may request
// is exactly the set the binding carries.
func migrationMemberSubject(info certinfo.Info) (commonName string, dnsNames, ipAddresses []string, err error) {
	if len(info.EmailAddresses) > 0 || len(info.URIs) > 0 {
		return "", nil, nil, errors.New("migration member predecessor must carry DNS or IP identifiers only")
	}
	seen := map[string]bool{}
	for _, name := range info.DNSNames {
		name = strings.TrimSpace(name)
		if key := strings.ToLower(name); name != "" && !seen[key] {
			seen[key] = true
			dnsNames = append(dnsNames, name)
		}
	}
	for _, raw := range info.IPAddresses {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			return "", nil, nil, errors.New("migration member predecessor carries an unreadable IP address")
		}
		if key := ip.String(); !seen["ip:"+key] {
			seen["ip:"+key] = true
			ipAddresses = append(ipAddresses, key)
		}
	}
	switch {
	case len(dnsNames) > 0:
		commonName = dnsNames[0]
	case len(ipAddresses) > 0:
		commonName = ipAddresses[0]
	default:
		return "", nil, nil, errors.New("migration member predecessor carries no DNS name or IP address")
	}
	return commonName, dnsNames, ipAddresses, nil
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
