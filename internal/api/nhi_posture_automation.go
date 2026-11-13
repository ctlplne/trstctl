// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

// Automatic NHI posture actions (A100).
//
// A tenant's lifecycle module may declare nhi_posture rules over one NHI
// inventory row's merged posture (input.nhi). A rule may ask for one of two
// remediations: "revoke" a managed identity, through the same lifecycle gate
// as the identity's own revoke, or "right_size" a row's usage-backed unused
// grants, through the right-size playbook's connector intent. The leader's
// lifecycle sweep acts on them under the automation switch and maintenance
// deferral, bounded per tenant per sweep. Every action, and every gate
// refusal, is a remediation playbook run created by system:nhi-posture with
// the rule in its reason and the module digest in its evidence. A rule that
// asks for nothing, or for anything else, is reported in the plan and never
// acted on. GET /api/v1/nhi/posture/automation shows the plan.
//
// A rule may also ask to "revoke_oauth_grant" or "block_oauth_app" for a
// discovered OAuth grant (A170-L3), so a detection is acted on without an
// operator: the sweep queues the same durable request and control-plane
// outbox row the operator's revoke or block queues, after the same checks,
// and the finding records it with actor system:nhi-posture. An abusive grant
// discovery detected (malicious_oauth_grant) is posture family oauth_abuse.

const (
	nhiPostureAutomationActor          = "system:nhi-posture"
	nhiPostureAutomationPerTenantLimit = 25
	// A refused automatic revoke is retried after this long, so a tenant
	// under dual control is not re-evaluated (and re-audited) every sweep.
	nhiPostureRefusalBackoff = 24 * time.Hour

	nhiPostureActionRevoke           = "revoke"
	nhiPostureActionRightSize        = "right_size"
	nhiPostureActionRevokeOAuthGrant = "revoke_oauth_grant"
	nhiPostureActionBlockOAuthApp    = "block_oauth_app"
	nhiPostureActionReportOnly       = "report_only"
	nhiPostureActionNotApplicable    = "not_applicable"

	// nhiPostureOAuthAbuseDetection is the detection an abusive OAuth grant
	// finding carries (CAP-ITDR-03).
	nhiPostureOAuthAbuseDetection = "malicious_oauth_grant"
)

// NHIPosturePolicyEvaluator is the NHI half of the live engine's posture seam.
type NHIPosturePolicyEvaluator interface {
	EvaluateNHIPosture(ctx context.Context, in policy.Input) ([]policy.PostureViolation, error)
	ActiveModule(ctx context.Context, tenantID string) (string, policy.ModuleInfo, error)
}

type nhiPostureAutomationResponse struct {
	Capability             string                        `json:"capability"`
	GeneratedAt            time.Time                     `json:"generated_at"`
	Coverage               []string                      `json:"coverage"`
	PolicyModuleSHA256     string                        `json:"policy_module_sha256,omitempty"`
	PolicyEvaluated        int                           `json:"policy_evaluated"`
	PolicyEvaluationErrors int                           `json:"policy_evaluation_errors"`
	Summary                nhiPostureAutomationSummary   `json:"summary"`
	Items                  []nhiPostureAutomationItem    `json:"items"`
	EvidenceRefs           []string                      `json:"evidence_refs"`
	PerTenantSweepLimit    int                           `json:"per_tenant_sweep_limit"`
	families               map[string]nhiPostureFamilies `json:"-"`
}

type nhiPostureAutomationSummary struct {
	Violations       int `json:"violations"`
	Revoke           int `json:"revoke"`
	RightSize        int `json:"right_size"`
	RevokeOAuthGrant int `json:"revoke_oauth_grant"`
	BlockOAuthApp    int `json:"block_oauth_app"`
	ReportOnly       int `json:"report_only"`
	NotApplicable    int `json:"not_applicable"`
}

type nhiPostureAutomationItem struct {
	InventoryID string   `json:"inventory_id"`
	DisplayName string   `json:"display_name"`
	Kind        string   `json:"kind"`
	Status      string   `json:"status"`
	Posture     []string `json:"posture"`
	Rule        string   `json:"rule"`
	Severity    string   `json:"severity,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	// Remediation is what the rule asked for, from the closed set.
	Remediation string `json:"remediation,omitempty"`
	// Action is what the sweep does with it: revoke, right_size,
	// revoke_oauth_grant, block_oauth_app, report_only (the rule asks for
	// nothing it recognizes) or not_applicable (the row cannot take the
	// remediation; Detail says why).
	Action  string                   `json:"action"`
	Detail  string                   `json:"detail,omitempty"`
	LastRun *nhiPostureAutomationRun `json:"last_run,omitempty"`
}

// nhiPostureAutomationRun is the latest automatic playbook run for one row
// and rule. For an OAuth remediation it is the finding's latest provider
// action of that kind, whoever asked for it: ID is the request, Status its
// queued/confirmed/already_absent/failed state and CreatedAt when that state
// was recorded.
type nhiPostureAutomationRun struct {
	ID         string    `json:"id"`
	PlaybookID string    `json:"playbook_id"`
	Status     string    `json:"status"`
	Phase      string    `json:"phase"`
	CreatedAt  time.Time `json:"created_at"`
}

// nhiPostureFamilies holds the posture families that fired for one row.
type nhiPostureFamilies struct {
	overprivilege *nhiOverPrivilegeFinding
}

// NHIPostureAutomationResult counts one tenant sweep's automatic actions.
type NHIPostureAutomationResult struct {
	Revoked    int
	RightSized int
	// OAuthQueued counts OAuth grant revokes and app blocks queued at the
	// provider (A170-L3).
	OAuthQueued int
	Refused     int
	Skipped     int
}

func (a *API) listNHIPostureAutomation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := a.nhiPostureAutomationPlan(r.Context(), tenantID, time.Now().UTC())
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

// nhiPostureFactsForItem merges one inventory row's posture families into the
// input.nhi object. ok is false when no family fired for the row. attackPath is
// the row's latest provider-native validation, if any (A167-L3): an open one
// raises the exposure family as it does in the exposure posture.
func nhiPostureFactsForItem(item nhiInventoryItem, now time.Time, attackPath *nhiExposureAttackPath) (policy.NHIFacts, nhiPostureFamilies, bool) {
	facts := policy.NHIFacts{
		InventoryID: item.ID, Kind: item.Kind, Source: item.Source, DisplayName: item.DisplayName,
		OwnerID: item.OwnerID, Status: item.Status, Managed: strings.HasPrefix(item.ID, "identity/"),
		Posture: []string{}, FindingTypes: []string{},
	}
	var families nhiPostureFamilies
	types := map[string]bool{}
	merge := func(family, severity string, risk int, findingTypes []string, ownerStatus string) {
		facts.Posture = append(facts.Posture, family)
		for _, typ := range findingTypes {
			if !types[typ] {
				types[typ] = true
				facts.FindingTypes = append(facts.FindingTypes, typ)
			}
		}
		if severityRank(severity) > severityRank(facts.Severity) {
			facts.Severity = severity
		}
		if risk > facts.RiskScore {
			facts.RiskScore = risk
		}
		if facts.OwnerStatus == "" {
			facts.OwnerStatus = ownerStatus
		}
	}
	if f, ok := nhiOverPrivilegeForItem(item); ok {
		finding := f
		families.overprivilege = &finding
		merge("overprivilege", f.Severity, f.RiskScore, f.FindingTypes, "")
		facts.GrantedScopes, facts.UnusedScopes, facts.RecommendedScopes = f.GrantedScopes, f.UnusedScopes, f.RecommendedScopes
	}
	if f, ok := nhiStaleFindingForItem(item, now); ok {
		merge("stale", f.Severity, f.RiskScore, f.FindingTypes, f.OwnerStatus)
		facts.ActivityAgeDays = f.ActivityAgeDays
	}
	if f, ok := nhiStaticFindingForItem(item, now); ok {
		merge("static_credentials", f.Severity, f.RiskScore, f.FindingTypes, f.OwnerStatus)
		facts.CredentialAgeDays, facts.RotationAgeDays = f.CredentialAgeDays, f.RotationAgeDays
	}
	if f, ok := nhiExposureFindingForItem(item); ok {
		nhiExposureApplyAttackPath(&f, attackPath)
		merge("exposure", f.Severity, f.RiskScore, f.FindingTypes, f.OwnerStatus)
	}
	if findingTypes, ok := nhiOAuthAbuseForItem(item); ok {
		merge("oauth_abuse", nhiOAuthAbuseSeverity(item.RiskScore), item.RiskScore, findingTypes, "")
	}
	if nhiPostureOAuthGrantRow(facts) {
		facts.Provider = metadataString(decodeNHIInventoryMetadata(item.Metadata), "provider")
	}
	sort.Strings(facts.FindingTypes)
	return facts, families, len(facts.Posture) > 0
}

// nhiOAuthAbuseForItem reports a discovered OAuth grant the detector judged
// abusive (A170-L3): its finding types are the detection and its reasons, so
// a rule can act when the detection lands.
func nhiOAuthAbuseForItem(item nhiInventoryItem) ([]string, bool) {
	if item.Source != "discovery_finding" {
		return nil, false
	}
	meta := decodeNHIInventoryMetadata(item.Metadata)
	if metadataString(meta, "detection_kind") != nhiPostureOAuthAbuseDetection {
		return nil, false
	}
	return append([]string{nhiPostureOAuthAbuseDetection}, readNHIPostureStrings(meta["abuse_reasons"])...), true
}

// nhiOAuthAbuseSeverity grades an abusive grant by the detector's risk score.
func nhiOAuthAbuseSeverity(risk int) string {
	switch {
	case risk >= 90:
		return "critical"
	case risk >= 70:
		return "high"
	case risk >= 45:
		return "medium"
	default:
		return "low"
	}
}

// nhiPostureOAuthGrantRow is true for a discovery finding row that may name
// an OAuth grant; the operator's own checks decide whether it does.
func nhiPostureOAuthGrantRow(facts policy.NHIFacts) bool {
	return strings.HasPrefix(facts.InventoryID, "finding/") && (facts.Kind == "oauth_app" || facts.Kind == "oauth_grant_abuse")
}

// nhiPostureOAuthProviderAction maps an OAuth remediation to the provider
// action the operator's routes queue.
func nhiPostureOAuthProviderAction(action string) string {
	if action == nhiPostureActionBlockOAuthApp {
		return orchestrator.OAuthActionBlockApp
	}
	return orchestrator.OAuthActionRevokeGrant
}

// nhiPostureActionFor decides what the sweep does with one violation.
func nhiPostureActionFor(remediation string, facts policy.NHIFacts, families nhiPostureFamilies) (string, string) {
	switch remediation {
	case policy.PostureRemediationRevoke:
		if !facts.Managed {
			return nhiPostureActionNotApplicable, "revoke acts only on a managed identity; claim the finding to a managed identity first"
		}
		if !incidentRevocable(orchestrator.State(facts.Status)) {
			return nhiPostureActionNotApplicable, "revoke acts only on an issued, deployed, renewing or renewal_failed identity"
		}
		return nhiPostureActionRevoke, ""
	case policy.PostureRemediationRightSize:
		if families.overprivilege == nil || len(families.overprivilege.UnusedScopes) == 0 {
			return nhiPostureActionNotApplicable, "right_size needs usage-backed unused grants (CAP-POST-01)"
		}
		return nhiPostureActionRightSize, ""
	case policy.PostureRemediationRevokeOAuthGrant, policy.PostureRemediationBlockOAuthApp:
		if !nhiPostureOAuthGrantRow(facts) {
			return nhiPostureActionNotApplicable, remediation + " acts only on a discovered OAuth grant (an oauth_grant or oauth_grant_abuse finding)"
		}
		if remediation == policy.PostureRemediationBlockOAuthApp {
			return nhiPostureActionBlockOAuthApp, ""
		}
		return nhiPostureActionRevokeOAuthGrant, ""
	default:
		return nhiPostureActionReportOnly, ""
	}
}

// nhiPostureAutomationPlan evaluates the tenant's nhi_posture rules over the
// NHI inventory. Without a live policy engine or an active module it reports
// nothing, so automation is opt-in through the module itself.
func (a *API) nhiPostureAutomationPlan(ctx context.Context, tenantID string, now time.Time) (nhiPostureAutomationResponse, error) {
	out := nhiPostureAutomationResponse{
		Capability: "CAP-POST-06", GeneratedAt: now,
		Coverage:            []string{"nhi_posture_rules", "revoke", "right_size", "oauth_provider_action", "lifecycle_gate", "playbook_evidence"},
		Items:               []nhiPostureAutomationItem{},
		EvidenceRefs:        []string{"projection:nhi_inventory", "projection:remediation_playbook_runs"},
		PerTenantSweepLimit: nhiPostureAutomationPerTenantLimit,
		families:            map[string]nhiPostureFamilies{},
	}
	evaluator, _ := a.gate.Policy.(NHIPosturePolicyEvaluator)
	if evaluator == nil {
		return out, nil
	}
	_, info, err := evaluator.ActiveModule(ctx, tenantID)
	if err != nil {
		out.PolicyEvaluationErrors++
		return out, nil
	}
	out.PolicyModuleSHA256 = info.ModuleSHA256
	out.EvidenceRefs = append(out.EvidenceRefs, "policy:module:"+info.ModuleSHA256)
	inventory, err := a.nhiInventory(ctx, tenantID)
	if err != nil {
		return nhiPostureAutomationResponse{}, err
	}
	lastRuns, err := a.nhiPostureAutomaticRuns(ctx, tenantID)
	if err != nil {
		return nhiPostureAutomationResponse{}, err
	}
	attackPaths, _, err := a.nhiExposureAttackPathsByInventory(ctx, tenantID)
	if err != nil {
		return nhiPostureAutomationResponse{}, err
	}
	for _, item := range inventory.Items {
		facts, families, ok := nhiPostureFactsForItem(item, now, attackPaths[item.ID])
		if !ok {
			continue
		}
		violations, err := evaluator.EvaluateNHIPosture(ctx, policy.Input{
			Action: policy.ActionNHIPosture, TenantID: tenantID, Subject: item.ID, NHI: &facts,
		})
		if err != nil {
			// A rule that cannot be evaluated acts on nothing; the plan counts it.
			out.PolicyEvaluationErrors++
			continue
		}
		out.PolicyEvaluated++
		for _, v := range violations {
			action, detail := nhiPostureActionFor(v.Remediation, facts, families)
			lastRun := lastRuns[nhiPostureRunKey(item.ID, v.Rule)]
			if action == nhiPostureActionRevokeOAuthGrant || action == nhiPostureActionBlockOAuthApp {
				action, detail, lastRun, err = a.nhiPostureOAuthPlan(ctx, tenantID, item, action)
				if err != nil {
					return nhiPostureAutomationResponse{}, err
				}
			}
			planned := nhiPostureAutomationItem{
				InventoryID: item.ID, DisplayName: item.DisplayName, Kind: item.Kind, Status: item.Status,
				Posture: facts.Posture, Rule: v.Rule, Severity: v.Severity, Reason: v.Reason,
				Remediation: v.Remediation, Action: action, Detail: detail, LastRun: lastRun,
			}
			out.Items = append(out.Items, planned)
			out.Summary.Violations++
			switch action {
			case nhiPostureActionRevoke:
				out.Summary.Revoke++
			case nhiPostureActionRightSize:
				out.Summary.RightSize++
			case nhiPostureActionRevokeOAuthGrant:
				out.Summary.RevokeOAuthGrant++
			case nhiPostureActionBlockOAuthApp:
				out.Summary.BlockOAuthApp++
			case nhiPostureActionReportOnly:
				out.Summary.ReportOnly++
			default:
				out.Summary.NotApplicable++
			}
		}
		out.families[item.ID] = families
	}
	sort.SliceStable(out.Items, func(i, j int) bool {
		a, b := out.Items[i], out.Items[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) > severityRank(b.Severity)
		}
		if a.InventoryID != b.InventoryID {
			return a.InventoryID < b.InventoryID
		}
		return a.Rule < b.Rule
	})
	return out, nil
}

func nhiPostureRunKey(inventoryID, rule string) string { return inventoryID + "\x00" + rule }

// nhiPostureOAuthPlan checks an OAuth remediation as the operator's own
// revoke or block is checked (A170-L3) — the finding names an OAuth grant,
// its provider has a served admin API that can take the action, and the
// source that found it holds an admin connection — and reads the finding's
// latest provider action of that kind. A row that cannot take it is
// not_applicable with the operator's own reason.
func (a *API) nhiPostureOAuthPlan(ctx context.Context, tenantID string, item nhiInventoryItem, action string) (string, string, *nhiPostureAutomationRun, error) {
	providerAction := nhiPostureOAuthProviderAction(action)
	if _, err := a.oauthProviderActionIntent(ctx, tenantID, strings.TrimPrefix(item.ID, "finding/"), providerAction, ""); err != nil {
		if detail, refused := nhiPostureOAuthRefusal(err); refused {
			return nhiPostureActionNotApplicable, detail, nil, nil
		}
		return "", "", nil, err
	}
	return action, "", nhiPostureOAuthLastRun(item, providerAction), nil
}

// nhiPostureOAuthRefusal reports the operator check that refused an OAuth
// action (a conflict or a finding that is gone), as opposed to a failure.
func nhiPostureOAuthRefusal(err error) (string, bool) {
	var refused *apiError
	if errors.As(err, &refused) && refused.cause == nil &&
		(refused.status == http.StatusConflict || refused.status == http.StatusNotFound) {
		return refused.detail, true
	}
	return "", false
}

// nhiPostureOAuthLastRun is the finding's latest provider action of one
// kind, as the finding records it.
func nhiPostureOAuthLastRun(item nhiInventoryItem, providerAction string) *nhiPostureAutomationRun {
	actions, _ := decodeNHIInventoryMetadata(item.Metadata)["provider_actions"].(map[string]any)
	state, _ := actions[providerAction].(map[string]any)
	if state == nil {
		return nil
	}
	at, _ := time.Parse(time.RFC3339Nano, metadataString(state, "updated_at"))
	return &nhiPostureAutomationRun{ID: metadataString(state, "request_id"), Status: metadataString(state, "status"),
		Phase: providerAction, CreatedAt: at}
}

// nhiPostureAutomaticRuns indexes the latest automatic run per row and rule.
// The rule is carried in the run's evidence as nhi_posture_rule:<rule>.
func (a *API) nhiPostureAutomaticRuns(ctx context.Context, tenantID string) (map[string]*nhiPostureAutomationRun, error) {
	latest := map[string]*nhiPostureAutomationRun{}
	for _, playbook := range []string{remediationPlaybookRevokeIdentity, remediationPlaybookRightSizeNHI} {
		rows, err := a.store.ListRemediationPlaybookRunsPage(ctx, tenantID, playbook, store.ZeroUUID, 500)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if row.CreatedBy != nhiPostureAutomationActor {
				continue
			}
			rule := ""
			for _, ref := range row.EvidenceRefs {
				if after, ok := strings.CutPrefix(ref, "nhi_posture_rule:"); ok {
					rule = after
				}
			}
			key := nhiPostureRunKey(row.InventoryID, rule)
			if prev := latest[key]; prev == nil || row.CreatedAt.After(prev.CreatedAt) {
				latest[key] = &nhiPostureAutomationRun{ID: row.ID, PlaybookID: row.PlaybookID, Status: row.Status,
					Phase: row.Phase, CreatedAt: row.CreatedAt}
			}
		}
	}
	return latest, nil
}

// nhiPostureAutomationPrincipal is the actor automatic actions run as. It
// holds what the routes require (certs:issue for the gate's RA separation);
// the tenant's own module authorized it by declaring the rule, the gate's
// policy and ABAC overlay still see actor system:nhi-posture, and dual
// control refuses it, since an automatic action carries no exact approval.
func nhiPostureAutomationPrincipal(tenantID string) authz.Principal {
	return authz.Principal{TenantID: tenantID, Subject: nhiPostureAutomationActor, Grants: []authz.Grant{{
		Role: authz.Role{Name: "nhi-posture-automation", Permissions: []authz.Permission{
			authz.CertsIssue, authz.IdentitiesWrite, authz.IncidentsWrite}},
		Scope: authz.Scope{TenantID: tenantID},
	}}}
}

// RunNHIPostureAutomation acts on the tenant's nhi_posture remediations, at
// most nhiPostureAutomationPerTenantLimit per call. The leader's lifecycle
// sweep calls it under the automation switch and maintenance deferral.
func (a *API) RunNHIPostureAutomation(ctx context.Context, tenantID string, now time.Time) (NHIPostureAutomationResult, error) {
	var result NHIPostureAutomationResult
	if a.orch == nil || a.store == nil {
		return result, nil
	}
	plan, err := a.nhiPostureAutomationPlan(ctx, tenantID, now)
	if err != nil {
		return result, err
	}
	var errs []error
	for _, item := range plan.Items {
		if result.Revoked+result.RightSized+result.OAuthQueued+result.Refused >= nhiPostureAutomationPerTenantLimit {
			break
		}
		var err error
		switch item.Action {
		case nhiPostureActionRevoke:
			err = a.automaticNHIRevoke(ctx, tenantID, plan.PolicyModuleSHA256, item, now, &result)
		case nhiPostureActionRightSize:
			err = a.automaticNHIRightSize(ctx, tenantID, plan.PolicyModuleSHA256, item, plan.families[item.InventoryID], now, &result)
		case nhiPostureActionRevokeOAuthGrant, nhiPostureActionBlockOAuthApp:
			err = a.automaticNHIOAuthAction(ctx, tenantID, plan.PolicyModuleSHA256, item, now, &result)
		default:
			continue
		}
		if err != nil {
			// One row's failure must not stall the rest of the tenant.
			errs = append(errs, err)
		}
	}
	return result, errors.Join(errs...)
}

func nhiPostureEvidence(item nhiPostureAutomationItem, moduleSHA string) []string {
	return []string{"inventory:" + item.InventoryID, "nhi_posture_rule:" + item.Rule, "policy:module:" + moduleSHA}
}

func nhiPostureRunReason(item nhiPostureAutomationItem) string {
	reason := "posture:" + item.Rule
	if item.Reason != "" {
		reason += ": " + item.Reason
	}
	return reason
}

// automaticNHIRevoke revokes a managed identity a rule asked to revoke,
// through the lifecycle gate, with RFC 5280 cessationOfOperation.
func (a *API) automaticNHIRevoke(ctx context.Context, tenantID, moduleSHA string, item nhiPostureAutomationItem, now time.Time, result *NHIPostureAutomationResult) error {
	if last := item.LastRun; last != nil && last.Status == "refused" && now.Sub(last.CreatedAt) < nhiPostureRefusalBackoff {
		result.Skipped++
		return nil
	}
	identityID := strings.TrimPrefix(item.InventoryID, "identity/")
	principal := nhiPostureAutomationPrincipal(tenantID)
	evidence := nhiPostureEvidence(item, moduleSHA)
	if err := a.gateOperatorTransition(ctx, principal, tenantID, identityID, orchestrator.StateRevoked); err != nil {
		detail, refused := operatorGateRefusal(err)
		if !refused {
			return err
		}
		_, recErr := a.orch.RecordRemediationPlaybookRun(ctx, tenantID, store.RemediationPlaybookRun{
			PlaybookID: remediationPlaybookRevokeIdentity, TargetIdentityID: identityID, InventoryID: item.InventoryID,
			Status: "refused", Phase: "lifecycle_gate_refused", Action: "revoke",
			Reason: nhiPostureRunReason(item) + " (refused: " + detail + ")", ScopeDelta: json.RawMessage(`{}`),
			EvidenceRefs:   evidence,
			IdempotencyKey: "nhi-posture:revoke-refused:" + identityID + ":" + item.Rule + ":" + now.Format("2006-01-02T15"),
			CreatedBy:      nhiPostureAutomationActor,
		}, "")
		if recErr != nil {
			return recErr
		}
		result.Refused++
		return nil
	}
	revocationReason := string(crypto.RevocationReasonCessationOfOperation)
	if err := a.orch.Transition(ctx, tenantID, identityID, orchestrator.StateRevoked, revocationReason); err != nil {
		if errors.Is(err, orchestrator.ErrInvalidTransition) {
			// Revoked or moved on since the plan was read.
			result.Skipped++
			return nil
		}
		return err
	}
	if _, err := a.orch.RecordRemediationPlaybookRun(ctx, tenantID, store.RemediationPlaybookRun{
		PlaybookID: remediationPlaybookRevokeIdentity, TargetIdentityID: identityID, InventoryID: item.InventoryID,
		Status: "executed", Phase: "identity_revoked", Action: "revoke", Reason: nhiPostureRunReason(item),
		ScopeDelta:     json.RawMessage(`{}`),
		EvidenceRefs:   append(evidence, "identity:"+identityID, "revocation_reason:"+revocationReason),
		IdempotencyKey: "nhi-posture:revoke:" + identityID + ":" + item.Rule,
		CreatedBy:      nhiPostureAutomationActor,
	}, ""); err != nil {
		return err
	}
	result.Revoked++
	return nil
}

// automaticNHIRightSize queues the right-size playbook's connector intent
// for the row's usage-backed unused grants. The run's key binds the row, the
// rule and the exact scopes, so the same posture is queued once.
func (a *API) automaticNHIRightSize(ctx context.Context, tenantID, moduleSHA string, item nhiPostureAutomationItem, families nhiPostureFamilies, now time.Time, result *NHIPostureAutomationResult) error {
	if families.overprivilege == nil {
		result.Skipped++
		return nil
	}
	scopes := canonicalRightSizeScopes(families.overprivilege.UnusedScopes)
	key := "nhi-posture:right-size:" + crypto.SHA256Hex([]byte(item.InventoryID+"\x00"+item.Rule+"\x00"+strings.Join(scopes, "\x00")))
	if last := item.LastRun; last != nil && last.PlaybookID == remediationPlaybookRightSizeNHI &&
		last.ID == orchestrator.ConnectorRightSizeIdentityFor(tenantID, key).OperationID {
		result.Skipped++
		return nil
	}
	principal := nhiPostureAutomationPrincipal(tenantID)
	// No explicit selection: the playbook removes exactly the usage-backed
	// unused grants the key above binds.
	req := remediationPlaybookRunRequest{InventoryID: item.InventoryID, Reason: nhiPostureRunReason(item)}
	run, err := a.prepareRightSizePlaybook(ctx, tenantID, principal, req, key)
	if err != nil {
		return err
	}
	binding, err := json.Marshal(struct {
		Domain  string                        `json:"domain"`
		Actor   string                        `json:"actor"`
		Command remediationPlaybookRunRequest `json:"command"`
	}{"trstctl.nhi-posture.right-size.v1", nhiPostureAutomationActor, canonicalRightSizePlaybookCommand(req)})
	if err != nil {
		return err
	}
	run.TenantID = tenantID
	run.RequestBinding = crypto.SHA256Hex(binding)
	run.EvidenceRefs = append(run.EvidenceRefs, nhiPostureEvidence(item, moduleSHA)...)
	run.InitialHTTPStatus = http.StatusCreated
	run.CreatedAt, run.UpdatedAt = now, now
	initial, err := json.Marshal(a.initialRightSizeRunResponse(ctx, tenantID, run))
	if err != nil {
		return err
	}
	run.InitialResponse = initial
	if _, err := a.orch.RecordConnectorRightSizeOperation(ctx, tenantID, run); err != nil {
		return err
	}
	result.RightSized++
	return nil
}

// automaticNHIOAuthAction queues at the provider the OAuth action a rule
// asked for (A170-L3): the same durable request and control-plane outbox row
// the operator's revoke or block queues, after the same checks, recorded on
// the finding with actor system:nhi-posture and a reason naming the rule and
// the module. A grant whose action is already queued or settled is left
// alone, whoever asked; a failed one is asked again after the refusal
// back-off, as a new request. The request key binds the finding, the action,
// the rule, the module and the attempt, so a retried sweep converges.
func (a *API) automaticNHIOAuthAction(ctx context.Context, tenantID, moduleSHA string, item nhiPostureAutomationItem, now time.Time, result *NHIPostureAutomationResult) error {
	attempt := "first"
	if last := item.LastRun; last != nil {
		if last.Status != orchestrator.OAuthActionFailed || now.Sub(last.CreatedAt) < nhiPostureRefusalBackoff {
			result.Skipped++
			return nil
		}
		attempt = "after:" + last.ID
	}
	findingID := strings.TrimPrefix(item.InventoryID, "finding/")
	providerAction := nhiPostureOAuthProviderAction(item.Action)
	intent, err := a.oauthProviderActionIntent(ctx, tenantID, findingID, providerAction,
		nhiPostureRunReason(item)+" ("+strings.Join(nhiPostureEvidence(item, moduleSHA), ", ")+")")
	if err != nil {
		if _, refused := nhiPostureOAuthRefusal(err); refused {
			// The finding or its source changed since the plan was read.
			result.Skipped++
			return nil
		}
		return err
	}
	requestKey := "nhi-posture:oauth:" + crypto.SHA256Hex([]byte(findingID+"\x00"+providerAction+"\x00"+item.Rule+"\x00"+moduleSHA+"\x00"+attempt))
	if _, err := a.orch.QueueOAuthProviderAction(ctx, tenantID, requestKey, nhiPostureAutomationActor, intent); err != nil {
		return err
	}
	result.OAuthQueued++
	return nil
}
