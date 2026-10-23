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

const (
	nhiPostureAutomationActor          = "system:nhi-posture"
	nhiPostureAutomationPerTenantLimit = 25
	// A refused automatic revoke is retried after this long, so a tenant
	// under dual control is not re-evaluated (and re-audited) every sweep.
	nhiPostureRefusalBackoff = 24 * time.Hour

	nhiPostureActionRevoke        = "revoke"
	nhiPostureActionRightSize     = "right_size"
	nhiPostureActionReportOnly    = "report_only"
	nhiPostureActionNotApplicable = "not_applicable"
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
	Violations    int `json:"violations"`
	Revoke        int `json:"revoke"`
	RightSize     int `json:"right_size"`
	ReportOnly    int `json:"report_only"`
	NotApplicable int `json:"not_applicable"`
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
	// report_only (the rule asks for nothing it recognizes) or
	// not_applicable (the row cannot take the remediation; Detail says why).
	Action  string                   `json:"action"`
	Detail  string                   `json:"detail,omitempty"`
	LastRun *nhiPostureAutomationRun `json:"last_run,omitempty"`
}

// nhiPostureAutomationRun is the latest automatic playbook run for one row
// and rule.
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
	Refused    int
	Skipped    int
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
// input.nhi object. ok is false when no family fired for the row.
func nhiPostureFactsForItem(item nhiInventoryItem, now time.Time) (policy.NHIFacts, nhiPostureFamilies, bool) {
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
		merge("exposure", f.Severity, f.RiskScore, f.FindingTypes, f.OwnerStatus)
	}
	sort.Strings(facts.FindingTypes)
	return facts, families, len(facts.Posture) > 0
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
		Coverage:            []string{"nhi_posture_rules", "revoke", "right_size", "lifecycle_gate", "playbook_evidence"},
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
	for _, item := range inventory.Items {
		facts, families, ok := nhiPostureFactsForItem(item, now)
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
			planned := nhiPostureAutomationItem{
				InventoryID: item.ID, DisplayName: item.DisplayName, Kind: item.Kind, Status: item.Status,
				Posture: facts.Posture, Rule: v.Rule, Severity: v.Severity, Reason: v.Reason,
				Remediation: v.Remediation, Action: action, Detail: detail,
				LastRun: lastRuns[nhiPostureRunKey(item.ID, v.Rule)],
			}
			out.Items = append(out.Items, planned)
			out.Summary.Violations++
			switch action {
			case nhiPostureActionRevoke:
				out.Summary.Revoke++
			case nhiPostureActionRightSize:
				out.Summary.RightSize++
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
		if result.Revoked+result.RightSized+result.Refused >= nhiPostureAutomationPerTenantLimit {
			break
		}
		var err error
		switch item.Action {
		case nhiPostureActionRevoke:
			err = a.automaticNHIRevoke(ctx, tenantID, plan.PolicyModuleSHA256, item, now, &result)
		case nhiPostureActionRightSize:
			err = a.automaticNHIRightSize(ctx, tenantID, plan.PolicyModuleSHA256, item, plan.families[item.InventoryID], now, &result)
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
