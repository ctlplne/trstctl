// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Reviewed configuration change sets (A248). A change set is a typed set of
// objects a tenant should hold: certificate profiles and CA bindings, connector
// targets, member role grants, and owners with their application model. It is
// authored by form, API or GitOps (`trstctl changes plan|apply -f`), and every
// author's set goes through the same plan.
//
// Planning checks each object as the operator's own request for it is checked,
// refuses a malformed or over-broad set and one that carries a secret value,
// checks the caller may write every object, and lists per object exactly what
// applying it would do: the identities, credentials, grants, destinations,
// approvals and events involved, and how the result is verified. The plan
// digest binds the set's objects and each one's current revision, so applying
// needs the digest and refuses a plan the tenant has moved past. Applying
// writes each object through the command the operator's request takes, then
// reads it back.

// changeSetScope keeps a change set's keyed objects apart from a tenant
// baseline's in the same tenant.
const changeSetScope = "change-set"

// maxChangeSetObjects bounds one change set; a larger change is split.
const maxChangeSetObjects = 200

// ChangeKindOwner is an owner object in a change set.
const ChangeKindOwner = "owner"

// Plan actions.
const (
	ChangeCreate    = "create"
	ChangeUpdate    = "update"
	ChangeUnchanged = "unchanged"
)

// ChangeSet is the typed set of objects a tenant should hold. Its name and
// description label the review; they are not part of its digest.
type ChangeSet struct {
	Name              string                     `json:"name"`
	Description       string                     `json:"description,omitempty"`
	Profiles          []BaselineProfile          `json:"profiles,omitempty"`
	Issuers           []BaselineIssuer           `json:"issuers,omitempty"`
	DeploymentTargets []BaselineDeploymentTarget `json:"deployment_targets,omitempty"`
	Members           []BaselineMember           `json:"members,omitempty"`
	Owners            []ChangeOwner              `json:"owners,omitempty"`
}

// ChangeOwner is an owner and its application model. Key names it within
// change sets, so the same key always names the same owner.
type ChangeOwner struct {
	Key             string   `json:"key"`
	Kind            string   `json:"kind"`
	Name            string   `json:"name"`
	Email           string   `json:"email,omitempty"`
	ApplicationID   string   `json:"application_id,omitempty"`
	Service         string   `json:"service,omitempty"`
	BusinessUnit    string   `json:"business_unit,omitempty"`
	Environment     string   `json:"environment,omitempty"`
	EscalationChain []string `json:"escalation_chain,omitempty"`
}

// ChangePlanItem is what applying one object would do.
type ChangePlanItem struct {
	Kind           string   `json:"kind"`
	Key            string   `json:"key"`
	ObjectID       string   `json:"object_id,omitempty"`
	Action         string   `json:"action"`
	ExpectedDigest string   `json:"expected_digest"`
	ActualDigest   string   `json:"actual_digest,omitempty"`
	Detail         string   `json:"detail,omitempty"`
	Identities     []string `json:"identities"`
	Credentials    []string `json:"credentials"`
	Grants         []string `json:"grants"`
	Destinations   []string `json:"destinations"`
	Approvals      []string `json:"approvals"`
	Effects        []string `json:"effects"`
	Verification   string   `json:"verification"`
}

// ChangePlan is a reviewed change set's plan.
type ChangePlan struct {
	Name            string           `json:"name"`
	ChangeSetDigest string           `json:"change_set_digest"`
	PlanDigest      string           `json:"plan_digest"`
	Changes         int              `json:"changes"`
	Items           []ChangePlanItem `json:"items"`
}

// ChangeApplyRequest applies a change set as it was planned.
type ChangeApplyRequest struct {
	ChangeSet  ChangeSet `json:"change_set"`
	PlanDigest string    `json:"plan_digest"`
}

// ChangeApplyResult is what applying one object did, read back.
type ChangeApplyResult struct {
	Kind              string `json:"kind"`
	Key               string `json:"key"`
	ObjectID          string `json:"object_id,omitempty"`
	Outcome           string `json:"outcome"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
	Verified          bool   `json:"verified"`
	Error             string `json:"error,omitempty"`
}

// ChangeApplication is what applying a reviewed change set did.
type ChangeApplication struct {
	Name            string              `json:"name"`
	ChangeSetDigest string              `json:"change_set_digest"`
	PlanDigest      string              `json:"plan_digest"`
	Complete        bool                `json:"complete"`
	Results         []ChangeApplyResult `json:"results"`
}

// normalized is the set with each list in key order and each member's roles
// sorted, so the same intent written in any order plans the same.
func (cs ChangeSet) normalized() ChangeSet {
	out := cs
	out.Profiles = sortedBy(cs.Profiles, func(x BaselineProfile) string { return strings.TrimSpace(x.Name) })
	out.Issuers = sortedBy(cs.Issuers, func(x BaselineIssuer) string { return strings.TrimSpace(x.Key) })
	out.DeploymentTargets = sortedBy(cs.DeploymentTargets, func(x BaselineDeploymentTarget) string { return strings.TrimSpace(x.Key) })
	out.Members = sortedBy(cs.Members, func(x BaselineMember) string { return strings.TrimSpace(x.Subject) })
	for i := range out.Members {
		out.Members[i].Roles = append([]string(nil), out.Members[i].Roles...)
		sort.Strings(out.Members[i].Roles)
	}
	out.Owners = sortedBy(cs.Owners, func(x ChangeOwner) string { return strings.TrimSpace(x.Key) })
	return out
}

func sortedBy[T any](in []T, key func(T) string) []T {
	if in == nil {
		return nil
	}
	out := append([]T(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}

// ChangeSetDigest is the digest of a change set's objects — its intent — in
// key order. Its name and description are not part of it, so a form, an API
// call and a draft that ask for the same objects have the same digest.
func ChangeSetDigest(cs ChangeSet) string {
	n := cs.normalized()
	n.Name, n.Description = "", ""
	return baselineDigest(n)
}

func (cs ChangeSet) objects() int {
	return len(cs.Profiles) + len(cs.Issuers) + len(cs.DeploymentTargets) + len(cs.Members) + len(cs.Owners)
}

// validateChangeSet refuses a malformed or over-broad change set, and one that
// carries a secret value, before anything is read or written.
func (a *API) validateChangeSet(cs ChangeSet) error {
	switch n := cs.objects(); {
	case strings.TrimSpace(cs.Name) == "":
		return errStatus(http.StatusUnprocessableEntity, "a change set needs a name")
	case n == 0:
		return errStatus(http.StatusUnprocessableEntity, "the change set has no objects")
	case n > maxChangeSetObjects:
		return errStatus(http.StatusUnprocessableEntity, fmt.Sprintf("the change set names %d objects; split it into sets of at most %d", n, maxChangeSetObjects))
	}
	if err := a.ValidateTenantBaseline(TenantBaseline{Profiles: cs.Profiles, Issuers: cs.Issuers, DeploymentTargets: cs.DeploymentTargets, Members: cs.Members}); err != nil {
		return errStatusFrom(http.StatusUnprocessableEntity, err)
	}
	if err := distinctKeys("owner", len(cs.Owners), func(i int) string { return cs.Owners[i].Key }); err != nil {
		return errStatusFrom(http.StatusUnprocessableEntity, err)
	}
	for _, x := range cs.Owners {
		if err := orchestrator.ValidateOwnerRecord(changeOwnerRecord(x, "", "")); err != nil {
			return errStatusFrom(http.StatusUnprocessableEntity, fmt.Errorf("owner %s: %w", x.Key, err))
		}
	}
	if field, value := broadChangeName(cs); field != "" {
		return errStatus(http.StatusUnprocessableEntity, fmt.Sprintf("%s %q is a pattern; a change set names each object exactly", field, value))
	}
	if path, shape := changeSetSecret(cs); path != "" {
		return errStatus(http.StatusUnprocessableEntity, fmt.Sprintf("%s holds %s; a change set carries references and metadata, never secret values: name a stored secret instead", path, shape))
	}
	return nil
}

// broadChangeName is the first name, key, subject or role written as a pattern
// rather than one object.
func broadChangeName(cs ChangeSet) (string, string) {
	broad := func(v string) bool { return strings.ContainsAny(v, "*?[]") }
	for _, x := range cs.Profiles {
		if broad(x.Name) {
			return "profile name", x.Name
		}
	}
	for _, x := range cs.Issuers {
		for field, v := range map[string]string{"issuer key": x.Key, "issuer name": x.Name} {
			if broad(v) {
				return field, v
			}
		}
	}
	for _, x := range cs.DeploymentTargets {
		for field, v := range map[string]string{"deployment target key": x.Key, "deployment target name": x.Name} {
			if broad(v) {
				return field, v
			}
		}
	}
	for _, x := range cs.Members {
		if broad(x.Subject) {
			return "member subject", x.Subject
		}
		for _, role := range x.Roles {
			if broad(role) {
				return "member role", role
			}
		}
	}
	for _, x := range cs.Owners {
		for field, v := range map[string]string{"owner key": x.Key, "owner name": x.Name} {
			if broad(v) {
				return field, v
			}
		}
	}
	return "", ""
}

// secretFieldNames are field names that hold a secret's value; a field naming a
// stored secret ends in _ref instead.
var secretFieldNames = map[string]bool{
	"password": true, "passwd": true, "passphrase": true, "secret": true, "client_secret": true,
	"api_key": true, "apikey": true, "access_key": true, "secret_key": true, "private_key": true,
	"token": true, "auth_token": true, "access_token": true, "refresh_token": true, "session_token": true,
	"bearer": true, "credential": true, "credentials": true,
}

// changeSetSecret is the path of the first value in the set that is a secret —
// a field named for one, or a string holding a private key, token, credential
// or password — and what it holds. Certificates and public keys pass.
func changeSetSecret(cs ChangeSet) (string, string) {
	raw, err := json.Marshal(cs)
	if err != nil {
		return "change set", "an unreadable value"
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "change set", "an unreadable value"
	}
	return secretIn("change set", v)
}

func secretIn(path string, v any) (string, string) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if secretFieldNames[strings.ToLower(k)] {
				if s, ok := x[k].(string); !ok || s != "" {
					return path + "." + k, "a field for a secret value"
				}
			}
			if p, shape := secretIn(path+"."+k, x[k]); p != "" {
				return p, shape
			}
		}
	case []any:
		for i, item := range x {
			if p, shape := secretIn(fmt.Sprintf("%s[%d]", path, i), item); p != "" {
				return p, shape
			}
		}
	case string:
		if shape, ok := aimodel.StructuredSecret(x); ok {
			return path, shape
		}
	}
	return "", ""
}

func changeOwnerRecord(x ChangeOwner, tenantID, id string) store.Owner {
	chain, _ := json.Marshal(x.EscalationChain)
	if x.EscalationChain == nil {
		chain = []byte("[]")
	}
	return store.Owner{ID: id, TenantID: tenantID, Kind: store.OwnerKind(strings.TrimSpace(x.Kind)), Name: x.Name, Email: x.Email,
		ApplicationID: x.ApplicationID, Service: x.Service, BusinessUnit: x.BusinessUnit, Environment: x.Environment, EscalationChain: chain}
}

// ownerDigest is an owner's digest as a change set compares it. An owner
// stored without an escalation chain reads back as JSON null; it is the same
// empty chain a change set writes as [].
func ownerDigest(o store.Owner) string {
	chain := []any{}
	if len(o.EscalationChain) > 0 {
		var stored []any
		if json.Unmarshal(o.EscalationChain, &stored) == nil && stored != nil {
			chain = stored
		}
	}
	return baselineDigest(struct {
		Kind            string `json:"kind"`
		Name            string `json:"name"`
		Email           string `json:"email"`
		ApplicationID   string `json:"application_id"`
		Service         string `json:"service"`
		BusinessUnit    string `json:"business_unit"`
		Environment     string `json:"environment"`
		EscalationChain any    `json:"escalation_chain"`
	}{string(o.Kind), strings.TrimSpace(o.Name), strings.TrimSpace(o.Email), strings.TrimSpace(o.ApplicationID),
		strings.TrimSpace(o.Service), strings.TrimSpace(o.BusinessUnit), strings.TrimSpace(o.Environment), chain})
}

// changeStep is one object of a change set: the permission writing it needs,
// how it reads and applies, and what its plan item discloses.
type changeStep struct {
	perm     authz.Permission
	step     baselineStep
	disclose func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error
}

func (a *API) changeSteps(tenantID string, cs ChangeSet) []changeStep {
	var steps []changeStep
	for _, p := range cs.Profiles {
		steps = append(steps, a.changeProfileStep(tenantID, p))
	}
	for _, x := range cs.Issuers {
		steps = append(steps, a.changeIssuerStep(tenantID, x))
	}
	for _, x := range cs.DeploymentTargets {
		steps = append(steps, a.changeTargetStep(tenantID, x))
	}
	for _, x := range cs.Members {
		steps = append(steps, a.changeMemberStep(tenantID, x))
	}
	for _, x := range cs.Owners {
		steps = append(steps, a.changeOwnerStep(tenantID, x))
	}
	return steps
}

func (a *API) changeProfileStep(tenantID string, p BaselineProfile) changeStep {
	return changeStep{perm: authz.ProfilesWrite, step: a.baselineProfileStep(tenantID, p),
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			item.Effects = []string{projections.EventProfileCreated}
			if current != nil {
				item.Effects = []string{projections.EventProfileUpdated}
			}
			gated, err := a.orch.ProfileEditRequiresApproval(ctx, tenantID, strings.TrimSpace(p.Name), p.Spec)
			if err != nil {
				return err
			}
			if gated {
				item.Approvals = []string{"a second operator approves this profile version before it becomes active (requires_approval)"}
				item.Effects = []string{projections.EventProfileEditApprovalRequested}
			}
			return nil
		}}
}

func (a *API) changeIssuerStep(tenantID string, x BaselineIssuer) changeStep {
	return changeStep{perm: authz.IssuersWrite, step: a.baselineIssuerStep(tenantID, changeSetScope, x),
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			item.Effects = []string{projections.EventIssuerCreated}
			item.Credentials = []string{fmt.Sprintf("%d public certificate(s) in the chain; no private key", len(x.Chain))}
			if current != nil {
				n, err := a.store.CountIdentitiesBound(ctx, tenantID, store.IdentitiesByIssuer, state.ObjectID)
				if err != nil {
					return err
				}
				item.Identities = []string{fmt.Sprintf("%d identities are issued under this CA", n)}
			}
			return nil
		}}
}

// changeTargetStep reads a target as a tenant baseline does, and applies it
// with every check the operator's create request runs.
func (a *API) changeTargetStep(tenantID string, x BaselineDeploymentTarget) changeStep {
	base := a.baselineTargetStep(tenantID, changeSetScope, x)
	id := baselineObjectID(tenantID, changeSetScope, BaselineKindDeploymentTarget, x.Key)
	req, _ := baselineTargetRequest(x)
	enabled := deploymentTargetRequestEnabled(req.Enabled)
	base.apply = func(ctx context.Context, current any) (string, string, error) {
		if err := a.requireAdmittedConnector(ctx, tenantID, req.Connector); err != nil {
			return "", "", err
		}
		if err := a.requireModuleInputs(ctx, tenantID, req.Connector, req.Config); err != nil {
			return "", "", err
		}
		if enabled {
			if _, err := a.store.ValidateHostTargetAssignment(ctx, tenantID, req.Connector, req.Config); err != nil {
				return "", "", errWithStatus(http.StatusUnprocessableEntity, err)
			}
		}
		if _, err := a.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{
			ID: id, Name: req.Name, Type: req.Connector, Config: req.Config, Enabled: enabled, EnabledSet: true,
		}); err != nil {
			return "", "", err
		}
		return createdOrUpdated(current), "", nil
	}
	return changeStep{perm: authz.ConnectorsWrite, step: base,
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			item.Effects = []string{projections.EventDeploymentTargetUpserted}
			destination := req.Connector + " target " + req.Name
			if endpoint := targetEndpoint(req.Config); endpoint != "" {
				destination += " at " + endpoint
			}
			if !enabled {
				destination += " (disabled)"
			}
			item.Destinations = []string{destination}
			item.Credentials = credentialReferences(req.Config)
			n, err := a.store.CountIdentitiesBound(ctx, tenantID, store.IdentitiesByDeploymentTarget, id)
			if err != nil {
				return err
			}
			item.Identities = []string{fmt.Sprintf("%d identities deploy to this target", n)}
			return nil
		}}
}

// targetEndpoint is where a target's config says it is.
func targetEndpoint(config json.RawMessage) string {
	var fields map[string]any
	if json.Unmarshal(config, &fields) != nil {
		return ""
	}
	for _, k := range []string{"endpoint", "url", "address", "host"} {
		if v, ok := fields[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// credentialReferences are the stored secrets a target's config names.
func credentialReferences(config json.RawMessage) []string {
	var fields map[string]any
	if json.Unmarshal(config, &fields) != nil {
		return []string{}
	}
	out := []string{}
	for k, v := range fields {
		if s, ok := v.(string); ok && strings.HasSuffix(strings.ToLower(k), "_ref") && strings.TrimSpace(s) != "" {
			out = append(out, k+" names the stored secret "+strings.TrimSpace(s))
		}
	}
	sort.Strings(out)
	return out
}

// changeMemberStep grants a member's roles with the checks and the recorded
// decision of the operator's own member request.
func (a *API) changeMemberStep(tenantID string, x BaselineMember) changeStep {
	subject := strings.TrimSpace(x.Subject)
	base := a.baselineMemberStep(tenantID, baselineOrigin{}, x)
	base.apply = func(ctx context.Context, current any) (string, string, error) {
		if err := a.validateRoleNames(ctx, tenantID, x.Roles); err != nil {
			return "", "", err
		}
		if err := a.authorizeRoleAssignment(ctx, tenantID, subject, x.Roles, true); err != nil {
			return "", "", err
		}
		if _, err := a.orch.UpsertTenantMember(ctx, tenantID, store.TenantMember{
			Subject: subject, DisplayName: x.DisplayName, Email: x.Email, Roles: x.Roles, Source: "change_set",
		}); err != nil {
			return "", "", err
		}
		return createdOrUpdated(current), "", nil
	}
	return changeStep{perm: authz.AccessRoleAssign, step: base,
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			item.Identities = []string{"member " + subject}
			grant := "roles " + strings.Join(x.Roles, ", ")
			if m, ok := current.(*store.TenantMember); ok && m != nil {
				grant += " (now " + strings.Join(m.Roles, ", ") + ")"
			}
			item.Grants = []string{grant}
			item.Effects = []string{orchestrator.EventAuthzDecision, projections.EventTenantMemberUpserted}
			return nil
		}}
}

func (a *API) changeOwnerStep(tenantID string, x ChangeOwner) changeStep {
	key := strings.TrimSpace(x.Key)
	id := baselineObjectID(tenantID, changeSetScope, ChangeKindOwner, key)
	want := changeOwnerRecord(x, tenantID, id)
	expected := ownerDigest(want)
	step := baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			got, err := a.store.GetOwner(ctx, tenantID, id)
			missing, err := missingOrErr(err)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if missing {
				return stateOf(ChangeKindOwner, key, id, expected, "", true), nil, nil
			}
			return stateOf(ChangeKindOwner, key, id, expected, ownerDigest(got), false), &got, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			if current == nil {
				_, err := a.orch.CreateOwnerRecord(ctx, want)
				return BaselineCreated, "", err
			}
			_, err := a.orch.UpdateOwnerRecord(ctx, want)
			return BaselineUpdated, "", err
		},
	}
	return changeStep{perm: authz.OwnersWrite, step: step,
		disclose: func(ctx context.Context, state BaselineObjectState, current any, item *ChangePlanItem) error {
			item.Effects = []string{projections.EventOwnerCreated}
			if current != nil {
				item.Effects = []string{projections.EventOwnerUpdated}
				n, err := a.store.CountIdentitiesBound(ctx, tenantID, store.IdentitiesByOwner, id)
				if err != nil {
					return err
				}
				item.Identities = []string{fmt.Sprintf("%d identities are owned by %s", n, strings.TrimSpace(x.Name))}
			}
			if chain := x.EscalationChain; len(chain) > 0 {
				item.Destinations = []string{"escalation chain " + strings.Join(chain, " → ")}
			}
			return nil
		}}
}

type plannedChange struct {
	step    changeStep
	current any
}

// planChangeSet validates the set, checks principal may write every object,
// and reads each one's current revision into the plan.
func (a *API) planChangeSet(ctx context.Context, principal authz.Principal, tenantID string, cs ChangeSet) (ChangePlan, []plannedChange, error) {
	if err := a.validateChangeSet(cs); err != nil {
		return ChangePlan{}, nil, err
	}
	cs = cs.normalized()
	scope := authz.Scope{TenantID: tenantID}
	for _, x := range cs.Members {
		if err := a.validateRoleNames(ctx, tenantID, x.Roles); err != nil {
			return ChangePlan{}, nil, err
		}
		reason, err := a.roleAssignmentRefusal(ctx, tenantID, principal, strings.TrimSpace(x.Subject), x.Roles)
		if err != nil {
			return ChangePlan{}, nil, err
		}
		if reason != "" {
			return ChangePlan{}, nil, errStatus(http.StatusForbidden, "member "+strings.TrimSpace(x.Subject)+": "+reason)
		}
	}
	plan := ChangePlan{Name: strings.TrimSpace(cs.Name), ChangeSetDigest: ChangeSetDigest(cs), Items: []ChangePlanItem{}}
	var planned []plannedChange
	revisions := []string{plan.ChangeSetDigest}
	for _, st := range a.changeSteps(tenantID, cs) {
		if !principal.Can(st.perm, scope) {
			return ChangePlan{}, nil, errStatus(http.StatusForbidden, fmt.Sprintf("the change set writes objects that need %s, which you do not hold", st.perm))
		}
		state, current, err := st.step.read(ctx)
		if err != nil {
			return ChangePlan{}, nil, err
		}
		item := ChangePlanItem{Kind: state.Kind, Key: state.Key, ObjectID: state.ObjectID, ExpectedDigest: state.ExpectedDigest,
			ActualDigest: state.ActualDigest, Detail: state.Detail, Identities: []string{}, Credentials: []string{}, Grants: []string{},
			Destinations: []string{}, Approvals: []string{}, Effects: []string{}}
		switch {
		case state.Status == BaselineInSync:
			item.Action = ChangeUnchanged
		case current == nil:
			item.Action = ChangeCreate
		default:
			item.Action = ChangeUpdate
		}
		if item.Action != ChangeUnchanged {
			plan.Changes++
			if err := st.disclose(ctx, state, current, &item); err != nil {
				return ChangePlan{}, nil, err
			}
			item.Verification = fmt.Sprintf("after applying, %s %s reads back with digest %s", item.Kind, item.Key, item.ExpectedDigest)
		} else {
			item.Verification = fmt.Sprintf("%s %s already reads back with digest %s; applying leaves it alone", item.Kind, item.Key, item.ExpectedDigest)
		}
		plan.Items = append(plan.Items, item)
		planned = append(planned, plannedChange{step: st, current: current})
		revisions = append(revisions, item.Kind+"\x00"+item.Key+"\x00"+item.ObjectID+"\x00"+item.ActualDigest)
	}
	plan.PlanDigest = baselineDigest(revisions)
	return plan, planned, nil
}

// applyChangeSet re-plans the set, refuses a plan the tenant has moved past,
// then writes each changed object and reads it back.
func (a *API) applyChangeSet(ctx context.Context, principal authz.Principal, tenantID string, req ChangeApplyRequest) (ChangeApplication, error) {
	plan, planned, err := a.planChangeSet(ctx, principal, tenantID, req.ChangeSet)
	if err != nil {
		return ChangeApplication{}, err
	}
	if strings.TrimSpace(req.PlanDigest) != plan.PlanDigest {
		return ChangeApplication{}, errStatus(http.StatusConflict, "the plan is stale: the tenant or the change set differs from what was reviewed (current plan "+plan.PlanDigest+"); plan it again and review")
	}
	out := ChangeApplication{Name: plan.Name, ChangeSetDigest: plan.ChangeSetDigest, PlanDigest: plan.PlanDigest, Complete: true, Results: []ChangeApplyResult{}}
	for i, p := range planned {
		item := plan.Items[i]
		result := ChangeApplyResult{Kind: item.Kind, Key: item.Key, ObjectID: item.ObjectID, Outcome: BaselineUnchanged, Verified: true}
		if item.Action != ChangeUnchanged {
			outcome, approval, err := p.step.step.apply(ctx, p.current)
			switch {
			case err != nil:
				result.Outcome, result.Error, result.Verified = BaselineFailed, err.Error(), false
			default:
				result.Outcome, result.ApprovalRequestID = outcome, approval
				after, _, rerr := p.step.step.read(ctx)
				result.Verified = rerr == nil && after.Status == BaselineInSync
				if after.ObjectID != "" {
					result.ObjectID = after.ObjectID
				}
			}
		}
		if !result.Verified {
			out.Complete = false
		}
		out.Results = append(out.Results, result)
	}
	return out, nil
}

func (a *API) planChangeSetHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	var cs ChangeSet
	if err := decodeJSONWithLimitOptions(r, &cs, defaultRESTJSONBodyLimit, true); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	plan, _, err := a.planChangeSet(r.Context(), principal, tenantID, cs)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

//trstctl:mutation
func (a *API) applyChangeSetHandler(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		var req ChangeApplyRequest
		if err := decodeJSONWithLimitOptions(r, &req, defaultRESTJSONBodyLimit, true); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if strings.TrimSpace(req.PlanDigest) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "plan_digest is required: apply the plan you reviewed")
		}
		applied, err := a.applyChangeSet(ctx, principal, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, applied, nil
	})
}

func changeSetRoutes(a *API) []route {
	return []route{
		{method: "POST", path: "/api/v1/changes/plan", opID: "planChangeSet",
			summary: "Plan a reviewed configuration change set: validate it, check every object's permission, and list exactly what applying it would do",
			handler: a.planChangeSetHandler, reqSchema: "ChangeSet", resSchema: "ChangePlan", successCode: "200", readOnly: true, perm: authz.ChangesWrite},
		{method: "POST", path: "/api/v1/changes/draft", opID: "draftChangeSet",
			summary: "Draft a change set from a request with the configured AI model; the draft goes through the same plan and is never applied here",
			handler: a.draftChangeSetHandler, reqSchema: "ChangeDraftRequest", resSchema: "ChangeDraft", successCode: "200", readOnly: true, perm: authz.ChangesWrite},
		{method: "POST", path: "/api/v1/changes/apply", opID: "applyChangeSet",
			summary: "Apply a planned change set; a plan the tenant has moved past is refused",
			handler: a.applyChangeSetHandler, reqSchema: "ChangeApplyRequest", resSchema: "ChangeApplication", successCode: "200", mutation: true, perm: authz.ChangesWrite},
	}
}

func changeSetSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	boolean := func() *Schema { return &Schema{Type: "boolean"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	list := func(item *Schema) *Schema { return &Schema{Type: "array", Items: item} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	anyJSON := func() *Schema { return &Schema{} }
	profile := object(map[string]*Schema{"name": str(), "spec": anyJSON()}, "name", "spec")
	issuer := object(map[string]*Schema{"key": str(), "name": str(), "kind": str(), "chain": list(str()), "public_key": str(), "internal": boolean()}, "key", "name", "kind")
	target := object(map[string]*Schema{"key": str(), "name": str(), "connector": str(), "config": anyJSON(), "enabled": boolean()}, "key", "name", "connector", "config")
	member := object(map[string]*Schema{"subject": str(), "display_name": str(), "email": str(), "roles": list(str())}, "subject", "roles")
	owner := object(map[string]*Schema{"key": str(), "kind": str(), "name": str(), "email": str(), "application_id": str(), "service": str(),
		"business_unit": str(), "environment": str(), "escalation_chain": list(str())}, "key", "kind", "name")
	changeSet := object(map[string]*Schema{"name": str(), "description": str(), "profiles": list(profile), "issuers": list(issuer),
		"deployment_targets": list(target), "members": list(member), "owners": list(owner)}, "name")
	item := object(map[string]*Schema{"kind": str(), "key": str(), "object_id": str(), "action": {Type: "string", Enum: []string{ChangeCreate, ChangeUpdate, ChangeUnchanged}},
		"expected_digest": str(), "actual_digest": str(), "detail": str(), "identities": list(str()), "credentials": list(str()), "grants": list(str()),
		"destinations": list(str()), "approvals": list(str()), "effects": list(str()), "verification": str()},
		"kind", "key", "action", "expected_digest", "identities", "credentials", "grants", "destinations", "approvals", "effects", "verification")
	result := object(map[string]*Schema{"kind": str(), "key": str(), "object_id": str(), "outcome": str(), "approval_request_id": str(), "verified": boolean(), "error": str()},
		"kind", "key", "outcome", "verified")
	plan := object(map[string]*Schema{"name": str(), "change_set_digest": str(), "plan_digest": str(), "changes": integer(), "items": list(item)}, "name", "change_set_digest", "plan_digest", "changes", "items")
	return map[string]*Schema{
		"ChangeDraftRequest": object(map[string]*Schema{"request": str()}, "request"),
		"ChangeDraft":        object(map[string]*Schema{"change_set": changeSet, "plan": plan, "refused": str(), "model": str()}, "change_set", "model"),
		"ChangeSet":          changeSet,
		"ChangePlan":         plan,
		"ChangeApplyRequest": object(map[string]*Schema{"change_set": changeSet, "plan_digest": str()}, "change_set", "plan_digest"),
		"ChangeApplication":  object(map[string]*Schema{"name": str(), "change_set_digest": str(), "plan_digest": str(), "complete": boolean(), "results": list(result)}, "name", "change_set_digest", "plan_digest", "complete", "results"),
	}
}
