// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// A tenant baseline is a set of objects a caller holds a tenant to: certificate
// profiles, the lifecycle policy, the CA chains its identities are bound to,
// connector targets, notification channels, member role grants and report
// schedules. Applying it writes each object through the same event-sourced
// commands and validation an operator's request takes, and only when the tenant's
// current object differs; reading it back says, per object, whether the tenant
// holds it as the baseline says. The Provider plane's tenant templates are built
// on it.

// TenantBaseline is the set of objects.
type TenantBaseline struct {
	Profiles             []BaselineProfile             `json:"profiles,omitempty"`
	Policy               *BaselinePolicy               `json:"policy,omitempty"`
	Issuers              []BaselineIssuer              `json:"issuers,omitempty"`
	DeploymentTargets    []BaselineDeploymentTarget    `json:"deployment_targets,omitempty"`
	NotificationChannels []BaselineNotificationChannel `json:"notification_channels,omitempty"`
	Members              []BaselineMember              `json:"members,omitempty"`
	ReportSchedules      []BaselineReportSchedule      `json:"report_schedules,omitempty"`
}

// BaselineProfile is a certificate profile by name.
type BaselineProfile struct {
	Name string          `json:"name"`
	Spec json.RawMessage `json:"spec"`
}

// BaselinePolicy is the tenant's active lifecycle policy module.
type BaselinePolicy struct {
	Module      string `json:"module"`
	Description string `json:"description,omitempty"`
}

// BaselineIssuer binds the tenant to a CA: the X.509 chain (or SSH CA key) its
// identities are issued under. Key names it within the baseline.
type BaselineIssuer struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Chain     []string `json:"chain,omitempty"`
	PublicKey string   `json:"public_key,omitempty"`
	Internal  bool     `json:"internal,omitempty"`
}

// BaselineDeploymentTarget is a connector target the tenant deploys to by
// default. Key names it within the baseline.
type BaselineDeploymentTarget struct {
	Key       string          `json:"key"`
	Name      string          `json:"name"`
	Connector string          `json:"connector"`
	Config    json.RawMessage `json:"config"`
	Enabled   *bool           `json:"enabled,omitempty"`
}

// BaselineNotificationChannel is the tenant's channel of one type.
type BaselineNotificationChannel struct {
	ChannelType   string `json:"channel_type"`
	Label         string `json:"label,omitempty"`
	EndpointURL   string `json:"endpoint_url,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	Enabled       *bool  `json:"enabled,omitempty"`
}

// BaselineMember grants built-in roles to one member subject.
type BaselineMember struct {
	Subject     string   `json:"subject"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles"`
}

// BaselineReportSchedule is a scheduled compliance report. Key names it within
// the baseline. Dispatch announces each completed run as the tenant's own
// schedule would (A103); its channels are the tenant's channels of those types,
// usually the baseline's own notification channels.
type BaselineReportSchedule struct {
	Key             string                          `json:"key"`
	Name            string                          `json:"name"`
	Framework       string                          `json:"framework"`
	ReportType      string                          `json:"report_type"`
	IntervalSeconds int                             `json:"interval_seconds"`
	Enabled         *bool                           `json:"enabled,omitempty"`
	Dispatch        *store.ComplianceReportDispatch `json:"dispatch,omitempty"`
}

// TenantBaselineService is the tenant baseline as another plane uses it: the
// Provider plane's tenant templates validate, apply and read back baselines in
// customer tenants through it.
type TenantBaselineService interface {
	ValidateTenantBaseline(TenantBaseline) error
	ApplyTenantBaseline(ctx context.Context, tenantID, scope string, b TenantBaseline) (TenantBaselineApplication, error)
	TenantBaselineDrift(ctx context.Context, tenantID, scope string, b TenantBaseline) (TenantBaselineReport, error)
}

var _ TenantBaselineService = (*API)(nil)

// Baseline object kinds.
const (
	BaselineKindProfile             = "profile"
	BaselineKindPolicy              = "policy"
	BaselineKindIssuer              = "issuer"
	BaselineKindDeploymentTarget    = "deployment_target"
	BaselineKindNotificationChannel = "notification_channel"
	BaselineKindMember              = "member"
	BaselineKindReportSchedule      = "report_schedule"
)

// Baseline object statuses and apply outcomes.
const (
	BaselineInSync  = "in_sync"
	BaselineDrifted = "drifted"
	BaselineMissing = "missing"

	BaselineUnchanged       = "unchanged"
	BaselineCreated         = "created"
	BaselineUpdated         = "updated"
	BaselinePendingApproval = "pending_approval"
	BaselineFailed          = "failed"
)

// BaselineObjectState is one baseline object as the tenant holds it.
type BaselineObjectState struct {
	Kind           string `json:"kind"`
	Key            string `json:"key"`
	ObjectID       string `json:"object_id,omitempty"`
	Status         string `json:"status"`
	ExpectedDigest string `json:"expected_digest"`
	ActualDigest   string `json:"actual_digest,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

// BaselineObjectResult is what applying did to one object.
type BaselineObjectResult struct {
	BaselineObjectState
	Outcome           string `json:"outcome"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
	Error             string `json:"error,omitempty"`
}

// TenantBaselineReport is a tenant's state against a baseline.
type TenantBaselineReport struct {
	TenantID       string                `json:"tenant_id"`
	BaselineDigest string                `json:"baseline_digest"`
	InSync         bool                  `json:"in_sync"`
	Objects        []BaselineObjectState `json:"objects"`
}

// TenantBaselineApplication is what applying a baseline to a tenant did.
type TenantBaselineApplication struct {
	TenantID       string                 `json:"tenant_id"`
	BaselineDigest string                 `json:"baseline_digest"`
	Complete       bool                   `json:"complete"`
	Results        []BaselineObjectResult `json:"results"`
}

// ErrBaselineTenantNotRegistered refuses a baseline for a tenant core has not
// registered.
var ErrBaselineTenantNotRegistered = errors.New("api: the tenant is not registered")

// TenantBaselineDigest is the baseline's stable digest.
func TenantBaselineDigest(b TenantBaseline) string {
	raw, err := json.Marshal(b)
	if err != nil {
		return ""
	}
	return "sha256:" + crypto.SHA256Hex(canonicalJSON(raw))
}

// canonicalJSON re-encodes JSON with sorted object keys, so equal values hash
// equally however they were written.
func canonicalJSON(raw []byte) []byte {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

func baselineDigest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return "sha256:" + crypto.SHA256Hex(canonicalJSON(raw))
}

// baselineObjectID is the deterministic ID of a keyed baseline object in one
// tenant, so applying the same baseline twice names the same object.
func baselineObjectID(tenantID, scope, kind, key string) string {
	return guuid.NewSHA1(guuid.NameSpaceURL, []byte("trstctl:tenant-baseline:"+tenantID+"/"+scope+"/"+kind+"/"+key)).String()
}

// ValidateTenantBaseline checks a baseline as an operator's requests for each
// object would be checked, before it is recorded or applied.
func (a *API) ValidateTenantBaseline(b TenantBaseline) error {
	names := map[string]bool{}
	for _, p := range b.Profiles {
		name := strings.TrimSpace(p.Name)
		if name == "" || names[name] {
			return fmt.Errorf("baseline profile names must be present and distinct (%q)", p.Name)
		}
		names[name] = true
		if err := profile.ValidateSpec(p.Spec); err != nil {
			return fmt.Errorf("baseline profile %s: %w", name, err)
		}
	}
	if b.Policy != nil {
		live, ok := a.liveLifecyclePolicy()
		if !ok {
			return errors.New("baseline policy: live lifecycle policy activation is not configured")
		}
		if _, _, _, err := live.PrepareModule(strings.TrimSpace(b.Policy.Module)); err != nil {
			return fmt.Errorf("baseline policy: %w", err)
		}
	}
	if err := distinctKeys("issuer", len(b.Issuers), func(i int) string { return b.Issuers[i].Key }); err != nil {
		return err
	}
	for _, x := range b.Issuers {
		if err := baselineIssuer(x, "", "").Validate(); err != nil {
			return fmt.Errorf("baseline issuer %s: %w", x.Key, err)
		}
	}
	if err := distinctKeys("deployment target", len(b.DeploymentTargets), func(i int) string { return b.DeploymentTargets[i].Key }); err != nil {
		return err
	}
	for _, x := range b.DeploymentTargets {
		if _, err := baselineTargetRequest(x); err != nil {
			return fmt.Errorf("baseline deployment target %s: %w", x.Key, err)
		}
	}
	if err := distinctKeys("notification channel", len(b.NotificationChannels), func(i int) string {
		return canonicalNotificationChannelID(b.NotificationChannels[i].ChannelType)
	}); err != nil {
		return err
	}
	for _, x := range b.NotificationChannels {
		if _, err := baselineChannel("", x); err != nil {
			return fmt.Errorf("baseline notification channel %s: %w", x.ChannelType, err)
		}
	}
	if err := distinctKeys("member", len(b.Members), func(i int) string { return strings.TrimSpace(b.Members[i].Subject) }); err != nil {
		return err
	}
	for _, x := range b.Members {
		if len(x.Roles) == 0 {
			return fmt.Errorf("baseline member %s: roles are required", x.Subject)
		}
		if err := a.validateRoleNameShapes(x.Roles); err != nil {
			return fmt.Errorf("baseline member %s: %w", x.Subject, err)
		}
	}
	if err := distinctKeys("report schedule", len(b.ReportSchedules), func(i int) string { return b.ReportSchedules[i].Key }); err != nil {
		return err
	}
	for _, x := range b.ReportSchedules {
		if _, err := baselineScheduleRequest(x); err != nil {
			return fmt.Errorf("baseline report schedule %s: %w", x.Key, err)
		}
	}
	return nil
}

func distinctKeys(what string, n int, key func(int) string) error {
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		k := strings.TrimSpace(key(i))
		if k == "" || seen[k] {
			return fmt.Errorf("baseline %s keys must be present and distinct (%q)", what, k)
		}
		seen[k] = true
	}
	return nil
}

func baselineIssuer(x BaselineIssuer, tenantID, id string) store.Issuer {
	return store.Issuer{ID: id, TenantID: tenantID, Kind: store.IssuerKind(strings.TrimSpace(x.Kind)), Name: strings.TrimSpace(x.Name),
		Chain: x.Chain, PublicKey: strings.TrimSpace(x.PublicKey), Internal: x.Internal}
}

func baselineTargetRequest(x BaselineDeploymentTarget) (deploymentTargetRequest, error) {
	raw, err := json.Marshal(deploymentTargetRequest{Name: x.Name, Connector: x.Connector, Config: x.Config, Enabled: x.Enabled})
	if err != nil {
		return deploymentTargetRequest{}, err
	}
	return parseDeploymentTargetRequest(raw)
}

func baselineChannel(tenantID string, x BaselineNotificationChannel) (store.NotificationChannel, error) {
	return notificationChannelFromRequest(tenantID, x.ChannelType, notificationChannelRequest{
		ChannelType: x.ChannelType, Label: x.Label, EndpointURL: x.EndpointURL, CredentialRef: x.CredentialRef, Enabled: x.Enabled,
	})
}

func baselineScheduleRequest(x BaselineReportSchedule) (complianceReportScheduleRequest, error) {
	return normalizeComplianceReportScheduleRequest(complianceReportScheduleRequest{
		Framework: x.Framework, Name: x.Name, ReportType: x.ReportType, IntervalSeconds: x.IntervalSeconds, Enabled: x.Enabled,
		Dispatch: x.Dispatch,
	})
}

// TenantBaselineDrift reads the tenant's objects against the baseline. scope
// keeps one baseline's keyed objects apart from another's in the same tenant.
func (a *API) TenantBaselineDrift(ctx context.Context, tenantID, scope string, b TenantBaseline) (TenantBaselineReport, error) {
	if _, err := a.store.GetTenant(ctx, tenantID); err != nil {
		return TenantBaselineReport{}, ErrBaselineTenantNotRegistered
	}
	report := TenantBaselineReport{TenantID: tenantID, BaselineDigest: TenantBaselineDigest(b), InSync: true, Objects: []BaselineObjectState{}}
	for _, step := range a.baselineSteps(tenantID, scope, b) {
		state, _, err := step.read(ctx)
		if err != nil {
			return TenantBaselineReport{}, err
		}
		if state.Status != BaselineInSync {
			report.InSync = false
		}
		report.Objects = append(report.Objects, state)
	}
	return report, nil
}

// ApplyTenantBaseline writes every object the tenant does not hold as the
// baseline says, and leaves the rest alone. Each object is written through the
// command an operator's request takes; one object's failure is reported and the
// others still apply.
func (a *API) ApplyTenantBaseline(ctx context.Context, tenantID, scope string, b TenantBaseline) (TenantBaselineApplication, error) {
	if _, err := a.store.GetTenant(ctx, tenantID); err != nil {
		return TenantBaselineApplication{}, ErrBaselineTenantNotRegistered
	}
	if err := a.ValidateTenantBaseline(b); err != nil {
		return TenantBaselineApplication{}, errStatus(http.StatusUnprocessableEntity, err.Error())
	}
	out := TenantBaselineApplication{TenantID: tenantID, BaselineDigest: TenantBaselineDigest(b), Complete: true, Results: []BaselineObjectResult{}}
	for _, step := range a.baselineSteps(tenantID, scope, b) {
		state, current, err := step.read(ctx)
		if err != nil {
			return TenantBaselineApplication{}, err
		}
		result := BaselineObjectResult{BaselineObjectState: state, Outcome: BaselineUnchanged}
		if state.Status != BaselineInSync {
			outcome, approval, err := step.apply(ctx, current)
			switch {
			case err != nil:
				result.Outcome, result.Error = BaselineFailed, err.Error()
			default:
				result.Outcome, result.ApprovalRequestID = outcome, approval
				if after, _, rerr := step.read(ctx); rerr == nil {
					result.BaselineObjectState = after
				}
			}
		}
		if result.Outcome == BaselineFailed || result.Outcome == BaselinePendingApproval {
			out.Complete = false
		}
		out.Results = append(out.Results, result)
	}
	return out, nil
}

// baselineStep reads one object's state and applies it. read returns the
// current object (or nil) so apply knows whether it creates or updates.
type baselineStep struct {
	read  func(context.Context) (BaselineObjectState, any, error)
	apply func(context.Context, any) (outcome, approvalRequestID string, err error)
}

func (a *API) baselineSteps(tenantID, scope string, b TenantBaseline) []baselineStep {
	var steps []baselineStep
	for _, p := range b.Profiles {
		steps = append(steps, a.baselineProfileStep(tenantID, p))
	}
	if b.Policy != nil {
		steps = append(steps, a.baselinePolicyStep(tenantID, scope, *b.Policy))
	}
	for _, x := range b.Issuers {
		steps = append(steps, a.baselineIssuerStep(tenantID, scope, x))
	}
	for _, x := range b.DeploymentTargets {
		steps = append(steps, a.baselineTargetStep(tenantID, scope, x))
	}
	for _, x := range b.NotificationChannels {
		steps = append(steps, a.baselineChannelStep(tenantID, x))
	}
	for _, x := range b.Members {
		steps = append(steps, a.baselineMemberStep(tenantID, x))
	}
	for _, x := range b.ReportSchedules {
		steps = append(steps, a.baselineScheduleStep(tenantID, scope, x))
	}
	return steps
}

func missingOrErr(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	if store.IsNotFound(err) {
		return true, nil
	}
	return false, err
}

func stateOf(kind, key, id, expected, actual string, missing bool) BaselineObjectState {
	s := BaselineObjectState{Kind: kind, Key: key, ObjectID: id, ExpectedDigest: expected, ActualDigest: actual, Status: BaselineInSync}
	switch {
	case missing:
		s.Status, s.ActualDigest = BaselineMissing, ""
	case expected != actual:
		s.Status = BaselineDrifted
	}
	return s
}

func createdOrUpdated(current any) string {
	if current == nil {
		return BaselineCreated
	}
	return BaselineUpdated
}

func (a *API) baselineProfileStep(tenantID string, p BaselineProfile) baselineStep {
	name := strings.TrimSpace(p.Name)
	expected := "sha256:" + store.ProfileSpecDigest(p.Spec)
	return baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			active, err := a.store.GetActiveProfile(ctx, tenantID, name)
			missing, err := missingOrErr(err)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if missing {
				return stateOf(BaselineKindProfile, name, "", expected, "", true), nil, nil
			}
			s := stateOf(BaselineKindProfile, name, active.ID, expected, "sha256:"+store.ProfileSpecDigest(active.Spec), false)
			s.Detail = fmt.Sprintf("active version %d", active.Version)
			return s, &active, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			if _, err := a.orch.CreateProfile(ctx, tenantID, name, p.Spec); err != nil {
				var pending *orchestrator.ProfileEditPendingError
				if errors.As(err, &pending) {
					return BaselinePendingApproval, pending.Request.ID, nil
				}
				return "", "", err
			}
			return createdOrUpdated(current), "", nil
		},
	}
}

func (a *API) baselinePolicyStep(tenantID, scope string, p BaselinePolicy) baselineStep {
	module := strings.TrimSpace(p.Module)
	return baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			live, ok := a.liveLifecyclePolicy()
			if !ok {
				return BaselineObjectState{}, nil, errStatus(http.StatusServiceUnavailable, "live lifecycle policy activation is not configured")
			}
			_, want, _, err := live.PrepareModule(module)
			if err != nil {
				return BaselineObjectState{}, nil, errStatus(http.StatusUnprocessableEntity, err.Error())
			}
			activeModule, active, err := live.ActiveModule(ctx, tenantID)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			expected := "sha256:" + want.ModuleSHA256
			if strings.TrimSpace(activeModule) == "" {
				return stateOf(BaselineKindPolicy, "lifecycle", "", expected, "", true), nil, nil
			}
			return stateOf(BaselineKindPolicy, "lifecycle", "", expected, "sha256:"+active.ModuleSHA256, false), active, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			err := a.store.WithProjectionLock(ctx, func(ctx context.Context) error {
				return a.authorAndActivateBaselinePolicy(ctx, tenantID, scope, module, p.Description)
			})
			if err != nil {
				return "", "", err
			}
			return createdOrUpdated(current), "", nil
		},
	}
}

// authorAndActivateBaselinePolicy records the module as a lifecycle policy
// version (once: its ID derives from the module digest) and activates it, with
// the same events an operator's create and activate requests append.
func (a *API) authorAndActivateBaselinePolicy(ctx context.Context, tenantID, scope, module, description string) error {
	live, ok := a.liveLifecyclePolicy()
	if !ok {
		return errStatus(http.StatusServiceUnavailable, "live lifecycle policy activation is not configured")
	}
	_, info, prepared, err := live.PrepareModule(module)
	if err != nil {
		return errStatus(http.StatusUnprocessableEntity, err.Error())
	}
	state, err := a.policyVersions(ctx, tenantID)
	if err != nil {
		return err
	}
	id := baselineObjectID(tenantID, scope, BaselineKindPolicy, info.ModuleSHA256)
	actor := ""
	if evActor, ok := events.ActorFromContext(ctx); ok {
		actor = evActor.Subject
	}
	kind := string(policy.DryRunKindLifecycle)
	if _, exists := state.items[id]; !exists {
		payload, err := json.Marshal(policyVersionAuthoredEvent{
			ID: id, Kind: kind, Module: prepared, ModuleSHA256: info.ModuleSHA256, Package: info.Package, Query: info.Query,
			Description: trimPolicyText(firstNonEmpty(description, "tenant baseline "+scope), 500), Author: actor,
		})
		if err != nil {
			return err
		}
		if _, err := a.appendPolicyVersionEvent(ctx, tenantID, policyVersionAuthoredEventType, payload); err != nil {
			return err
		}
	}
	previousModule, previousInfo, err := live.ActiveModule(ctx, tenantID)
	if err != nil {
		return err
	}
	previousID := state.activeByKind[kind]
	if previousID == "" {
		previousID = policyVersionBootID
	}
	payload, err := json.Marshal(policyVersionActivatedEvent{
		ID: id, Kind: kind, Reason: "applied by tenant baseline " + scope, ActivatedBy: actor,
		PreviousID: previousID, PreviousModule: previousModule, PreviousModuleSHA256: previousInfo.ModuleSHA256,
		PreviousPackage: previousInfo.Package, PreviousQuery: previousInfo.Query,
	})
	if err != nil {
		return err
	}
	_, err = a.appendPolicyVersionEvent(ctx, tenantID, policyVersionActivatedEventType, payload)
	return err
}

func issuerDigest(i store.Issuer) string {
	chain := append([]string(nil), i.Chain...)
	return baselineDigest(struct {
		Kind      string   `json:"kind"`
		Name      string   `json:"name"`
		Chain     []string `json:"chain"`
		PublicKey string   `json:"public_key"`
		Internal  bool     `json:"internal"`
	}{string(i.Kind), i.Name, chain, i.PublicKey, i.Internal})
}

func (a *API) baselineIssuerStep(tenantID, scope string, x BaselineIssuer) baselineStep {
	want := baselineIssuer(x, tenantID, "")
	expected := issuerDigest(want)
	// An issuer is immutable: a changed chain binds a new issuer, so its ID
	// carries the digest and the old binding stays for what it already issued.
	id := baselineObjectID(tenantID, scope, BaselineKindIssuer, x.Key+"/"+expected)
	want.ID = id
	return baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			got, err := a.store.GetIssuer(ctx, tenantID, id)
			missing, err := missingOrErr(err)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if missing {
				return stateOf(BaselineKindIssuer, x.Key, id, expected, "", true), nil, nil
			}
			return stateOf(BaselineKindIssuer, x.Key, id, expected, issuerDigest(got), false), &got, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			if _, err := a.orch.CreateIssuer(ctx, tenantID, want); err != nil {
				return "", "", err
			}
			return createdOrUpdated(current), "", nil
		},
	}
}

func targetDigest(name, connector string, config json.RawMessage, enabled bool) string {
	return baselineDigest(struct {
		Name      string          `json:"name"`
		Connector string          `json:"connector"`
		Config    json.RawMessage `json:"config"`
		Enabled   bool            `json:"enabled"`
	}{name, connector, json.RawMessage(canonicalJSON(config)), enabled})
}

func (a *API) baselineTargetStep(tenantID, scope string, x BaselineDeploymentTarget) baselineStep {
	id := baselineObjectID(tenantID, scope, BaselineKindDeploymentTarget, x.Key)
	req, reqErr := baselineTargetRequest(x)
	enabled := deploymentTargetRequestEnabled(req.Enabled)
	expected := targetDigest(req.Name, req.Connector, req.Config, enabled)
	return baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			if reqErr != nil {
				return BaselineObjectState{}, nil, errStatus(http.StatusUnprocessableEntity, reqErr.Error())
			}
			got, err := a.store.GetDeploymentTarget(ctx, tenantID, id)
			missing, err := missingOrErr(err)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if missing {
				return stateOf(BaselineKindDeploymentTarget, x.Key, id, expected, "", true), nil, nil
			}
			gotEnabled := got.Enabled || !got.EnabledSet
			return stateOf(BaselineKindDeploymentTarget, x.Key, id, expected, targetDigest(got.Name, got.Type, got.Config, gotEnabled), false), &got, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			if err := a.requireAdmittedConnector(ctx, tenantID, req.Connector); err != nil {
				return "", "", err
			}
			if enabled {
				if _, err := a.store.ValidateHostTargetAssignment(ctx, tenantID, req.Connector, req.Config); err != nil {
					return "", "", err
				}
			}
			if _, err := a.orch.UpsertDeploymentTarget(ctx, tenantID, store.DeploymentTarget{
				ID: id, Name: req.Name, Type: req.Connector, Config: req.Config, Enabled: enabled, EnabledSet: true,
			}); err != nil {
				return "", "", err
			}
			return createdOrUpdated(current), "", nil
		},
	}
}

func channelDigest(c store.NotificationChannel) string {
	return baselineDigest(struct {
		Label         string `json:"label"`
		EndpointURL   string `json:"endpoint_url"`
		CredentialRef string `json:"credential_ref"`
		Enabled       bool   `json:"enabled"`
	}{c.Label, c.EndpointURL, c.CredentialRef, c.Enabled})
}

func (a *API) baselineChannelStep(tenantID string, x BaselineNotificationChannel) baselineStep {
	want, wantErr := baselineChannel(tenantID, x)
	expected := channelDigest(want)
	return baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			if wantErr != nil {
				return BaselineObjectState{}, nil, errStatus(http.StatusUnprocessableEntity, wantErr.Error())
			}
			got, err := a.store.GetNotificationChannel(ctx, tenantID, want.ID)
			missing, err := missingOrErr(err)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if missing {
				return stateOf(BaselineKindNotificationChannel, want.ID, want.ID, expected, "", true), nil, nil
			}
			return stateOf(BaselineKindNotificationChannel, want.ID, want.ID, expected, channelDigest(got), false), &got, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			if _, err := a.appendNotificationChannelUpsert(ctx, tenantID, want); err != nil {
				return "", "", err
			}
			return createdOrUpdated(current), "", nil
		},
	}
}

func memberDigest(roles []string, active bool) string {
	sorted := append([]string(nil), roles...)
	sort.Strings(sorted)
	return baselineDigest(struct {
		Roles  []string `json:"roles"`
		Active bool     `json:"active"`
	}{sorted, active})
}

func (a *API) baselineMemberStep(tenantID string, x BaselineMember) baselineStep {
	subject := strings.TrimSpace(x.Subject)
	expected := memberDigest(x.Roles, true)
	return baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			got, err := a.store.GetTenantMember(ctx, tenantID, subject)
			missing, err := missingOrErr(err)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if missing {
				return stateOf(BaselineKindMember, subject, "", expected, "", true), nil, nil
			}
			s := stateOf(BaselineKindMember, subject, "", expected, memberDigest(got.Roles, got.OffboardedAt == nil), false)
			if got.OffboardedAt != nil {
				s.Detail = "the member was offboarded"
			}
			return s, &got, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			if err := a.validateRoleNames(ctx, tenantID, x.Roles); err != nil {
				return "", "", err
			}
			if _, err := a.orch.UpsertTenantMember(ctx, tenantID, store.TenantMember{
				Subject: subject, DisplayName: x.DisplayName, Email: x.Email, Roles: x.Roles, Source: "baseline",
			}); err != nil {
				return "", "", err
			}
			principal := authz.Principal{TenantID: tenantID}
			if actor, ok := events.ActorFromContext(ctx); ok {
				principal.Subject = actor.Subject
			}
			if err := a.recordRoleAssignDecision(ctx, tenantID, principal, subject, x.Roles, "allow", "granted by a tenant baseline"); err != nil {
				return "", "", err
			}
			return createdOrUpdated(current), "", nil
		},
	}
}

// scheduleDigest omits an empty dispatch, so a schedule without one keeps the
// digest it had before schedules could carry one.
func scheduleDigest(name, framework, reportType string, interval int, enabled bool, dispatch *store.ComplianceReportDispatch) string {
	if dispatch.Empty() {
		dispatch = nil
	}
	return baselineDigest(struct {
		Name            string                          `json:"name"`
		Framework       string                          `json:"framework"`
		ReportType      string                          `json:"report_type"`
		IntervalSeconds int                             `json:"interval_seconds"`
		Enabled         bool                            `json:"enabled"`
		Dispatch        *store.ComplianceReportDispatch `json:"dispatch,omitempty"`
	}{name, framework, reportType, interval, enabled, dispatch})
}

func (a *API) baselineScheduleStep(tenantID, scope string, x BaselineReportSchedule) baselineStep {
	id := baselineObjectID(tenantID, scope, BaselineKindReportSchedule, x.Key)
	req, reqErr := baselineScheduleRequest(x)
	enabled := req.Enabled == nil || *req.Enabled
	expected := scheduleDigest(req.Name, req.Framework, req.ReportType, req.IntervalSeconds, enabled, req.Dispatch)
	return baselineStep{
		read: func(ctx context.Context) (BaselineObjectState, any, error) {
			if reqErr != nil {
				return BaselineObjectState{}, nil, reqErr
			}
			got, err := a.store.GetComplianceReportSchedule(ctx, tenantID, id)
			missing, err := missingOrErr(err)
			if err != nil {
				return BaselineObjectState{}, nil, err
			}
			if missing {
				return stateOf(BaselineKindReportSchedule, x.Key, id, expected, "", true), nil, nil
			}
			return stateOf(BaselineKindReportSchedule, x.Key, id, expected,
				scheduleDigest(got.Name, got.Framework, got.ReportType, got.IntervalSeconds, got.Enabled, got.Dispatch), false), &got, nil
		},
		apply: func(ctx context.Context, current any) (string, string, error) {
			blockers := append(a.complianceReportBlockers(), a.complianceReportDispatchBlockers(ctx, tenantID, req.Dispatch)...)
			if len(blockers) != 0 {
				return "", "", errors.New(strings.Join(blockers, " "))
			}
			if _, err := a.orch.UpsertComplianceReportSchedule(ctx, tenantID, store.ComplianceReportSchedule{
				ID: id, Framework: req.Framework, Name: req.Name, ReportType: req.ReportType,
				IntervalSeconds: req.IntervalSeconds, Enabled: enabled, Delivery: req.Delivery, RecipientRef: req.RecipientRef,
				Dispatch: req.Dispatch,
			}); err != nil {
				return "", "", err
			}
			return createdOrUpdated(current), "", nil
		},
	}
}
