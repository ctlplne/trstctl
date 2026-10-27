// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// Tenant templates hold a Provider's customer tenants to a versioned set of
// tenant objects: certificate profiles, the lifecycle policy, CA bindings,
// connector targets, notification channels, member role grants and report
// schedules (core's tenant baseline). A template version is immutable. A
// customer is onboarded from a version, which registers its core tenant when
// needed and writes each object through the customer's own commands; its drift
// is read back from its own records; and a new version rolls out across the
// customers that use the template after a preview, each customer's application
// an audited Provider event.

// Template authority events.
const (
	EventTemplateRecorded      = "provider.template.recorded"
	EventTenantTemplateApplied = "provider.tenant_template.applied"
)

// Template errors.
var (
	ErrTemplateInvalid       = errors.New("provider: invalid tenant template")
	ErrTemplateNotFound      = fmt.Errorf("%w: tenant template", ErrNotFound)
	ErrTenantNotTemplated    = fmt.Errorf("%w: this customer was not onboarded from a template", ErrNotFound)
	ErrTemplateRolloutStale  = errors.New("provider: the customers changed since the rollout preview; preview again")
	errTemplatesNotAttached  = fmt.Errorf("%w: tenant templates need the durable template store and core's tenant baseline, which this deployment has not attached", ErrForbidden)
	templateIDPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	errTemplateBaselineEmpty = fmt.Errorf("%w: a template must name at least one object", ErrTemplateInvalid)
)

// TenantTemplate is one immutable template version.
type TenantTemplate struct {
	ID         string             `json:"id"`
	Version    int                `json:"version"`
	Name       string             `json:"name"`
	Baseline   api.TenantBaseline `json:"baseline"`
	Digest     string             `json:"digest"`
	RecordedBy string             `json:"recorded_by"`
	RecordedAt string             `json:"recorded_at"`
}

// TemplateApplication is one customer's application of a template version.
type TemplateApplication struct {
	TenantID   string                     `json:"tenant_id"`
	TemplateID string                     `json:"template_id"`
	Version    int                        `json:"version"`
	Digest     string                     `json:"digest"`
	Complete   bool                       `json:"complete"`
	Results    []api.BaselineObjectResult `json:"results"`
	AppliedBy  string                     `json:"applied_by"`
	AppliedAt  string                     `json:"applied_at"`
}

// TemplateDeps are what templates need beyond the Provider plane: the durable
// read store, core's tenant baseline, and core tenant registration.
type TemplateDeps struct {
	Store          TemplateStore
	Baselines      api.TenantBaselineService
	RegisterTenant func(ctx context.Context, tenantID, name, idempotencyKey string) error
}

// TemplateStore reads projected templates and customer bindings.
type TemplateStore interface {
	// TenantTemplateVersions lists one template's versions, oldest first.
	TenantTemplateVersions(ctx context.Context, templateID string) ([]TenantTemplate, error)
	// TenantTemplates lists the latest version of every template.
	TenantTemplates(ctx context.Context) ([]TenantTemplate, error)
	// TenantTemplateBinding is a customer's last application, or nil.
	TenantTemplateBinding(ctx context.Context, tenantID string) (*TemplateApplication, error)
	// TenantTemplateBindings lists the customers bound to a template.
	TenantTemplateBindings(ctx context.Context, templateID string) ([]TemplateApplication, error)
}

// TemplateRequest records a template version.
type TemplateRequest struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Baseline api.TenantBaseline `json:"baseline"`
}

// TemplateApplyRequest applies a template version to one customer; version 0
// means the latest.
type TemplateApplyRequest struct {
	TemplateID string `json:"template_id"`
	Version    int    `json:"version,omitempty"`
}

// TemplateDetail is a template's versions and the customers bound to it that
// the operator may see.
type TemplateDetail struct {
	Latest   TenantTemplate        `json:"latest"`
	Versions []TenantTemplate      `json:"versions"`
	Tenants  []TemplateApplication `json:"tenants"`
}

// TemplateDrift is a customer's state against the version it was onboarded or
// last updated to.
type TemplateDrift struct {
	Binding       TemplateApplication      `json:"binding"`
	LatestVersion int                      `json:"latest_version"`
	Report        api.TenantBaselineReport `json:"report"`
}

// RolloutRequest previews or applies a template version across customers.
// Version 0 means the latest; no tenant IDs means every customer bound to the
// template that the operator may provision.
type RolloutRequest struct {
	Version            int      `json:"version,omitempty"`
	TenantIDs          []string `json:"tenant_ids,omitempty"`
	PreviewFingerprint string   `json:"preview_fingerprint,omitempty"`
}

// RolloutTenant is one customer in a rollout preview.
type RolloutTenant struct {
	TenantID       string                    `json:"tenant_id"`
	CurrentVersion int                       `json:"current_version"`
	InSync         bool                      `json:"in_sync"`
	Changes        []api.BaselineObjectState `json:"changes"`
}

// RolloutPreview says what applying a version would change in each customer.
// Nothing is written; Fingerprint binds the rollout to exactly this preview.
type RolloutPreview struct {
	TemplateID  string          `json:"template_id"`
	Version     int             `json:"version"`
	Digest      string          `json:"digest"`
	Tenants     []RolloutTenant `json:"tenants"`
	Fingerprint string          `json:"fingerprint"`
}

// RolloutResult is what a rollout applied in each customer.
type RolloutResult struct {
	TemplateID   string                `json:"template_id"`
	Version      int                   `json:"version"`
	Applications []TemplateApplication `json:"applications"`
}

func (s *Service) templatesReady() error {
	if s.templates.Store == nil || s.templates.Baselines == nil {
		return errTemplatesNotAttached
	}
	return nil
}

func templateScope(templateID string) string { return "template:" + templateID }

// RecordTemplate validates a template with core's own checks and records it as
// a new immutable version; an unchanged definition returns the latest version.
func (s *Service) RecordTemplate(ctx context.Context, actor Operator, req TemplateRequest) (TenantTemplate, error) {
	if err := s.requirePermission(ctx, actor, PermTemplatesWrite); err != nil {
		return TenantTemplate{}, err
	}
	if err := s.templatesReady(); err != nil {
		return TenantTemplate{}, err
	}
	if s.mutations == nil {
		return TenantTemplate{}, errors.New("provider: tenant templates require the event mutation sink")
	}
	id, name := strings.TrimSpace(req.ID), strings.TrimSpace(req.Name)
	if !templateIDPattern.MatchString(id) {
		return TenantTemplate{}, fmt.Errorf("%w: id must be 2-64 lower-case letters, digits or hyphens starting with a letter", ErrTemplateInvalid)
	}
	if name == "" || len(name) > 120 {
		return TenantTemplate{}, fmt.Errorf("%w: name is required and at most 120 characters", ErrTemplateInvalid)
	}
	if baselineObjectCount(req.Baseline) == 0 {
		return TenantTemplate{}, errTemplateBaselineEmpty
	}
	if err := s.templates.Baselines.ValidateTenantBaseline(req.Baseline); err != nil {
		return TenantTemplate{}, fmt.Errorf("%w: %v", ErrTemplateInvalid, err)
	}
	versions, err := s.templates.Store.TenantTemplateVersions(ctx, id)
	if err != nil {
		return TenantTemplate{}, err
	}
	digest := api.TenantBaselineDigest(req.Baseline)
	version := 1
	if n := len(versions); n > 0 {
		latest := versions[n-1]
		if latest.Digest == digest && latest.Name == name {
			return latest, nil
		}
		version = latest.Version + 1
	}
	now := s.clock().UTC()
	tmpl := TenantTemplate{ID: id, Version: version, Name: name, Baseline: req.Baseline, Digest: digest,
		RecordedBy: actor.ID, RecordedAt: now.Format(timeLayout)}
	canonical, err := s.emit(ctx, EventTemplateRecorded, providerAuthorityTenant, AuthorityEvent{
		Template: &tmpl, EffectiveAt: now,
		Audit: AuditEvent{Type: EventTemplateRecorded, TenantID: providerAuthorityTenant, OperatorID: actor.ID, OperatorEmail: actor.Email,
			Subject: id, Reason: fmt.Sprintf("template %s version %d (%d objects)", id, version, baselineObjectCount(req.Baseline)), At: now},
	})
	if err != nil {
		return TenantTemplate{}, err
	}
	if canonical.Template != nil {
		tmpl = *canonical.Template
	}
	return tmpl, nil
}

const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

func baselineObjectCount(b api.TenantBaseline) int {
	n := len(b.Profiles) + len(b.Issuers) + len(b.DeploymentTargets) + len(b.NotificationChannels) + len(b.Members) + len(b.ReportSchedules)
	if b.Policy != nil {
		n++
	}
	return n
}

// ListTemplates lists the latest version of every template.
func (s *Service) ListTemplates(ctx context.Context, actor Operator) ([]TenantTemplate, error) {
	if err := s.requireOperator(actor); err != nil {
		return nil, err
	}
	if err := s.templatesReady(); err != nil {
		return nil, err
	}
	out, err := s.templates.Store.TenantTemplates(ctx)
	if out == nil {
		out = []TenantTemplate{}
	}
	return out, err
}

// GetTemplate returns a template's versions and the customers bound to it that
// the operator may read.
func (s *Service) GetTemplate(ctx context.Context, actor Operator, templateID string) (TemplateDetail, error) {
	if err := s.requireOperator(actor); err != nil {
		return TemplateDetail{}, err
	}
	if err := s.templatesReady(); err != nil {
		return TemplateDetail{}, err
	}
	versions, err := s.templates.Store.TenantTemplateVersions(ctx, strings.TrimSpace(templateID))
	if err != nil {
		return TemplateDetail{}, err
	}
	if len(versions) == 0 {
		return TemplateDetail{}, ErrTemplateNotFound
	}
	bindings, err := s.templates.Store.TenantTemplateBindings(ctx, versions[0].ID)
	if err != nil {
		return TemplateDetail{}, err
	}
	detail := TemplateDetail{Latest: versions[len(versions)-1], Versions: versions, Tenants: []TemplateApplication{}}
	for _, b := range bindings {
		if s.authorize(ctx, actor, b.TenantID, OpRead) == nil {
			detail.Tenants = append(detail.Tenants, b)
		}
	}
	return detail, nil
}

func (s *Service) templateVersion(ctx context.Context, templateID string, version int) (TenantTemplate, int, error) {
	versions, err := s.templates.Store.TenantTemplateVersions(ctx, strings.TrimSpace(templateID))
	if err != nil {
		return TenantTemplate{}, 0, err
	}
	if len(versions) == 0 {
		return TenantTemplate{}, 0, ErrTemplateNotFound
	}
	latest := versions[len(versions)-1]
	if version == 0 {
		return latest, latest.Version, nil
	}
	for _, v := range versions {
		if v.Version == version {
			return v, latest.Version, nil
		}
	}
	return TenantTemplate{}, 0, fmt.Errorf("%w: version %d", ErrTemplateNotFound, version)
}

// ApplyTemplate onboards a delegated customer from a template version, or moves
// it to another: it registers the customer's core tenant when core has not, writes
// every object the customer does not hold as the version says through the
// customer's own commands, and records the application as an audited Provider
// event bound to the customer.
func (s *Service) ApplyTemplate(ctx context.Context, actor Operator, customerID string, req TemplateApplyRequest) (TemplateApplication, error) {
	if err := s.requirePermission(ctx, actor, PermTemplatesWrite); err != nil {
		return TemplateApplication{}, err
	}
	if err := s.authorize(ctx, actor, customerID, OpProvision); err != nil {
		return TemplateApplication{}, err
	}
	if err := s.templatesReady(); err != nil {
		return TemplateApplication{}, err
	}
	tmpl, _, err := s.templateVersion(ctx, req.TemplateID, req.Version)
	if err != nil {
		return TemplateApplication{}, err
	}
	return s.applyTemplate(ctx, actor, customerID, tmpl)
}

func (s *Service) applyTemplate(ctx context.Context, actor Operator, customerID string, tmpl TenantTemplate) (TemplateApplication, error) {
	tenant, err := s.store.Tenant(ctx, customerID)
	if err != nil {
		return TemplateApplication{}, err
	}
	if tenant.Status != TenantActive {
		return TemplateApplication{}, fmt.Errorf("%w: customer %s is %s", ErrTenantStateConflict, customerID, tenant.Status)
	}
	coreCtx := events.ContextWithActor(ctx, events.Actor{Subject: "provider:" + firstNonEmptyString(actor.Email, actor.ID), Roles: []string{"provider:" + string(actor.Role)}})
	applied, err := s.templates.Baselines.ApplyTenantBaseline(coreCtx, customerID, templateScope(tmpl.ID), tmpl.Baseline)
	if errors.Is(err, api.ErrBaselineTenantNotRegistered) && s.templates.RegisterTenant != nil {
		if err := s.templates.RegisterTenant(coreCtx, customerID, tenant.Name, "provider-template-onboard:"+customerID); err != nil {
			return TemplateApplication{}, fmt.Errorf("provider: register the customer's tenant: %w", err)
		}
		applied, err = s.templates.Baselines.ApplyTenantBaseline(coreCtx, customerID, templateScope(tmpl.ID), tmpl.Baseline)
	}
	if err != nil {
		return TemplateApplication{}, err
	}
	now := s.clock().UTC()
	app := TemplateApplication{TenantID: customerID, TemplateID: tmpl.ID, Version: tmpl.Version, Digest: tmpl.Digest,
		Complete: applied.Complete, Results: applied.Results, AppliedBy: actor.ID, AppliedAt: now.Format(timeLayout)}
	canonical, err := s.emit(ctx, EventTenantTemplateApplied, customerID, AuthorityEvent{
		TemplateApplication: &app, EffectiveAt: now,
		Audit: AuditEvent{Type: EventTenantTemplateApplied, TenantID: customerID, OperatorID: actor.ID, OperatorEmail: actor.Email,
			Subject: tmpl.ID, Reason: applicationSummary(tmpl, applied), At: now},
	})
	if err != nil {
		return TemplateApplication{}, err
	}
	if canonical.TemplateApplication != nil {
		app = *canonical.TemplateApplication
	}
	return app, nil
}

func applicationSummary(tmpl TenantTemplate, applied api.TenantBaselineApplication) string {
	counts := map[string]int{}
	for _, r := range applied.Results {
		counts[r.Outcome]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
	}
	return fmt.Sprintf("template %s version %d: %s", tmpl.ID, tmpl.Version, strings.Join(parts, ", "))
}

// TemplateDrift reads a delegated customer's objects against the version it was
// last applied.
func (s *Service) TemplateDrift(ctx context.Context, actor Operator, customerID string) (TemplateDrift, error) {
	if err := s.requireOperator(actor); err != nil {
		return TemplateDrift{}, err
	}
	if err := s.authorize(ctx, actor, customerID, OpRead); err != nil {
		return TemplateDrift{}, err
	}
	if err := s.templatesReady(); err != nil {
		return TemplateDrift{}, err
	}
	binding, err := s.templates.Store.TenantTemplateBinding(ctx, customerID)
	if err != nil {
		return TemplateDrift{}, err
	}
	if binding == nil {
		return TemplateDrift{}, ErrTenantNotTemplated
	}
	tmpl, latest, err := s.templateVersion(ctx, binding.TemplateID, binding.Version)
	if err != nil {
		return TemplateDrift{}, err
	}
	report, err := s.templates.Baselines.TenantBaselineDrift(ctx, customerID, templateScope(tmpl.ID), tmpl.Baseline)
	if err != nil {
		return TemplateDrift{}, err
	}
	return TemplateDrift{Binding: *binding, LatestVersion: latest, Report: report}, nil
}

// PreviewTemplateRollout says what applying a version would change in each
// customer, and writes nothing.
func (s *Service) PreviewTemplateRollout(ctx context.Context, actor Operator, templateID string, req RolloutRequest) (RolloutPreview, error) {
	if err := s.requirePermission(ctx, actor, PermTemplatesWrite); err != nil {
		return RolloutPreview{}, err
	}
	if err := s.templatesReady(); err != nil {
		return RolloutPreview{}, err
	}
	tmpl, _, err := s.templateVersion(ctx, templateID, req.Version)
	if err != nil {
		return RolloutPreview{}, err
	}
	customers, err := s.rolloutCustomers(ctx, actor, tmpl.ID, req.TenantIDs)
	if err != nil {
		return RolloutPreview{}, err
	}
	preview := RolloutPreview{TemplateID: tmpl.ID, Version: tmpl.Version, Digest: tmpl.Digest, Tenants: []RolloutTenant{}}
	fingerprint := []string{"trstctl.provider.template-rollout.v1", tmpl.ID, fmt.Sprint(tmpl.Version), tmpl.Digest}
	for _, c := range customers {
		report, err := s.templates.Baselines.TenantBaselineDrift(ctx, c.TenantID, templateScope(tmpl.ID), tmpl.Baseline)
		if err != nil {
			return RolloutPreview{}, fmt.Errorf("provider: preview customer %s: %w", c.TenantID, err)
		}
		row := RolloutTenant{TenantID: c.TenantID, CurrentVersion: c.Version, InSync: report.InSync, Changes: []api.BaselineObjectState{}}
		fingerprint = append(fingerprint, c.TenantID, fmt.Sprint(c.Version))
		for _, o := range report.Objects {
			fingerprint = append(fingerprint, o.Kind, o.Key, o.Status, o.ActualDigest)
			if o.Status != api.BaselineInSync {
				row.Changes = append(row.Changes, o)
			}
		}
		preview.Tenants = append(preview.Tenants, row)
	}
	preview.Fingerprint = crypto.SHA256Hex([]byte(strings.Join(fingerprint, "\x00")))
	return preview, nil
}

// RolloutTemplate applies a version across customers exactly as previewed: when
// any customer changed since the preview, nothing is applied and the caller
// previews again.
func (s *Service) RolloutTemplate(ctx context.Context, actor Operator, templateID string, req RolloutRequest) (RolloutResult, error) {
	preview, err := s.PreviewTemplateRollout(ctx, actor, templateID, req)
	if err != nil {
		return RolloutResult{}, err
	}
	if strings.TrimSpace(req.PreviewFingerprint) == "" || req.PreviewFingerprint != preview.Fingerprint {
		return RolloutResult{}, ErrTemplateRolloutStale
	}
	tmpl, _, err := s.templateVersion(ctx, templateID, preview.Version)
	if err != nil {
		return RolloutResult{}, err
	}
	out := RolloutResult{TemplateID: tmpl.ID, Version: tmpl.Version, Applications: []TemplateApplication{}}
	for _, t := range preview.Tenants {
		app, err := s.applyTemplate(ctx, actor, t.TenantID, tmpl)
		if err != nil {
			return out, fmt.Errorf("provider: apply to customer %s: %w", t.TenantID, err)
		}
		out.Applications = append(out.Applications, app)
	}
	return out, nil
}

// rolloutCustomers is the named customers, or every customer bound to the
// template, each one the operator may provision.
func (s *Service) rolloutCustomers(ctx context.Context, actor Operator, templateID string, named []string) ([]TemplateApplication, error) {
	bindings, err := s.templates.Store.TenantTemplateBindings(ctx, templateID)
	if err != nil {
		return nil, err
	}
	bound := map[string]TemplateApplication{}
	for _, b := range bindings {
		bound[b.TenantID] = b
	}
	var out []TemplateApplication
	if len(named) == 0 {
		for _, b := range bindings {
			if s.authorize(ctx, actor, b.TenantID, OpProvision) == nil {
				out = append(out, b)
			}
		}
		return out, nil
	}
	seen := map[string]bool{}
	for _, id := range named {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if err := s.authorize(ctx, actor, id, OpProvision); err != nil {
			return nil, err
		}
		b, ok := bound[id]
		if !ok {
			b = TemplateApplication{TenantID: id, TemplateID: templateID}
		}
		out = append(out, b)
	}
	return out, nil
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
