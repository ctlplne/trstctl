package provider

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
)

const (
	AuditTenantProvisioned   = "provider.tenant_provision"
	AuditTenantSuspended     = "provider.tenant_suspend"
	AuditTenantOffboarded    = "provider.tenant_offboard"
	AuditBreakGlassRequested = "provider.breakglass_request"
	AuditBreakGlassConsented = "provider.breakglass_consent"
	AuditBreakGlassDenied    = "provider.breakglass_deny"
	AuditBreakGlassAccessed  = "provider.breakglass_access"
	providerAuditTenant      = "provider-control-plane"
	defaultMaxBreakGlassTTL  = 2 * time.Hour
	defaultBreakGlassTTL     = 30 * time.Minute
)

// Config wires the provider service. Core supplies this only through the tagged
// EE attach seam when the provider-plane feature is licensed.
type Config struct {
	License          *license.Manager
	Store            Store
	Audit            AuditSink
	Telemetry        TelemetryReader
	Clock            func() time.Time
	MaxBreakGlassTTL time.Duration
}

// ProvisionRequest creates a tenant lifecycle record.
type ProvisionRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// BreakGlassRequest opens a pending tenant-consent grant.
type BreakGlassRequest struct {
	TenantID string        `json:"tenant_id"`
	Reason   string        `json:"reason"`
	TTL      time.Duration `json:"ttl"`
}

// AuditEvent is the provider audit stream envelope.
type AuditEvent struct {
	Type          string    `json:"type"`
	TenantID      string    `json:"tenant_id,omitempty"`
	OperatorID    string    `json:"operator_id,omitempty"`
	OperatorEmail string    `json:"operator_email,omitempty"`
	GrantID       string    `json:"grant_id,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	At            time.Time `json:"at"`
}

type AuditSink interface {
	RecordProviderAudit(context.Context, AuditEvent) error
}

type TelemetryReader interface {
	TenantSnapshot(context.Context, string) (TenantSnapshot, error)
}

// Service enforces provider privilege-domain, license, tenant-band, and
// break-glass rules over the storage boundary.
type Service struct {
	license          *license.Manager
	store            Store
	audit            AuditSink
	telemetry        TelemetryReader
	clock            func() time.Time
	maxBreakGlassTTL time.Duration
}

func NewService(cfg Config) *Service {
	lic := cfg.License
	if lic == nil {
		lic = license.Community()
	}
	store := cfg.Store
	if store == nil {
		store = NewMemStore()
	}
	audit := cfg.Audit
	if audit == nil {
		audit = noopAudit{}
	}
	telemetry := cfg.Telemetry
	if telemetry == nil {
		telemetry = emptyTelemetry{}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	maxTTL := cfg.MaxBreakGlassTTL
	if maxTTL <= 0 {
		maxTTL = defaultMaxBreakGlassTTL
	}
	return &Service{license: lic, store: store, audit: audit, telemetry: telemetry, clock: clock, maxBreakGlassTTL: maxTTL}
}

func (s *Service) Provision(ctx context.Context, actor Operator, req ProvisionRequest) (Tenant, error) {
	if err := s.requireMutation(actor, true); err != nil {
		return Tenant{}, err
	}
	slug := strings.TrimSpace(req.Slug)
	name := strings.TrimSpace(req.Name)
	if slug == "" || name == "" {
		return Tenant{}, errors.New("provider: tenant slug and name are required")
	}
	if band := s.license.TenantBand(); band > 0 {
		count, err := s.store.CountBillableTenants(ctx)
		if err != nil {
			return Tenant{}, err
		}
		if count >= band {
			return Tenant{}, ErrTenantBandExhausted
		}
	}
	now := s.clock()
	tenant, err := s.store.CreateTenant(ctx, Tenant{ID: "tenant-" + slug, Slug: slug, Name: name, Status: TenantActive, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		return Tenant{}, err
	}
	if err := s.record(ctx, AuditEvent{Type: AuditTenantProvisioned, TenantID: tenant.ID, OperatorID: actor.ID, OperatorEmail: actor.Email, At: now}); err != nil {
		return Tenant{}, err
	}
	return tenant, nil
}

func (s *Service) ListTenants(ctx context.Context) ([]Tenant, error) {
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		return nil, ErrUnlicensed
	}
	return s.store.ListTenants(ctx)
}

func (s *Service) Suspend(ctx context.Context, actor Operator, tenantID string) error {
	return s.setTenantStatus(ctx, actor, tenantID, TenantSuspended, AuditTenantSuspended)
}

func (s *Service) Offboard(ctx context.Context, actor Operator, tenantID string) error {
	return s.setTenantStatus(ctx, actor, tenantID, TenantOffboarded, AuditTenantOffboarded)
}

func (s *Service) DirectTenantSnapshot(ctx context.Context, actor Operator, tenantID string) (TenantSnapshot, error) {
	if err := s.requireOperator(actor); err != nil {
		return TenantSnapshot{}, err
	}
	return s.store.DirectTenantSnapshot(ctx, tenantID)
}

func (s *Service) RequestBreakGlass(ctx context.Context, actor Operator, req BreakGlassRequest) (BreakGlassGrant, error) {
	if err := s.requireMutation(actor, false); err != nil {
		return BreakGlassGrant{}, err
	}
	if strings.TrimSpace(req.Reason) == "" {
		return BreakGlassGrant{}, ErrBreakGlassReasonRequired
	}
	if req.TTL == 0 {
		req.TTL = defaultBreakGlassTTL
	}
	if req.TTL < 0 || req.TTL > s.maxBreakGlassTTL {
		return BreakGlassGrant{}, ErrBreakGlassInvalidDuration
	}
	if _, err := s.store.Tenant(ctx, req.TenantID); err != nil {
		return BreakGlassGrant{}, err
	}
	now := s.clock()
	grant, err := s.store.CreateBreakGlassGrant(ctx, BreakGlassGrant{
		TenantID:      req.TenantID,
		OperatorID:    actor.ID,
		OperatorEmail: actor.Email,
		Reason:        strings.TrimSpace(req.Reason),
		RequestedAt:   now,
		ExpiresAt:     now.Add(req.TTL),
	})
	if err != nil {
		return BreakGlassGrant{}, err
	}
	if err := s.record(ctx, AuditEvent{Type: AuditBreakGlassRequested, TenantID: grant.TenantID, OperatorID: actor.ID, OperatorEmail: actor.Email, GrantID: grant.ID, Reason: grant.Reason, At: now}); err != nil {
		return BreakGlassGrant{}, err
	}
	return grant, nil
}

func (s *Service) ConsentBreakGlass(ctx context.Context, tenantID, grantID, subject string, approve bool) (BreakGlassGrant, error) {
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		return BreakGlassGrant{}, ErrUnlicensed
	}
	grant, err := s.store.BreakGlassGrant(ctx, grantID)
	if err != nil {
		return BreakGlassGrant{}, err
	}
	if grant.TenantID != tenantID {
		return BreakGlassGrant{}, ErrForbidden
	}
	if grant.State(s.clock()) != GrantPending {
		return BreakGlassGrant{}, ErrBreakGlassNotConsented
	}
	now := s.clock()
	auditType := AuditBreakGlassConsented
	if approve {
		grant.ConsentedAt = now
		grant.ConsentedBy = subject
	} else {
		grant.DeniedAt = now
		grant.DeniedBy = subject
		auditType = AuditBreakGlassDenied
	}
	grant, err = s.store.UpdateBreakGlassGrant(ctx, grant)
	if err != nil {
		return BreakGlassGrant{}, err
	}
	if err := s.record(ctx, AuditEvent{Type: auditType, TenantID: grant.TenantID, GrantID: grant.ID, Subject: subject, At: now}); err != nil {
		return BreakGlassGrant{}, err
	}
	return grant, nil
}

func (s *Service) BreakGlassResults(ctx context.Context, actor Operator, grantID string) (TenantSnapshot, error) {
	if err := s.requireOperator(actor); err != nil {
		return TenantSnapshot{}, err
	}
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		return TenantSnapshot{}, ErrUnlicensed
	}
	grant, err := s.store.BreakGlassGrant(ctx, grantID)
	if err != nil {
		return TenantSnapshot{}, err
	}
	if grant.OperatorID != actor.ID {
		return TenantSnapshot{}, ErrBreakGlassWrongOperator
	}
	now := s.clock()
	switch state := grant.State(now); state {
	case GrantActive:
	case GrantExpired:
		return TenantSnapshot{}, ErrBreakGlassExpired
	default:
		return TenantSnapshot{}, ErrBreakGlassNotConsented
	}
	if err := s.record(ctx, AuditEvent{Type: AuditBreakGlassAccessed, TenantID: grant.TenantID, OperatorID: actor.ID, OperatorEmail: actor.Email, GrantID: grant.ID, At: now}); err != nil {
		return TenantSnapshot{}, err
	}
	snapshot, err := s.telemetry.TenantSnapshot(ctx, grant.TenantID)
	if err != nil {
		return TenantSnapshot{}, err
	}
	if err := s.store.IncrementBreakGlassUse(ctx, grant.ID, now); err != nil {
		return TenantSnapshot{}, err
	}
	return snapshot, nil
}

func (s *Service) setTenantStatus(ctx context.Context, actor Operator, tenantID string, status TenantStatus, auditType string) error {
	if err := s.requireMutation(actor, true); err != nil {
		return err
	}
	tenant, err := s.store.UpdateTenantStatus(ctx, tenantID, status, s.clock())
	if err != nil {
		return err
	}
	return s.record(ctx, AuditEvent{Type: auditType, TenantID: tenant.ID, OperatorID: actor.ID, OperatorEmail: actor.Email, At: s.clock()})
}

func (s *Service) requireMutation(actor Operator, adminOnly bool) error {
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		return ErrUnlicensed
	}
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeReadOnly {
		return ErrReadOnly
	}
	if err := s.requireOperator(actor); err != nil {
		return err
	}
	if adminOnly && actor.Role != OperatorAdmin {
		return ErrForbidden
	}
	return nil
}

func (s *Service) requireOperator(actor Operator) error {
	if actor.ID == "" || !actor.MFA {
		return ErrForbidden
	}
	if actor.Role == "" {
		return ErrForbidden
	}
	return nil
}

func (s *Service) record(ctx context.Context, event AuditEvent) error {
	if event.At.IsZero() {
		event.At = s.clock()
	}
	return s.audit.RecordProviderAudit(ctx, event)
}

type noopAudit struct{}

func (noopAudit) RecordProviderAudit(context.Context, AuditEvent) error { return nil }

type emptyTelemetry struct{}

func (emptyTelemetry) TenantSnapshot(_ context.Context, tenantID string) (TenantSnapshot, error) {
	return TenantSnapshot{TenantID: tenantID, Health: "unknown"}, nil
}

type eventLogAudit struct {
	log *events.Log
}

// NewEventLogAuditSink records provider audit events into the immutable event log.
func NewEventLogAuditSink(log *events.Log) AuditSink {
	if log == nil {
		return noopAudit{}
	}
	return eventLogAudit{log: log}
}

func (s eventLogAudit) RecordProviderAudit(ctx context.Context, event AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, events.Event{Type: event.Type, TenantID: providerAuditTenant, Data: payload})
	return err
}
