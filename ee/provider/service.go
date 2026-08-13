// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/orchestrator"
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
	License *license.Manager
	Store   Store
	Audit   AuditSink
	// Mutations is the AN-2 command boundary. Production supplies one immutable
	// event sink whose projection owns provider read tables. Nil retains the
	// in-memory unit-test adapter only; the assembled binary never leaves it nil.
	Mutations MutationSink
	// Activity derives operator-visible evidence from the same immutable
	// Provider event history. Production wires the event log; nil fails the
	// activity read closed rather than inventing an empty history.
	Activity ActivitySource
	// Idempotency caches the exact HTTP result around the independently durable
	// event receiver. Production supplies the shared PostgreSQL ledger and
	// tenant-bound result protector; nil is limited to in-memory unit adapters.
	Idempotency *orchestrator.Idempotency
	// Authenticator verifies a provider operator credential. NIL MEANS THE
	// PROVIDER PLANE REFUSES EVERY REQUEST, which is the only safe default.
	//
	// It exists because the previous code had no notion of verification at all:
	// operatorFromRequest parsed "Bearer provider:<id>:<email>" for SHAPE and
	// returned Operator{Role: OperatorAdmin, MFA: true}. Any string in that form
	// was a provider administrator. On a provider-tier binary /provider/ is
	// mounted on the root mux behind nothing but a bulkhead, so tenant create,
	// suspend, offboard and break-glass were reachable unauthenticated.
	//
	// Failing closed rather than shipping a placeholder verifier is deliberate:
	// a placeholder is how the previous behaviour came to exist, and a provider
	// plane that returns 503 until somebody wires real authentication is
	// strictly better than one that authorises everybody in the meantime.
	Authenticator OperatorAuthenticator
	// Delegations supplies which customers each operator may act on. NIL MEANS
	// THE PROVIDER PLANE REFUSES EVERY CUSTOMER-SCOPED ACTION, for the same
	// reason Authenticator has no default: authentication answers who an
	// operator is and answers nothing about which customers they may touch, and
	// a plane that cannot express the partition hands every operator the union
	// of every customer's risk.
	Delegations DelegationSource
	// Access is the event-projected operator lifecycle and complete delegation
	// inventory used by provider-admin access management. Nil fails that surface
	// closed; it never falls back to token claims as directory state.
	Access OperatorAccessStore
	// SAML owns the Provider-plane SP endpoints and separate browser session.
	// Nil simply means SAML is not one of the configured identity methods.
	SAML *SAMLAuthenticator
	// SCIM owns Provider workforce joiner/leaver provisioning. The handler binds
	// it to Access and Mutations; nil means no Provider SCIM endpoint is served.
	SCIM *SCIMConfig
	// Brands is the durable white-label store (L3). NIL MEANS BRAND
	// ADMINISTRATION REFUSES, like Quotas: a brand that cannot survive a
	// restart is not a white-label guarantee.
	Brands BrandStore
	// Quotas is the durable per-customer limit store (L2). NIL MEANS QUOTA
	// ADMINISTRATION REFUSES: accepting a cap that cannot survive a restart
	// would tell a provider their customer is limited when nothing is.
	Quotas    QuotaStore
	Telemetry TelemetryReader
	// Drills runs the on-demand isolation drill (L3). NIL MEANS THE DRILL
	// ENDPOINT REFUSES: a provider must not be told isolation "passed" by a
	// plane that has nothing wired to actually test it.
	Drills           IsolationDriller
	Clock            func() time.Time
	MaxBreakGlassTTL time.Duration
}

// OperatorAuthenticator verifies a provider-operator credential from a request.
//
// Implementations MUST verify the credential cryptographically or against a
// durable store; parsing it is not verification. Returning ok=false must be the
// answer for anything not positively authenticated.
type OperatorAuthenticator interface {
	AuthenticateOperator(r *http.Request) (Operator, bool)
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

// legacyCustomerRevoker is an in-memory/config-file test seam only. The
// PostgreSQL delegation reader deliberately does not implement it; production
// offboarding removes delegation rows inside the authority projection.
type legacyCustomerRevoker interface {
	RevokeAllForCustomer(context.Context, string) error
}

// IsolationDriller runs an on-demand tenant-isolation drill and reports the
// outcome. The provider plane holds only this narrow interface so it does not
// depend on the core store's drill implementation; the attach seam adapts the
// core store to it.
type IsolationDriller interface {
	RunIsolationDrill(ctx context.Context) (IsolationDrillReport, error)
}

// IsolationDrillCheck is one assertion in a drill and whether it held.
type IsolationDrillCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// IsolationDrillReport is the outcome the provider console shows and records.
type IsolationDrillReport struct {
	Passed bool                  `json:"passed"`
	Checks []IsolationDrillCheck `json:"checks"`
	RanAt  time.Time             `json:"ran_at"`
}

// Service enforces provider privilege-domain, license, tenant-band, and
// break-glass rules over the storage boundary.
type Service struct {
	license          *license.Manager
	store            Store
	audit            AuditSink
	mutations        MutationSink
	activity         ActivitySource
	authenticator    OperatorAuthenticator
	delegations      DelegationSource
	access           OperatorAccessStore
	telemetry        TelemetryReader
	quotas           QuotaStore
	brands           BrandStore
	drills           IsolationDriller
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
	// cfg.Authenticator is passed through UNCHANGED, with no default. Every
	// other dependency above falls back to a working stand-in; this one must
	// not, because the safe stand-in for "who is this caller" does not exist.
	// Nil here means the handler refuses every request.
	// delegations is deliberately NOT defaulted. A default here would be a
	// default answer to "which customers may this operator touch", and the only
	// safe default answer is none.
	return &Service{license: lic, store: store, audit: audit, authenticator: cfg.Authenticator,
		mutations: cfg.Mutations, activity: cfg.Activity,
		delegations: cfg.Delegations, access: cfg.Access, telemetry: telemetry, quotas: cfg.Quotas, brands: cfg.Brands,
		drills: cfg.Drills, clock: clock, maxBreakGlassTTL: maxTTL}
}

// ListActivity returns newest-first immutable Provider authority evidence,
// limited to the customers currently delegated to actor. Deployment-wide
// isolation-drill evidence is visible only to a Provider administrator.
func (s *Service) ListActivity(ctx context.Context, actor Operator, limit int) ([]ProviderActivity, error) {
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		return nil, ErrUnlicensed
	}
	if err := s.requireOperator(actor); err != nil {
		return nil, err
	}
	if s.activity == nil {
		return nil, errors.New("provider: immutable activity source is not configured")
	}
	if s.delegations == nil {
		return nil, fmt.Errorf("%w: no delegation source is configured", ErrForbidden)
	}
	set, err := s.delegations.Delegations(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: delegations could not be read", ErrForbidden)
	}
	visible := map[string]bool{}
	for _, customer := range set.CustomersFor(actor.ID) {
		visible[customer] = true
	}
	all, err := s.activity.ProviderActivity(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultProviderActivityLimit
	}
	if limit > maxProviderActivityLimit {
		limit = maxProviderActivityLimit
	}
	out := make([]ProviderActivity, 0, min(limit, len(all)))
	for index := len(all) - 1; index >= 0 && len(out) < limit; index-- {
		item := all[index]
		if visible[item.TenantID] || (item.TenantID == providerAuditTenant && actor.Role == OperatorAdmin) {
			out = append(out, item)
		}
	}
	return out, nil
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
	// The customer does not exist yet, so the grant is over the ID it WILL get.
	// Onboarding is scoped like every other operation rather than being a
	// blanket "may create customers": an operator who can conjure a tenancy of
	// any name can conjure one whose name collides with a real customer's.
	//
	// The id is a uuid derived deterministically from the slug (not "tenant-"+
	// slug) so it fits the durable registry's uuid key and lines up with the
	// core tenant world every other provider table keys on — quotas, meters,
	// and the per-customer certificate count all live under this same uuid. It
	// must be deterministic, not random, precisely because we authorize against
	// it here BEFORE the row exists: a random id could not be pre-delegated.
	id := CustomerID(slug)
	if err := s.authorize(ctx, actor, id, OpProvision); err != nil {
		return Tenant{}, err
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
	tenant := Tenant{ID: id, Slug: slug, Name: name, Status: TenantActive, CreatedAt: now, UpdatedAt: now}
	if s.mutations != nil {
		canonical, err := s.emit(ctx, AuditTenantProvisioned, tenant.ID, AuthorityEvent{Tenant: &tenant,
			Audit: AuditEvent{Type: AuditTenantProvisioned, TenantID: tenant.ID,
				OperatorID: actor.ID, OperatorEmail: actor.Email, At: now}})
		if err != nil {
			return Tenant{}, err
		}
		if canonical.Tenant == nil {
			return Tenant{}, errors.New("provider: canonical provision event has no tenant result")
		}
		tenant = *canonical.Tenant
	} else {
		legacy, ok := s.store.(legacyMutableStore)
		if !ok {
			return Tenant{}, errors.New("provider: production stores require the event mutation sink")
		}
		var err error
		tenant, err = legacy.CreateTenant(ctx, tenant)
		if err != nil {
			return Tenant{}, err
		}
		if err := s.record(ctx, AuditEvent{Type: AuditTenantProvisioned, TenantID: tenant.ID,
			OperatorID: actor.ID, OperatorEmail: actor.Email, At: now}); err != nil {
			return Tenant{}, err
		}
	}
	return tenant, nil
}

// ListTenants returns only the customers this operator is delegated.
//
// The unfiltered version leaked the provider's whole customer list to every
// operator. That is a disclosure on its own — a competitor's engineer working
// one tenancy could read the names of every other customer the provider has —
// and it is also the reconnaissance step for the cross-customer action the
// delegation set refuses: you cannot ask to suspend a tenancy you cannot name.
//
// Filtering here rather than in the handler because the handler is not the only
// caller, and a list built from an unfiltered read is one refactor away from
// being returned.
func (s *Service) ListTenants(ctx context.Context, actor Operator) ([]Tenant, error) {
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		return nil, ErrUnlicensed
	}
	if err := s.requireOperator(actor); err != nil {
		return nil, err
	}
	if s.delegations == nil {
		return nil, fmt.Errorf("%w: no delegation source is configured", ErrForbidden)
	}
	set, err := s.delegations.Delegations(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: delegations could not be read", ErrForbidden)
	}
	visible := map[string]bool{}
	for _, customer := range set.CustomersFor(actor.ID) {
		visible[customer] = true
	}
	all, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	// Non-nil empty rather than nil: an operator with no delegations gets an
	// empty list, which is the true answer, not a null the caller may render as
	// "could not load".
	out := make([]Tenant, 0, len(all))
	for _, t := range all {
		if visible[t.ID] {
			out = append(out, t)
		}
	}
	return out, nil
}

// RunIsolationDrill runs the on-demand tenant-isolation drill and records an
// attestation of the outcome.
//
// This is deployment-wide assurance, not a per-customer read, so it is gated on
// provider ADMIN rather than a per-customer delegation: no single customer
// "owns" the isolation invariant, and an operator delegated one tenancy has no
// standing to probe the whole deployment. The attestation is recorded whatever
// the result — a FAILED drill is the one you most need on the record, so a
// failure is returned as a report with Passed=false, not swallowed as an error.
func (s *Service) RunIsolationDrill(ctx context.Context, actor Operator) (IsolationDrillReport, error) {
	if err := s.requireMutation(actor, true); err != nil {
		return IsolationDrillReport{}, err
	}
	if s.drills == nil {
		return IsolationDrillReport{}, fmt.Errorf("%w: no isolation driller is attached on this deployment, so a "+
			"drill result would be fabricated; refusing to report a pass nothing tested", ErrForbidden)
	}
	report, err := s.drills.RunIsolationDrill(ctx)
	if err != nil {
		return IsolationDrillReport{}, err
	}
	report.RanAt = s.clock()
	outcome := "passed"
	if !report.Passed {
		outcome = "failed"
	}
	audit := AuditEvent{Type: "provider.isolation.drill", OperatorID: actor.ID,
		OperatorEmail: actor.Email, Reason: outcome, At: report.RanAt}
	if s.mutations != nil {
		canonical, err := s.emit(ctx, audit.Type, providerAuditTenant, AuthorityEvent{Audit: audit, Drill: &report})
		if err != nil {
			return IsolationDrillReport{}, err
		}
		if canonical.Drill == nil {
			return IsolationDrillReport{}, errors.New("provider: canonical isolation-drill event has no report")
		}
		report = *canonical.Drill
	} else if err := s.record(ctx, audit); err != nil {
		return IsolationDrillReport{}, err
	}
	return report, nil
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
	// A snapshot is a read of a customer's whole estate, so it is delegated
	// like any other action. "Read-only" is not "harmless" when the thing read
	// is another customer's inventory.
	if err := s.authorize(ctx, actor, tenantID, OpRead); err != nil {
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
	// Break-glass is its own grant. An operator trusted to run a customer's
	// day-to-day tenancy is not automatically trusted to ask for emergency
	// access into it, and the tenant consent that follows is a second gate, not
	// a substitute for this one.
	if err := s.authorize(ctx, actor, req.TenantID, OpBreakGlass); err != nil {
		return BreakGlassGrant{}, err
	}
	if _, err := s.store.Tenant(ctx, req.TenantID); err != nil {
		return BreakGlassGrant{}, err
	}
	now := s.clock()
	grant := BreakGlassGrant{
		TenantID:      req.TenantID,
		OperatorID:    actor.ID,
		OperatorEmail: actor.Email,
		Reason:        strings.TrimSpace(req.Reason),
		RequestedAt:   now,
		ExpiresAt:     now.Add(req.TTL),
	}
	if s.mutations != nil {
		grant.ID = stableGrantID(req.TenantID, mutationKeyFromContext(ctx))
		canonical, err := s.emit(ctx, AuditBreakGlassRequested, grant.TenantID, AuthorityEvent{Grant: &grant,
			Audit: AuditEvent{Type: AuditBreakGlassRequested, TenantID: grant.TenantID,
				OperatorID: actor.ID, OperatorEmail: actor.Email, GrantID: grant.ID, Reason: grant.Reason, At: now}})
		if err != nil {
			return BreakGlassGrant{}, err
		}
		if canonical.Grant == nil {
			return BreakGlassGrant{}, errors.New("provider: canonical break-glass request has no grant")
		}
		grant = *canonical.Grant
	} else {
		legacy, ok := s.store.(legacyMutableStore)
		if !ok {
			return BreakGlassGrant{}, errors.New("provider: production stores require the event mutation sink")
		}
		var err error
		grant, err = legacy.CreateBreakGlassGrant(ctx, grant)
		if err != nil {
			return BreakGlassGrant{}, err
		}
		if err := s.record(ctx, AuditEvent{Type: AuditBreakGlassRequested, TenantID: grant.TenantID,
			OperatorID: actor.ID, OperatorEmail: actor.Email, GrantID: grant.ID,
			Reason: grant.Reason, At: now}); err != nil {
			return BreakGlassGrant{}, err
		}
	}
	return grant, nil
}

func (s *Service) ConsentBreakGlass(ctx context.Context, tenantID, grantID, subject string, approve bool) (BreakGlassGrant, error) {
	if s.license.Mode(license.FeatureProviderPlane) == license.ModeOff {
		return BreakGlassGrant{}, ErrUnlicensed
	}
	subject = strings.TrimSpace(subject)
	grant, err := s.store.BreakGlassGrant(ctx, grantID)
	if err != nil {
		return BreakGlassGrant{}, err
	}
	if grant.TenantID != tenantID {
		return BreakGlassGrant{}, ErrForbidden
	}
	now := s.clock()
	switch grant.State(now) {
	case GrantPending, GrantAwaitingCoConsent:
		// Consentable states: nobody has approved yet, or one approver has and a
		// second is awaited.
	default:
		// Already active, denied, revoked, or expired — nothing to consent to.
		return BreakGlassGrant{}, ErrBreakGlassAlreadyResolved
	}

	// A denial by ANY approver, at either stage, kills the grant. One person
	// refusing is enough to stop emergency access even if another already
	// consented — two-person control protects access, not denial.
	if !approve {
		grant.DeniedAt = now
		grant.DeniedBy = subject
		if s.mutations != nil {
			canonical, emitErr := s.emit(ctx, AuditBreakGlassDenied, grant.TenantID, AuthorityEvent{Grant: &grant,
				Audit: AuditEvent{Type: AuditBreakGlassDenied, TenantID: grant.TenantID,
					GrantID: grant.ID, Subject: subject, At: now}})
			if emitErr != nil {
				return BreakGlassGrant{}, emitErr
			}
			if canonical.Grant == nil {
				return BreakGlassGrant{}, errors.New("provider: canonical break-glass denial has no grant")
			}
			grant = *canonical.Grant
		} else {
			legacy, ok := s.store.(legacyMutableStore)
			if !ok {
				return BreakGlassGrant{}, errors.New("provider: production stores require the event mutation sink")
			}
			grant, err = legacy.UpdateBreakGlassGrant(ctx, grant)
			if err != nil {
				return BreakGlassGrant{}, err
			}
			if err := s.record(ctx, AuditEvent{Type: AuditBreakGlassDenied, TenantID: grant.TenantID,
				GrantID: grant.ID, Subject: subject, At: now}); err != nil {
				return BreakGlassGrant{}, err
			}
		}
		return grant, nil
	}

	// Two-person control on approval: a real approver identity, never the
	// requester, and the two approvers must be distinct operators.
	if subject == "" {
		return BreakGlassGrant{}, ErrForbidden
	}
	if subject == grant.OperatorID {
		return BreakGlassGrant{}, ErrBreakGlassConsentByRequester
	}
	if grant.State(now) == GrantPending {
		grant.ConsentedAt = now
		grant.ConsentedBy = subject
	} else { // GrantAwaitingCoConsent
		if subject == grant.ConsentedBy {
			return BreakGlassGrant{}, ErrBreakGlassConsentNotDistinct
		}
		grant.SecondConsentedAt = now
		grant.SecondConsentedBy = subject
	}
	if s.mutations != nil {
		canonical, emitErr := s.emit(ctx, AuditBreakGlassConsented, grant.TenantID, AuthorityEvent{Grant: &grant,
			Audit: AuditEvent{Type: AuditBreakGlassConsented, TenantID: grant.TenantID,
				GrantID: grant.ID, Subject: subject, At: now}})
		if emitErr != nil {
			return BreakGlassGrant{}, emitErr
		}
		if canonical.Grant == nil {
			return BreakGlassGrant{}, errors.New("provider: canonical break-glass consent has no grant")
		}
		grant = *canonical.Grant
	} else {
		legacy, ok := s.store.(legacyMutableStore)
		if !ok {
			return BreakGlassGrant{}, errors.New("provider: production stores require the event mutation sink")
		}
		grant, err = legacy.UpdateBreakGlassGrant(ctx, grant)
		if err != nil {
			return BreakGlassGrant{}, err
		}
		if err := s.record(ctx, AuditEvent{Type: AuditBreakGlassConsented, TenantID: grant.TenantID,
			GrantID: grant.ID, Subject: subject, At: now}); err != nil {
			return BreakGlassGrant{}, err
		}
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
	// Re-checked at USE time, not only when the grant was requested. A
	// delegation revoked after a grant was consented must stop the access it
	// would otherwise still authorise — otherwise revocation only takes effect
	// for operators who had not already asked.
	if err := s.authorize(ctx, actor, grant.TenantID, OpBreakGlass); err != nil {
		return TenantSnapshot{}, err
	}
	now := s.clock()
	switch state := grant.State(now); state {
	case GrantActive:
	case GrantExpired:
		return TenantSnapshot{}, ErrBreakGlassExpired
	default:
		return TenantSnapshot{}, ErrBreakGlassNotConsented
	}
	if s.mutations != nil {
		snapshot, err := s.telemetry.TenantSnapshot(ctx, grant.TenantID)
		if err != nil {
			return TenantSnapshot{}, err
		}
		grant.UseCount++
		canonical, emitErr := s.emit(ctx, AuditBreakGlassAccessed, grant.TenantID, AuthorityEvent{Grant: &grant, Snapshot: &snapshot,
			Audit: AuditEvent{Type: AuditBreakGlassAccessed, TenantID: grant.TenantID,
				OperatorID: actor.ID, OperatorEmail: actor.Email, GrantID: grant.ID, At: now}})
		if emitErr != nil {
			return TenantSnapshot{}, emitErr
		}
		if canonical.Snapshot == nil {
			return TenantSnapshot{}, errors.New("provider: canonical break-glass access event has no snapshot")
		}
		return *canonical.Snapshot, nil
	}
	if err := s.record(ctx, AuditEvent{Type: AuditBreakGlassAccessed, TenantID: grant.TenantID,
		OperatorID: actor.ID, OperatorEmail: actor.Email, GrantID: grant.ID, At: now}); err != nil {
		return TenantSnapshot{}, err
	}
	snapshot, err := s.telemetry.TenantSnapshot(ctx, grant.TenantID)
	if err != nil {
		return TenantSnapshot{}, err
	}
	legacy, ok := s.store.(legacyMutableStore)
	if !ok {
		return TenantSnapshot{}, errors.New("provider: production stores require the event mutation sink")
	}
	if err := legacy.IncrementBreakGlassUse(ctx, grant.ID, now); err != nil {
		return TenantSnapshot{}, err
	}
	return snapshot, nil
}

func (s *Service) setTenantStatus(ctx context.Context, actor Operator, tenantID string, status TenantStatus, auditType string) error {
	if err := s.requireMutation(actor, true); err != nil {
		return err
	}
	// Suspend and offboard are separate grants. Suspend interrupts a live
	// service; offboard DESTROYS. Being trusted with the first is not being
	// trusted with the second, so the operation is derived from the status
	// rather than folded into one "may change status" permission.
	//
	// The mapping is TOTAL rather than "offboard, else suspend". There is no
	// resume route today, so OpResume is granted and never checked — but the
	// day one is added, a defaulting map would authorise resuming a customer
	// with a suspend grant, and "may pause" would silently become "may
	// un-pause" for every operator who already had it.
	var op Operation
	switch status {
	case TenantOffboarded:
		op = OpOffboard
	case TenantSuspended:
		op = OpSuspend
	case TenantActive:
		op = OpResume
	default:
		// An unknown status is refused rather than mapped to the mildest
		// operation available.
		return fmt.Errorf("%w: no delegable operation corresponds to status %q", ErrForbidden, status)
	}
	if err := s.authorize(ctx, actor, tenantID, op); err != nil {
		return err
	}
	tenant, err := s.store.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	now := s.clock()
	tenant.Status, tenant.UpdatedAt = status, now
	if s.mutations != nil {
		_, emitErr := s.emit(ctx, auditType, tenant.ID, AuthorityEvent{Tenant: &tenant,
			Audit: AuditEvent{Type: auditType, TenantID: tenant.ID,
				OperatorID: actor.ID, OperatorEmail: actor.Email, At: now}})
		if emitErr != nil {
			return emitErr
		}
	} else {
		legacy, ok := s.store.(legacyMutableStore)
		if !ok {
			return errors.New("provider: production stores require the event mutation sink")
		}
		tenant, err = legacy.UpdateTenantStatus(ctx, tenantID, status, now)
		if err != nil {
			return err
		}
		if err := s.record(ctx, AuditEvent{Type: auditType, TenantID: tenant.ID,
			OperatorID: actor.ID, OperatorEmail: actor.Email, At: now}); err != nil {
			return err
		}
	}
	if status == TenantOffboarded && s.mutations == nil {
		if revoker, ok := s.delegations.(legacyCustomerRevoker); ok {
			if err := revoker.RevokeAllForCustomer(ctx, tenant.ID); err != nil {
				return fmt.Errorf("provider: customer %s was offboarded but its legacy operator delegations could not be cleared: %w", tenant.ID, err)
			}
		}
	}
	return nil
}

func (s *Service) emit(ctx context.Context, typ, tenantID string, payload AuthorityEvent) (AuthorityEvent, error) {
	key := mutationKeyFromContext(ctx)
	if key == "" {
		return AuthorityEvent{}, errors.New("provider: Idempotency-Key is required for mutations")
	}
	event, err := s.mutations.Append(ctx, key, typ, tenantID, payload)
	if err != nil {
		return AuthorityEvent{}, err
	}
	var canonical AuthorityEvent
	if err := json.Unmarshal(event.Data, &canonical); err != nil {
		return AuthorityEvent{}, fmt.Errorf("provider: decode canonical %s result: %w", typ, err)
	}
	return canonical, nil
}

func stableGrantID(tenantID, key string) string {
	return "grant-" + uuid.NewSHA1(providerMutationNamespace, []byte(tenantID+"\x00"+strings.TrimSpace(key))).String()
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

// authorize is the ONE place a customer-scoped provider action is permitted.
//
// Both axes must be satisfied explicitly: the operator must be delegated this
// customer, and delegated this operation on it. Every failure mode — no source
// configured, the source erroring, no grant — refuses. They are deliberately
// indistinguishable to the caller in outcome, because an operator who could
// tell "the delegation service is down" from "you have no grant" could probe
// which customers exist by watching which error they get.
func (s *Service) authorize(ctx context.Context, actor Operator, customerID string, op Operation) error {
	if s.delegations == nil {
		return fmt.Errorf("%w: no delegation source is configured, so no operator may act on any "+
			"customer. Reading an absent delegation source as \"everything is permitted\" is how one "+
			"customer's operator reaches into another's tenancy", ErrForbidden)
	}
	set, err := s.delegations.Delegations(ctx)
	if err != nil {
		// Fail closed on a read failure. Serving on an unreadable grant table
		// would mean the plane is widest exactly when it is least healthy.
		return fmt.Errorf("%w: delegations could not be read, so the action is refused", ErrForbidden)
	}
	if err := set.Authorize(actor, customerID, op); err != nil {
		return fmt.Errorf("%w: %s", ErrForbidden, err.Error())
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
