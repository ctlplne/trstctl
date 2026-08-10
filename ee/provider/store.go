// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package provider implements the licensed Provider/MSP plane.
package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	CodeTenantBandExhausted = "tenant_band_exhausted"
)

var (
	ErrTenantBandExhausted = errors.New("provider: tenant_band_exhausted")
	ErrForbidden           = errors.New("provider: forbidden")
	// ErrProviderUnauthenticated is returned when no configured authenticator
	// positively identified the caller. A nil authenticator produces it for
	// every request, which is the intended state of an unconfigured provider
	// plane: closed, not open.
	ErrProviderUnauthenticated = errors.New("provider: request is not authenticated")
	// ErrProviderConsentSubjectNotSettable rejects a break-glass consent that
	// tries to name its own approver. The consenting subject is the
	// authenticated caller; accepting the body field is what let a requester
	// approve their own grant, and silently ignoring it would let an
	// integration keep sending one and believe it worked.
	ErrProviderConsentSubjectNotSettable = errors.New(
		"provider: consent subject is taken from the authenticated operator and must not be supplied")
	ErrUnlicensed                = errors.New("provider: unlicensed")
	ErrReadOnly                  = errors.New("provider: read-only license")
	ErrNotFound                  = errors.New("provider: not found")
	ErrBreakGlassNotConsented    = errors.New("provider: break-glass grant is not active")
	ErrBreakGlassWrongOperator   = errors.New("provider: break-glass grant is bound to another operator")
	ErrBreakGlassExpired         = errors.New("provider: break-glass grant expired")
	ErrBreakGlassReasonRequired  = errors.New("provider: break-glass reason is required")
	ErrBreakGlassInvalidDuration = errors.New("provider: break-glass duration is invalid")
	// ErrBreakGlassConsentByRequester rejects the requester approving their own
	// break-glass request. The requester asking for emergency access is not one
	// of the two independent approvers that access requires (L4 dual consent).
	ErrBreakGlassConsentByRequester = errors.New("provider: the break-glass requester cannot approve their own request")
	// ErrBreakGlassConsentNotDistinct rejects one operator supplying both
	// consents. Two-person control needs two DIFFERENT people; the same operator
	// approving twice is one person, not two.
	ErrBreakGlassConsentNotDistinct = errors.New("provider: break-glass needs two distinct approvers; this operator already consented")
	// ErrBreakGlassAlreadyResolved rejects consenting to a grant that is no
	// longer awaiting consent (already active, denied, revoked, or expired).
	ErrBreakGlassAlreadyResolved = errors.New("provider: break-glass grant is no longer awaiting consent")
)

// OperatorRole names a provider-plane privilege set. Provider operators are not
// tenant users; the provider token/session issuer must have already completed MFA.
type OperatorRole string

const (
	OperatorAdmin    OperatorRole = "admin"
	OperatorOperator OperatorRole = "operator"
)

// Operator is the authenticated provider principal.
type Operator struct {
	ID      string       `json:"id"`
	Email   string       `json:"email"`
	Role    OperatorRole `json:"role"`
	MFA     bool         `json:"mfa"`
	Session string       `json:"session,omitempty"`
}

// TenantStatus is the provider-visible lifecycle state.
type TenantStatus string

const (
	TenantActive     TenantStatus = "active"
	TenantSuspended  TenantStatus = "suspended"
	TenantOffboarded TenantStatus = "offboarded"
)

// providerCustomerNamespace names the space customer ids are minted in. A fixed
// namespace makes CustomerID(slug) stable across processes and deployments, so
// the same slug always resolves to the same tenancy uuid.
var providerCustomerNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl.com/provider/customer"))

// CustomerID is the durable tenancy uuid for a customer slug.
//
// A provider customer is a core tenancy — the same uuid that keys its quotas,
// usage meters, and certificate inventory — so the id must be a uuid, not a
// "tenant-<slug>" label. It is derived deterministically from the slug (RFC 4122
// v5) so a not-yet-created customer can be authorized against the id it will
// receive, and so a re-provision of the same slug is an idempotent hit on the
// same row rather than a second tenancy.
func CustomerID(slug string) string {
	return uuid.NewSHA1(providerCustomerNamespace, []byte(strings.ToLower(strings.TrimSpace(slug)))).String()
}

// Tenant is provider-plane metadata only. It is not tenant credential data.
type Tenant struct {
	ID        string       `json:"id"`
	Slug      string       `json:"slug"`
	Name      string       `json:"name"`
	Status    TenantStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// TenantSnapshot is the narrow tenant-data payload returned only by an active,
// consented break-glass grant.
type TenantSnapshot struct {
	TenantID           string `json:"tenant_id"`
	Health             string `json:"health"`
	ActiveCertificates int    `json:"active_certificates"`
}

// GrantState is the derived state of a break-glass grant.
type GrantState string

const (
	GrantPending GrantState = "pending"
	// GrantAwaitingCoConsent is a grant with ONE consent, waiting for the
	// second. It is not active — a single approver cannot open a customer's
	// tenancy (L4 dual consent / two-person control), so this is a distinct
	// state from both "nobody has approved" and "approved".
	GrantAwaitingCoConsent GrantState = "awaiting_co_consent"
	GrantActive            GrantState = "active"
	GrantDenied            GrantState = "denied"
	GrantRevoked           GrantState = "revoked"
	GrantExpired           GrantState = "expired"
)

// BreakGlassGrant is time-bounded, operator-bound tenant consent.
type BreakGlassGrant struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	OperatorID    string    `json:"operator_id"`
	OperatorEmail string    `json:"operator_email"`
	Reason        string    `json:"reason"`
	RequestedAt   time.Time `json:"requested_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	ConsentedAt   time.Time `json:"consented_at,omitempty"`
	ConsentedBy   string    `json:"consented_by,omitempty"`
	// SecondConsentedAt/By is the co-approver's consent (L4 dual consent). A
	// grant is active only once BOTH are set, and the two approvers must be
	// distinct operators, neither of them the requester — otherwise two-person
	// control is a formality one person can satisfy alone.
	SecondConsentedAt time.Time `json:"second_consented_at,omitempty"`
	SecondConsentedBy string    `json:"second_consented_by,omitempty"`
	DeniedAt          time.Time `json:"denied_at,omitempty"`
	DeniedBy          string    `json:"denied_by,omitempty"`
	RevokedAt         time.Time `json:"revoked_at,omitempty"`
	UseCount          int       `json:"use_count"`
}

func (g BreakGlassGrant) State(now time.Time) GrantState {
	switch {
	case !g.RevokedAt.IsZero():
		return GrantRevoked
	case !g.DeniedAt.IsZero():
		return GrantDenied
	case !g.ConsentedAt.IsZero() && !g.SecondConsentedAt.IsZero() && now.Before(g.ExpiresAt):
		// Active requires BOTH consents. A single consent never opens the
		// tenancy — that is the whole point of two-person control.
		return GrantActive
	case !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt):
		// Past expiry the grant is spent, whether it had zero, one, or two
		// consents — a half-approved grant that timed out is not left dangling.
		return GrantExpired
	case !g.ConsentedAt.IsZero():
		return GrantAwaitingCoConsent
	default:
		return GrantPending
	}
}

func (g BreakGlassGrant) Usable(now time.Time) bool {
	return g.State(now) == GrantActive
}

// Store is the read-side provider storage boundary. Production PostgreSQL
// implementations deliberately expose no mutation methods: authority changes
// can only enter through MutationSink and the event projection. MemStore keeps
// mutation helpers for deterministic legacy unit fixtures, but those helpers
// are not part of this production interface.
type Store interface {
	CountBillableTenants(context.Context) (int, error)
	ListTenants(context.Context) ([]Tenant, error)
	Tenant(context.Context, string) (Tenant, error)
	DirectTenantSnapshot(context.Context, string) (TenantSnapshot, error)
	BreakGlassGrant(context.Context, string) (BreakGlassGrant, error)
}

// legacyMutableStore is intentionally package-private. It exists only so
// in-memory unit fixtures can exercise domain rules without PostgreSQL/NATS;
// assembled binaries always provide MutationSink and never reach this branch.
type legacyMutableStore interface {
	Store
	CreateTenant(context.Context, Tenant) (Tenant, error)
	UpdateTenantStatus(context.Context, string, TenantStatus, time.Time) (Tenant, error)
	CreateBreakGlassGrant(context.Context, BreakGlassGrant) (BreakGlassGrant, error)
	UpdateBreakGlassGrant(context.Context, BreakGlassGrant) (BreakGlassGrant, error)
	IncrementBreakGlassUse(context.Context, string, time.Time) error
}

// MemStore is the deterministic in-memory provider store used by tests and eval
// wiring. The production DB-backed store can implement the same shape with the
// provider PostgreSQL role and RLS policy.
type MemStore struct {
	mu        sync.Mutex
	tenants   map[string]Tenant
	slugIndex map[string]string
	grants    map[string]BreakGlassGrant
	nextGrant int
}

func NewMemStore() *MemStore {
	return &MemStore{
		tenants:   map[string]Tenant{},
		slugIndex: map[string]string{},
		grants:    map[string]BreakGlassGrant{},
	}
}

func (s *MemStore) CountBillableTenants(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for _, tenant := range s.tenants {
		if tenant.Status == TenantActive || tenant.Status == TenantSuspended {
			n++
		}
	}
	return n, nil
}

func (s *MemStore) CreateTenant(_ context.Context, tenant Tenant) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tenant.ID == "" {
		tenant.ID = "tenant-" + tenant.Slug
	}
	if _, ok := s.slugIndex[tenant.Slug]; ok {
		return Tenant{}, fmt.Errorf("provider: tenant slug %q already exists", tenant.Slug)
	}
	if _, ok := s.tenants[tenant.ID]; ok {
		return Tenant{}, fmt.Errorf("provider: tenant id %q already exists", tenant.ID)
	}
	s.tenants[tenant.ID] = tenant
	s.slugIndex[tenant.Slug] = tenant.ID
	return tenant, nil
}

func (s *MemStore) ListTenants(context.Context) ([]Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Tenant, 0, len(s.tenants))
	for _, tenant := range s.tenants {
		out = append(out, tenant)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (s *MemStore) Tenant(_ context.Context, id string) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant, ok := s.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return tenant, nil
}

func (s *MemStore) UpdateTenantStatus(_ context.Context, id string, status TenantStatus, now time.Time) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenant, ok := s.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	tenant.Status = status
	tenant.UpdatedAt = now
	s.tenants[id] = tenant
	return tenant, nil
}

func (s *MemStore) DirectTenantSnapshot(context.Context, string) (TenantSnapshot, error) {
	return TenantSnapshot{}, ErrForbidden
}

func (s *MemStore) CreateBreakGlassGrant(_ context.Context, grant BreakGlassGrant) (BreakGlassGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextGrant++
	if grant.ID == "" {
		grant.ID = fmt.Sprintf("grant-%06d", s.nextGrant)
	}
	s.grants[grant.ID] = grant
	return grant, nil
}

func (s *MemStore) BreakGlassGrant(_ context.Context, id string) (BreakGlassGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[id]
	if !ok {
		return BreakGlassGrant{}, ErrNotFound
	}
	return grant, nil
}

func (s *MemStore) UpdateBreakGlassGrant(_ context.Context, grant BreakGlassGrant) (BreakGlassGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[grant.ID]; !ok {
		return BreakGlassGrant{}, ErrNotFound
	}
	s.grants[grant.ID] = grant
	return grant, nil
}

func (s *MemStore) IncrementBreakGlassUse(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[id]
	if !ok {
		return ErrNotFound
	}
	grant.UseCount++
	s.grants[id] = grant
	return nil
}
