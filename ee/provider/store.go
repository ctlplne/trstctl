// Package provider implements the licensed Provider/MSP plane.
package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	CodeTenantBandExhausted = "tenant_band_exhausted"
)

var (
	ErrTenantBandExhausted       = errors.New("provider: tenant_band_exhausted")
	ErrForbidden                 = errors.New("provider: forbidden")
	ErrUnlicensed                = errors.New("provider: unlicensed")
	ErrReadOnly                  = errors.New("provider: read-only license")
	ErrNotFound                  = errors.New("provider: not found")
	ErrBreakGlassNotConsented    = errors.New("provider: break-glass grant is not active")
	ErrBreakGlassWrongOperator   = errors.New("provider: break-glass grant is bound to another operator")
	ErrBreakGlassExpired         = errors.New("provider: break-glass grant expired")
	ErrBreakGlassReasonRequired  = errors.New("provider: break-glass reason is required")
	ErrBreakGlassInvalidDuration = errors.New("provider: break-glass duration is invalid")
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
	GrantActive  GrantState = "active"
	GrantDenied  GrantState = "denied"
	GrantRevoked GrantState = "revoked"
	GrantExpired GrantState = "expired"
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
	DeniedAt      time.Time `json:"denied_at,omitempty"`
	DeniedBy      string    `json:"denied_by,omitempty"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	UseCount      int       `json:"use_count"`
}

func (g BreakGlassGrant) State(now time.Time) GrantState {
	switch {
	case !g.RevokedAt.IsZero():
		return GrantRevoked
	case !g.DeniedAt.IsZero():
		return GrantDenied
	case !g.ConsentedAt.IsZero() && now.Before(g.ExpiresAt):
		return GrantActive
	case !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt):
		return GrantExpired
	default:
		return GrantPending
	}
}

func (g BreakGlassGrant) Usable(now time.Time) bool {
	return g.State(now) == GrantActive
}

// Store is the provider storage boundary. It exposes provider lifecycle metadata
// and break-glass grants, but a direct tenant snapshot read must fail closed.
type Store interface {
	CountBillableTenants(context.Context) (int, error)
	CreateTenant(context.Context, Tenant) (Tenant, error)
	ListTenants(context.Context) ([]Tenant, error)
	Tenant(context.Context, string) (Tenant, error)
	UpdateTenantStatus(context.Context, string, TenantStatus, time.Time) (Tenant, error)
	DirectTenantSnapshot(context.Context, string) (TenantSnapshot, error)
	CreateBreakGlassGrant(context.Context, BreakGlassGrant) (BreakGlassGrant, error)
	BreakGlassGrant(context.Context, string) (BreakGlassGrant, error)
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
