// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
)

// providerAuthorityTenant is the RLS partition for Provider-global operator
// identities. It is not a customer tenant and is never accepted from HTTP.
const providerAuthorityTenant = corestore.ZeroUUID

// OperatorIdentity is the durable IdP/SCIM lifecycle of one Provider operator.
// A cryptographically valid OIDC token or SAML session is still refused when
// this row is inactive: identity proof says who presented the credential;
// lifecycle authority says whether that person still works here.
type OperatorIdentity struct {
	ID              string       `json:"id"`
	ExternalID      string       `json:"external_id"`
	UserName        string       `json:"user_name"`
	Email           string       `json:"email,omitempty"`
	DisplayName     string       `json:"display_name,omitempty"`
	Role            OperatorRole `json:"role"`
	Active          bool         `json:"active"`
	Source          string       `json:"source"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
	DeprovisionedAt time.Time    `json:"deprovisioned_at,omitempty"`
}

// DelegationRecord is the inventory form of one exact authority row. Revoked
// rows remain readable; only the active projection is used for authorization.
type DelegationRecord struct {
	OperatorID string    `json:"operator_id"`
	CustomerID string    `json:"customer_id"`
	Operation  Operation `json:"operation"`
	Source     string    `json:"source"`
	GrantedBy  string    `json:"granted_by,omitempty"`
	GrantedAt  time.Time `json:"granted_at"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string    `json:"revoked_by,omitempty"`
}

// OperatorAccess is the Provider-console row: lifecycle plus every current and
// historical per-customer grant.
type OperatorAccess struct {
	Identity    OperatorIdentity   `json:"identity"`
	Delegations []DelegationRecord `json:"delegations"`
}

// OperatorDirectory is the request-time lifecycle gate shared by OIDC and
// SAML. Subject may match the canonical id, SCIM externalId, or userName.
type OperatorDirectory interface {
	ResolveOperator(context.Context, string) (OperatorIdentity, error)
}

// OperatorAccessStore adds the admin inventory to the lifecycle lookup.
type OperatorAccessStore interface {
	OperatorDirectory
	ListOperatorAccess(context.Context) ([]OperatorAccess, error)
}

// PGAccessStore reads the event-projected Provider authority views.
type PGAccessStore struct{ store *corestore.Store }

func NewPGAccessStore(store *corestore.Store) *PGAccessStore {
	if store == nil {
		return nil
	}
	return &PGAccessStore{store: store}
}

func (p *PGAccessStore) ResolveOperator(ctx context.Context, subject string) (OperatorIdentity, error) {
	if p == nil || p.store == nil || strings.TrimSpace(subject) == "" {
		return OperatorIdentity{}, ErrNotFound
	}
	//trstctl:system-query — Provider-global authority is read before a customer tenant is selected; the fixed tenant_id is still explicit and the table is FORCE RLS.
	row := p.store.SystemPool().QueryRow(ctx, `SELECT id, external_id, user_name, email, display_name,
		role, active, source, created_at, updated_at, deprovisioned_at
		FROM provider_operators
		WHERE tenant_id = $1 AND (id = $2 OR external_id = $2 OR user_name = $2)`,
		providerAuthorityTenant, strings.TrimSpace(subject))
	identity, err := scanOperatorIdentity(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return OperatorIdentity{}, ErrNotFound
	}
	return identity, err
}

func (p *PGAccessStore) ListOperatorAccess(ctx context.Context) ([]OperatorAccess, error) {
	if p == nil || p.store == nil {
		return nil, errors.New("provider: operator access store is not configured")
	}
	//trstctl:system-query — Provider admins list the fixed Provider authority partition, never a caller-selected customer tenant.
	rows, err := p.store.SystemPool().Query(ctx, `SELECT id, external_id, user_name, email, display_name,
		role, active, source, created_at, updated_at, deprovisioned_at
		FROM provider_operators WHERE tenant_id = $1 ORDER BY user_name, id`, providerAuthorityTenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := map[string]*OperatorAccess{}
	var order []string
	for rows.Next() {
		identity, scanErr := scanOperatorIdentity(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		access := &OperatorAccess{Identity: identity, Delegations: []DelegationRecord{}}
		byID[identity.ID] = access
		order = append(order, identity.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	//trstctl:system-query — cross-customer Provider authority inventory; no customer data is returned and every row is attached to an already authorized Provider operator.
	grantRows, err := p.store.SystemPool().Query(ctx, `SELECT operator_id, customer_tenant_id, operation,
		source, granted_by, granted_at, expires_at, last_used_at, revoked_at, revoked_by
		FROM provider_operator_delegations WHERE tenant_id = $1
		ORDER BY operator_id, customer_tenant_id, operation`, providerAuthorityTenant)
	if err != nil {
		return nil, err
	}
	defer grantRows.Close()
	for grantRows.Next() {
		delegation, scanErr := scanDelegationRecord(grantRows)
		if scanErr != nil {
			return nil, scanErr
		}
		if access := byID[delegation.OperatorID]; access != nil {
			access.Delegations = append(access.Delegations, delegation)
		}
	}
	if err := grantRows.Err(); err != nil {
		return nil, err
	}
	out := make([]OperatorAccess, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

func scanOperatorIdentity(row pgx.Row) (OperatorIdentity, error) {
	var identity OperatorIdentity
	var role string
	var deprovisionedAt *time.Time
	if err := row.Scan(&identity.ID, &identity.ExternalID, &identity.UserName, &identity.Email,
		&identity.DisplayName, &role, &identity.Active, &identity.Source, &identity.CreatedAt,
		&identity.UpdatedAt, &deprovisionedAt); err != nil {
		return OperatorIdentity{}, err
	}
	identity.Role = OperatorRole(role)
	if deprovisionedAt != nil {
		identity.DeprovisionedAt = deprovisionedAt.UTC()
	}
	return identity, nil
}

func scanDelegationRecord(row pgx.Row) (DelegationRecord, error) {
	var delegation DelegationRecord
	var expiresAt, lastUsedAt, revokedAt *time.Time
	if err := row.Scan(&delegation.OperatorID, &delegation.CustomerID, &delegation.Operation,
		&delegation.Source, &delegation.GrantedBy, &delegation.GrantedAt, &expiresAt,
		&lastUsedAt, &revokedAt, &delegation.RevokedBy); err != nil {
		return DelegationRecord{}, err
	}
	if expiresAt != nil {
		delegation.ExpiresAt = expiresAt.UTC()
	}
	if lastUsedAt != nil {
		delegation.LastUsedAt = lastUsedAt.UTC()
	}
	if revokedAt != nil {
		delegation.RevokedAt = revokedAt.UTC()
	}
	return delegation, nil
}

func validOperatorRole(role OperatorRole) bool {
	return role == OperatorAdmin || role == OperatorOperator
}

func lesserRole(a, b OperatorRole) OperatorRole {
	if !validOperatorRole(a) || !validOperatorRole(b) {
		return ""
	}
	if a == OperatorOperator || b == OperatorOperator {
		return OperatorOperator
	}
	return OperatorAdmin
}

func normalizeOperations(operations []Operation) ([]Operation, error) {
	known := map[Operation]bool{}
	for _, operation := range Operations {
		known[operation] = true
	}
	seen := map[Operation]bool{}
	out := make([]Operation, 0, len(operations))
	for _, operation := range operations {
		operation = Operation(strings.TrimSpace(string(operation)))
		if !known[operation] {
			return nil, errors.New("provider: delegation contains an unknown operation")
		}
		if !seen[operation] {
			seen[operation] = true
			out = append(out, operation)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("provider: at least one delegation operation is required")
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
