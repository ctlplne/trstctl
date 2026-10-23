// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// A95: tenant-scoped break-glass with dual consent.
//
// A Provider's emergency access to a customer is approved by two Provider
// custodians. A customer that wants a say records a policy requiring its own
// consent, and then its own people approve or deny each Provider request by
// grant id; the Provider plane reads these rows under the customer's RLS
// before it hands over the emergency result. Everything here is projected
// from the customer's own events, so the customer's history says who let the
// Provider in.

// ProviderAccessPolicy is a tenant's standing rule for Provider emergency access.
type ProviderAccessPolicy struct {
	TenantID             string
	RequireTenantConsent bool
	Approvals            int
	SetBy                string
	SetAt                time.Time
}

// ProviderAccessRequest is a Provider emergency request projected from the
// Provider's own authority event under this tenant.
type ProviderAccessRequest struct {
	TenantID      string
	GrantID       string
	OperatorEmail string
	Reason        string
	RequestedAt   time.Time
	ExpiresAt     time.Time
}

// ProviderAccessConsent is one tenant decision on one Provider grant.
type ProviderAccessConsent struct {
	TenantID  string
	GrantID   string
	Subject   string
	Approve   bool
	Reason    string
	DecidedAt time.Time
}

// ApplyProviderAccessPolicySetTx projects tenant.provider_access.policy_set.
func (s *Store) ApplyProviderAccessPolicySetTx(ctx context.Context, tx pgx.Tx, p ProviderAccessPolicy) error {
	if p.TenantID == "" {
		return errors.New("store: provider access policy needs a tenant")
	}
	if p.Approvals <= 0 {
		p.Approvals = 2
	}
	_, err := tx.Exec(ctx, `INSERT INTO provider_access_policy (tenant_id, require_tenant_consent, approvals, set_by, set_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id) DO UPDATE SET require_tenant_consent = EXCLUDED.require_tenant_consent,
		  approvals = EXCLUDED.approvals, set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at`,
		p.TenantID, p.RequireTenantConsent, p.Approvals, p.SetBy, p.SetAt.UTC())
	return err
}

// ApplyProviderAccessRequestedTx projects a Provider break-glass request
// (provider.breakglass_request) under the customer tenant it names.
func (s *Store) ApplyProviderAccessRequestedTx(ctx context.Context, tx pgx.Tx, r ProviderAccessRequest) error {
	return ProjectProviderAccessRequestTx(ctx, tx, r)
}

// ProjectProviderAccessRequestTx is the same write for a projection that
// owns its own transaction: the licensed Provider authority projection
// records the request under the customer tenant when it folds the Provider's
// provider.breakglass_request event, so the customer sees what was asked.
func ProjectProviderAccessRequestTx(ctx context.Context, tx pgx.Tx, r ProviderAccessRequest) error {
	if r.TenantID == "" || r.GrantID == "" {
		return errors.New("store: provider access request needs a tenant and a grant id")
	}
	_, err := tx.Exec(ctx, `INSERT INTO provider_access_requests (tenant_id, grant_id, operator_email, reason, requested_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, grant_id) DO UPDATE SET operator_email = EXCLUDED.operator_email,
		  reason = EXCLUDED.reason, requested_at = EXCLUDED.requested_at, expires_at = EXCLUDED.expires_at`,
		r.TenantID, r.GrantID, r.OperatorEmail, r.Reason, r.RequestedAt.UTC(), r.ExpiresAt.UTC())
	return err
}

// ApplyProviderAccessConsentedTx projects tenant.provider_access.consented. A
// subject's first decision on a grant stands; a replayed event converges.
func (s *Store) ApplyProviderAccessConsentedTx(ctx context.Context, tx pgx.Tx, c ProviderAccessConsent) error {
	if c.TenantID == "" || c.GrantID == "" || strings.TrimSpace(c.Subject) == "" {
		return errors.New("store: provider access consent needs a tenant, a grant id and a subject")
	}
	_, err := tx.Exec(ctx, `INSERT INTO provider_access_consents (tenant_id, grant_id, subject, approve, reason, decided_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, grant_id, subject) DO NOTHING`,
		c.TenantID, c.GrantID, strings.TrimSpace(c.Subject), c.Approve, c.Reason, c.DecidedAt.UTC())
	return err
}

// ProviderAccessPolicyFor reads the tenant's policy; absent means consent is
// not required (found=false).
func (s *Store) ProviderAccessPolicyFor(ctx context.Context, tenantID string) (ProviderAccessPolicy, bool, error) {
	var out ProviderAccessPolicy
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT tenant_id::text, require_tenant_consent, approvals, set_by, set_at
			FROM provider_access_policy WHERE tenant_id = $1`, tenantID).
			Scan(&out.TenantID, &out.RequireTenantConsent, &out.Approvals, &out.SetBy, &out.SetAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return out, found, err
}

// ProviderAccessRequestsFor lists the Provider emergency requests recorded
// under the tenant that have not expired by now, newest first.
func (s *Store) ProviderAccessRequestsFor(ctx context.Context, tenantID string, now time.Time) ([]ProviderAccessRequest, error) {
	out := []ProviderAccessRequest{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, grant_id, operator_email, reason, requested_at, expires_at
			FROM provider_access_requests WHERE tenant_id = $1 AND expires_at > $2 ORDER BY requested_at DESC, grant_id`, tenantID, now.UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ProviderAccessRequest
			if err := rows.Scan(&r.TenantID, &r.GrantID, &r.OperatorEmail, &r.Reason, &r.RequestedAt, &r.ExpiresAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ProviderAccessConsentsFor lists the tenant's decisions on one grant.
func (s *Store) ProviderAccessConsentsFor(ctx context.Context, tenantID, grantID string) ([]ProviderAccessConsent, error) {
	out := []ProviderAccessConsent{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, grant_id, subject, approve, reason, decided_at
			FROM provider_access_consents WHERE tenant_id = $1 AND grant_id = $2 ORDER BY decided_at, subject`, tenantID, grantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ProviderAccessConsent
			if err := rows.Scan(&c.TenantID, &c.GrantID, &c.Subject, &c.Approve, &c.Reason, &c.DecidedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
