// SPDX-License-Identifier: LicenseRef-trstctl-EE

package whitelabel

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"
)

// Durable white-label branding (L3, AUD-14).
//
// The in-memory store lost a provider's brand on every deploy, SILENTLY: their
// customers went back to seeing our product name with nothing in the running
// system saying why. For a white-label feature that is the product failing
// quietly — the entire value is that the customer never sees our name.
type PGStore struct {
	store *corestore.Store
}

// NewPGStore builds the durable brand store.
func NewPGStore(s *corestore.Store) *PGStore { return &PGStore{store: s} }

var _ Store = (*PGStore)(nil)

const brandCols = `product_name, logo_data_uri, login_message, token_overrides,
	email_from_name, email_footer, custom_domain`

func scanBrand(row pgx.Row, tenantID string) (*Record, error) {
	var r Record
	var tokens []byte
	if err := row.Scan(&r.ProductName, &r.LogoDataURI, &r.LoginMessage, &tokens,
		&r.EmailFromName, &r.EmailFooter, &r.CustomDomain); err != nil {
		return nil, err
	}
	r.TenantID = tenantID
	if len(tokens) > 0 {
		// A malformed override blob leaves the map nil rather than failing the
		// whole lookup: a broken token set should degrade to the default label,
		// not blank the login page it was meant to decorate.
		_ = json.Unmarshal(tokens, &r.TokenOverrides)
	}
	return &r, nil
}

// TenantBrand reads one tenant's brand under its own RLS context.
func (p *PGStore) TenantBrand(ctx context.Context, tenantID string) (*Record, error) {
	if p == nil || p.store == nil {
		return nil, nil
	}
	var out *Record
	err := p.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		r, err := scanBrand(tx.QueryRow(ctx,
			`SELECT `+brandCols+` FROM tenant_branding WHERE tenant_id = $1`, tenantID), tenantID)
		if err != nil {
			// No row means no brand, which is the DEFAULT — not an error. An
			// error here would blank a login page over a tenant that simply
			// never configured one.
			return nil
		}
		out = r
		return nil
	})
	return out, err
}

// TenantByDomain resolves a custom domain to its brand.
//
// Cross-tenant by necessity: a request arriving on a custom domain has no
// tenant yet — resolving the host IS how the tenant is discovered. Marked for
// the RLS-bypass inventory guard accordingly.
func (p *PGStore) TenantByDomain(ctx context.Context, domain string) (*Record, error) {
	if p == nil || p.store == nil || domain == "" {
		return nil, nil
	}
	var tenantID string
	var out *Record
	row := p.store.SystemPool().QueryRow(ctx,
		//trstctl:system-query — cross-tenant by design: a request on a custom domain carries no tenant context yet, and resolving the host is precisely how the tenant is identified (AN-1 exemption). Returns presentation only.
		`SELECT tenant_id::text, `+brandCols+` FROM tenant_branding WHERE custom_domain = $1`, domain)
	var r Record
	var tokens []byte
	if err := row.Scan(&tenantID, &r.ProductName, &r.LogoDataURI, &r.LoginMessage, &tokens,
		&r.EmailFromName, &r.EmailFooter, &r.CustomDomain); err != nil {
		return nil, nil
	}
	r.TenantID = tenantID
	if len(tokens) > 0 {
		_ = json.Unmarshal(tokens, &r.TokenOverrides)
	}
	out = &r
	return out, nil
}

// ProviderBrand is the brand shown before any tenant is known.
func (p *PGStore) ProviderBrand(ctx context.Context) (*Record, error) {
	// Stored as the all-zero tenant so it shares one table and one code path
	// with tenant brands; a separate table would drift.
	return p.TenantBrand(ctx, corestore.ZeroUUID)
}

// SetTenantBrand writes a tenant's brand.
func (p *PGStore) SetTenantBrand(ctx context.Context, r Record) error {
	if p == nil || p.store == nil {
		return nil
	}
	tokens, err := json.Marshal(r.TokenOverrides)
	if err != nil {
		return err
	}
	return p.store.WithTenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO tenant_branding (tenant_id, product_name, logo_data_uri, login_message,
			   token_overrides, email_from_name, email_footer, custom_domain)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			 ON CONFLICT (tenant_id) DO UPDATE SET
			   product_name = EXCLUDED.product_name, logo_data_uri = EXCLUDED.logo_data_uri,
			   login_message = EXCLUDED.login_message, token_overrides = EXCLUDED.token_overrides,
			   email_from_name = EXCLUDED.email_from_name, email_footer = EXCLUDED.email_footer,
			   custom_domain = EXCLUDED.custom_domain, updated_at = now()`,
			r.TenantID, r.ProductName, r.LogoDataURI, r.LoginMessage, tokens,
			r.EmailFromName, r.EmailFooter, r.CustomDomain)
		return err
	})
}

// SetProviderBrand writes the pre-tenant brand.
func (p *PGStore) SetProviderBrand(ctx context.Context, r Record) error {
	r.TenantID = corestore.ZeroUUID
	return p.SetTenantBrand(ctx, r)
}
