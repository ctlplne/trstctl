// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"fmt"
	"strings"
)

// Per-customer white-label brand administration on the provider plane (epic L3).
//
// Brand WRITES live here for the same reason quota writes do: the brand — and
// especially the custom domain — is a claim about a customer that the customer
// must not make about themselves. A tenant-reachable brand route would let one
// customer set a product name or seize a custom domain, and the whole point of
// white-label is that the PROVIDER decides how their customer's screen looks.
//
// BrandStore is the durable half the plane writes through; ee/whitelabel's
// PGStore satisfies it. The plane holds only this narrow interface so it does
// not depend on the whitelabel package's record shape.

// TenantBrand is the operator-supplied brand for one customer.
type TenantBrand struct {
	TenantID       string
	ProductName    string
	LogoDataURI    string
	LoginMessage   string
	EmailFromName  string
	EmailFooter    string
	CustomDomain   string
	TokenOverrides map[string]string `json:"-"`
	Revision       string            `json:"-"`
}

// BrandStore is the read-view cache seam. The PostgreSQL brand store exposes
// no writer; after the event projection commits, the resolver cache is cleared
// so the new projected row is served immediately.
type BrandStore interface {
	Invalidate()
	TenantBrand(context.Context, string) (*TenantBrand, error)
}

type legacyBrandStore interface {
	BrandStore
	SetTenantBrand(context.Context, TenantBrand) error
}

// SetTenantBrand persists a customer's white-label brand.
//
// Provision-class authority, like quota: how a customer's product appears is a
// provisioning decision, and the operator trusted to create a tenancy is the
// one trusted to brand it. The tenant id comes from the PATH the operator was
// authorized against, never the body — a body naming a different customer would
// turn an authorization on one tenancy into a write on another, and with a
// custom domain that would be one customer seizing another's host.
func (s *Service) SetTenantBrand(ctx context.Context, actor Operator, customerID string, brand TenantBrand, expectedRevision string) error {
	if err := s.requireMutation(actor, true); err != nil {
		return err
	}
	if err := s.authorize(ctx, actor, customerID, OpProvision); err != nil {
		return err
	}
	if s.brands == nil {
		// Fail closed and name the missing piece: a provider who wired
		// authentication and delegation and still cannot set a brand needs to
		// know the brand store is not attached, not to re-check their grants.
		return fmt.Errorf("%w: no durable white-label store is attached on this deployment, so a "+
			"brand could not survive a restart; refusing to accept one that would silently evaporate",
			ErrForbidden)
	}
	brand.TenantID = customerID
	brand.Revision = ""
	brand.ProductName = strings.TrimSpace(brand.ProductName)
	brand.CustomDomain = strings.ToLower(strings.TrimSpace(brand.CustomDomain))
	now := s.clock()
	if s.mutations != nil {
		if _, err := s.emit(ctx, EventTenantBrandSet, customerID, AuthorityEvent{Brand: &brand, BrandTokenOverrides: brand.TokenOverrides, BrandExpectedRevision: &expectedRevision,
			Audit: AuditEvent{Type: EventTenantBrandSet, TenantID: customerID,
				OperatorID: actor.ID, OperatorEmail: actor.Email, At: now}}); err != nil {
			return err
		}
		s.brands.Invalidate()
		return nil
	}
	legacy, ok := s.brands.(legacyBrandStore)
	if !ok {
		return fmt.Errorf("provider: production brand stores require the event mutation sink")
	}
	current, err := s.brands.TenantBrand(ctx, customerID)
	if err != nil {
		return err
	}
	if brandRevision(current) != expectedRevision {
		return ErrBrandRevisionConflict
	}
	if err := legacy.SetTenantBrand(ctx, brand); err != nil {
		// A custom-domain collision (two tenants claiming one host) surfaces
		// from the store's uniqueness constraint. It is the store's job to
		// refuse it; the plane passes the refusal through rather than guessing.
		return err
	}
	return s.record(ctx, AuditEvent{Type: EventTenantBrandSet, TenantID: customerID,
		OperatorID: actor.ID, OperatorEmail: actor.Email, At: now})
}

func brandRevision(brand *TenantBrand) string {
	if brand == nil || brand.Revision == "" {
		return "0"
	}
	return brand.Revision
}

// GetTenantBrand reads only the exact delegated customer's projected brand.
// A missing record is an explicit default with revision 0, never another
// customer's provider-wide fallback.
func (s *Service) GetTenantBrand(ctx context.Context, actor Operator, customerID string) (TenantBrand, error) {
	if err := s.requireOperator(actor); err != nil {
		return TenantBrand{}, err
	}
	if err := s.authorize(ctx, actor, customerID, OpProvision); err != nil {
		return TenantBrand{}, err
	}
	if s.brands == nil {
		return TenantBrand{}, fmt.Errorf("%w: no durable white-label store is attached", ErrForbidden)
	}
	brand, err := s.brands.TenantBrand(ctx, customerID)
	if err != nil {
		return TenantBrand{}, err
	}
	if brand == nil {
		return TenantBrand{TenantID: customerID, Revision: "0"}, nil
	}
	brand.TenantID, brand.Revision = customerID, brandRevision(brand)
	return *brand, nil
}
