// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

type memBrandStore struct {
	byTenant map[string]TenantBrand
}

func (m *memBrandStore) Invalidate() {}

func (m *memBrandStore) SetTenantBrand(_ context.Context, b TenantBrand) error {
	if m.byTenant == nil {
		m.byTenant = map[string]TenantBrand{}
	}
	m.byTenant[b.TenantID] = b
	return nil
}

func twoCustomerHandlerWithBrands(t *testing.T, delegations DelegationSource, brands BrandStore) http.Handler {
	t.Helper()
	store := NewMemStore()
	now := fixedClock()()
	for _, id := range []string{"tenant-alpha", "tenant-beta"} {
		if _, err := store.CreateTenant(context.Background(), Tenant{
			ID: id, Slug: strings.TrimPrefix(id, "tenant-"), Name: id,
			Status: TenantActive, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	return NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         store,
		Audit:         &captureAudit{},
		Clock:         fixedClock(),
		Authenticator: stubAuth{accept: "Bearer real-credential"},
		Delegations:   delegations,
		Brands:        brands,
	})
}

// Brand administration is behind the SAME delegation partition as every other
// customer-scoped action (L3): an operator sets a delegated customer's brand,
// and a brand write on an UNdelegated customer is refused — because a custom
// domain is one customer's claim on a host, and an operator who could set
// another customer's brand could seize their domain.
func TestBrandAdministrationObeysTheDelegationPartition(t *testing.T) {
	t.Parallel()
	brands := &memBrandStore{}
	h := twoCustomerHandlerWithBrands(t, fullyDelegated("op-1", "tenant-alpha"), brands)

	rec := providerRequest(t, h, http.MethodPut, "/provider/v1/tenants/tenant-alpha/brand",
		`{"product_name":"Acme PKI","custom_domain":"certs.acme.example"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("set brand on the delegated customer = %d: %s", rec.Code, rec.Body.String())
	}
	got, ok := brands.byTenant["tenant-alpha"]
	if !ok || got.ProductName != "Acme PKI" || got.CustomDomain != "certs.acme.example" {
		t.Fatalf("brand never reached the store as authorized: %+v", brands.byTenant)
	}
	if got.TenantID != "tenant-alpha" {
		t.Fatal("the stored brand's tenant did not come from the authorized path")
	}

	// The OTHER customer: refused, store untouched.
	rec = providerRequest(t, h, http.MethodPut, "/provider/v1/tenants/tenant-beta/brand",
		`{"product_name":"Steal","custom_domain":"certs.acme.example"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("set brand on an undelegated customer = %d, want 403.\n\n"+
			"A custom domain is a claim on a host; an operator who could brand another customer "+
			"could seize the domain their customers reach them at.", rec.Code)
	}
	if _, ok := brands.byTenant["tenant-beta"]; ok {
		t.Fatal("the refused brand write reached the store anyway")
	}
}

// With no durable brand store attached, brand administration REFUSES rather
// than accepting a brand that would evaporate on restart — the same fail-closed
// stance quota administration takes.
func TestBrandAdministrationRefusesWithoutADurableStore(t *testing.T) {
	t.Parallel()
	h := twoCustomerHandlerWithBrands(t, fullyDelegated("op-1", "tenant-alpha"), nil)
	rec := providerRequest(t, h, http.MethodPut, "/provider/v1/tenants/tenant-alpha/brand",
		`{"product_name":"Acme PKI"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("brand set with no store = %d, want 403: a brand that cannot survive a restart "+
			"is not a white-label guarantee", rec.Code)
	}
}
