// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type memBrandStore struct {
	byTenant map[string]TenantBrand
	revision int
}

func (m *memBrandStore) Invalidate() {}

func (m *memBrandStore) TenantBrand(_ context.Context, id string) (*TenantBrand, error) {
	brand, ok := m.byTenant[id]
	if !ok {
		return nil, nil
	}
	return &brand, nil
}

func (m *memBrandStore) SetTenantBrand(_ context.Context, b TenantBrand) error {
	if m.byTenant == nil {
		m.byTenant = map[string]TenantBrand{}
	}
	m.revision++
	b.Revision = fmt.Sprintf("revision-%d", m.revision)
	m.byTenant[b.TenantID] = b
	return nil
}

func TestBrandReadbackAndConditionalUpdate(t *testing.T) {
	brands := &memBrandStore{}
	h := twoCustomerHandlerWithBrands(t, fullyDelegated("op-1", "tenant-alpha"), brands)
	path := "/provider/v1/tenants/tenant-alpha/brand"
	read := providerRequest(t, h, http.MethodGet, path, "")
	if read.Code != http.StatusOK || read.Header().Get("ETag") != `"0"` ||
		!strings.Contains(read.Body.String(), `"revision":"0"`) {
		t.Fatalf("initial brand = %d/%s", read.Code, read.Body.String())
	}
	missing := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"product_name":"blind"}`))
	missing.Header.Set("Authorization", "Bearer real-credential")
	missingResult := httptest.NewRecorder()
	h.ServeHTTP(missingResult, missing)
	if missingResult.Code != http.StatusPreconditionRequired {
		t.Fatalf("blind update = %d", missingResult.Code)
	}
	first := providerRequest(t, h, http.MethodPut, path, `{"product_name":"Original","custom_domain":"first.qa.test"}`)
	if first.Code != http.StatusNoContent {
		t.Fatalf("first brand = %d/%s", first.Code, first.Body.String())
	}
	current := providerRequest(t, h, http.MethodGet, path, "")
	if current.Code != http.StatusOK || current.Header().Get("ETag") != `"revision-1"` ||
		!strings.Contains(current.Body.String(), `"custom_domain":"first.qa.test"`) {
		t.Fatalf("current brand = %d/%s", current.Code, current.Body.String())
	}
	stale := providerRequest(t, h, http.MethodPut, path, `{"product_name":"stale","custom_domain":""}`)
	if stale.Code != http.StatusConflict || !strings.Contains(stale.Body.String(), "brand_revision_conflict") {
		t.Fatalf("stale update = %d/%s", stale.Code, stale.Body.String())
	}
	if got := brands.byTenant["tenant-alpha"].CustomDomain; got != "first.qa.test" {
		t.Fatalf("stale update erased domain: %q", got)
	}
	updated := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"product_name":"Updated","custom_domain":"first.qa.test"}`))
	updated.Header.Set("Authorization", "Bearer real-credential")
	updated.Header.Set("If-Match", current.Header().Get("ETag"))
	updatedResult := httptest.NewRecorder()
	h.ServeHTTP(updatedResult, updated)
	if updatedResult.Code != http.StatusNoContent {
		t.Fatalf("reviewed update = %d/%s", updatedResult.Code, updatedResult.Body.String())
	}
	other := providerRequest(t, h, http.MethodGet, "/provider/v1/tenants/tenant-beta/brand", "")
	if other.Code != http.StatusForbidden {
		t.Fatalf("undelegated read = %d", other.Code)
	}
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

func TestBrandCollisionAndPersistenceErrorsAreSafeForOperators(t *testing.T) {
	conflict := httptest.NewRecorder()
	writeProviderError(conflict, ErrBrandDomainConflict)
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), `"brand_domain_conflict"`) ||
		strings.Contains(conflict.Body.String(), "tenant_branding_domain_key") {
		t.Fatalf("domain collision response = %d %s", conflict.Code, conflict.Body.String())
	}
	internal := httptest.NewRecorder()
	writeProviderError(internal, fmt.Errorf("%w: tenant_branding_domain_key secret detail", ErrMutationPersistence))
	if internal.Code != http.StatusInternalServerError || strings.Contains(internal.Body.String(), "tenant_branding_domain_key") ||
		strings.Contains(internal.Body.String(), "secret detail") {
		t.Fatalf("persistence detail leaked = %d %s", internal.Code, internal.Body.String())
	}
}
