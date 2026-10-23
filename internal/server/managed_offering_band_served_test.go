// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
)

// A92: the licensed tenant band gates the managed-offering create path. It
// was stored and reported; a Provider could register hosted tenants past it.
// Now a provision beyond the band is a structured 429 naming the band and the
// count, a replay of an earlier successful key still returns its 201, and the
// status endpoint reports how many managed tenants the band already holds.
func testManagedOfferingLicenseWithBand(t *testing.T, band int) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_test_managed_band", Customer: "Managed Provider", Tier: license.TierProvider,
		TenantBand: band, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provider-license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	return mgr
}

func TestServedManagedOfferingTenantBandGatesProvisioningA92(t *testing.T) {
	provider := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) {
		d.License = testManagedOfferingLicenseWithBand(t, 1)
	})
	registerServedTenant(t, provider, "Provider band fixture")
	token := seedScopedTokenSubject(t, provider.store, provider.tenant, "provider-admin", "access:read", "access:write")
	provision := func(key, tenantID, name string) (int, []byte) {
		return doBearer(t, provider.ts, http.MethodPost, "/api/v1/managed-offering/tenants", token, key, map[string]any{"tenant_id": tenantID, "name": name})
	}
	status, body := provision("a92-first", "33333333-3333-4333-8333-333333333331", "First Hosted")
	if status != http.StatusCreated {
		t.Fatalf("first provision = %d %s", status, body)
	}
	first := string(body)
	// The band is full: the next hosted tenant is refused with the numbers.
	status, body = provision("a92-second", "33333333-3333-4333-8333-333333333332", "Second Hosted")
	if status != http.StatusTooManyRequests || !strings.Contains(string(body), "tenant band") || !strings.Contains(string(body), "1 of 1") {
		t.Fatalf("provision over the band = %d %s, want 429 naming the band and count", status, body)
	}
	if _, err := provider.store.GetTenant(t.Context(), "33333333-3333-4333-8333-333333333332"); err == nil {
		t.Fatal("a refused provision still registered the tenant")
	}
	// The earlier success replays under its key; the refusal does not become a
	// second registration.
	if status, again := provision("a92-first", "33333333-3333-4333-8333-333333333331", "First Hosted"); status != http.StatusCreated || string(again) != first {
		t.Fatalf("replay of the first provision = %d %s, want the identical 201", status, again)
	}
	// The status endpoint says how much of the band is used.
	status, body = doBearer(t, provider.ts, http.MethodGet, "/api/v1/managed-offering/status", token, "", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d %s", status, body)
	}
	var report struct {
		TenantBand               int `json:"tenant_band"`
		ManagedTenantsRegistered int `json:"managed_tenants_registered"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.TenantBand != 1 || report.ManagedTenantsRegistered != 1 {
		t.Fatalf("status band report = %+v, want band 1 with 1 registered", report)
	}
	count, err := provider.store.CountManagedTenants(t.Context())
	if err != nil || count != 1 {
		t.Fatalf("CountManagedTenants = %d %v, want 1", count, err)
	}
}
