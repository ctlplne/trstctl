// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24: a hosted tenant the Provider provisions starts
// with control-plane key generation off, decided by its own registration.
// Recording that default as a separate command inside the Provider's request
// was refused by the tenant service fence the request already held, so every
// managed provisioning failed; the default now rides on the registration event,
// is projected with the tenant row, survives a replay of the same request, and
// is reproduced by a rebuild.
func TestServedManagedTenantStartsWithControlPlaneKeygenOffFromItsRegistration(t *testing.T) {
	provider := newServedHarnessWithEventOptions(t, config.Protocols{}, []events.OpenOption{events.WithRequiredPrivacyEventPolicies()}, func(d *Deps) {
		d.License = testManagedOfferingLicenseManager(t)
	})
	registerServedTenant(t, provider, "Provider keygen default fixture")
	providerToken := seedScopedTokenSubject(t, provider.store, provider.tenant, "provider-admin", "access:read", "access:write")
	const hosted = "33333333-3333-4333-8333-333333333339"
	request := map[string]any{"tenant_id": hosted, "name": "Keygen Default Hosted"}
	if status, body := doBearer(t, provider.ts, http.MethodPost, "/api/v1/managed-offering/tenants", providerToken,
		"keygen-default-provision", request); status != http.StatusCreated {
		t.Fatalf("provider provision = %d body %s", status, body)
	}
	assertOff := func(stage string) {
		t.Helper()
		policy, found, err := provider.store.ControlPlaneKeygenFor(t.Context(), hosted)
		if err != nil || !found || policy.Enabled || policy.Source != store.ControlPlaneKeygenSourceRegistration ||
			policy.SetBy != "system:"+store.ControlPlaneKeygenSourceRegistration || policy.Evidence != nil {
			t.Fatalf("%s: hosted tenant decision = %+v found=%v err=%v, want off from its registration", stage, policy, found, err)
		}
	}
	assertOff("provisioned")
	if status, body := doBearer(t, provider.ts, http.MethodPost, "/api/v1/managed-offering/tenants", providerToken,
		"keygen-default-provision", request); status != http.StatusCreated {
		t.Fatalf("replayed provision = %d body %s", status, body)
	}
	if n := eventCount(t, provider.log, hosted, projections.EventControlPlaneKeygenSet); n != 0 {
		t.Fatalf("the default was recorded as %d separate decision events; it belongs to the registration", n)
	}
	assertOff("replayed")
	if err := provider.srv.proj.Rebuild(t.Context(), provider.log); err != nil {
		t.Fatal(err)
	}
	assertOff("rebuilt")
}
