// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantnames"
)

func TestServedLifecycleSweepContinuesForOperatingTenants(t *testing.T) {
	const operatingTenant = "22222222-2222-2222-2222-222222222222"
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleRenewBefore = 24 * time.Hour
		d.LifecycleAlertBefore = 7 * 24 * time.Hour
		d.TenantDNSNamespaces = tenantnames.Grants{
			servedTestTenant: {"first.lifecycle.test"},
			operatingTenant:  {"second.lifecycle.test"},
		}
	})
	registerServedTenantID(t, h, operatingTenant, "Second operating tenant")

	seedDueIdentity := func(name string) (string, store.Certificate) {
		t.Helper()
		tok := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{"kind": "workload", "name": name + "-owner"})
		if status != http.StatusCreated {
			t.Fatalf("create owner = %d %s", status, body)
		}
		var owner struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &owner); err != nil {
			t.Fatal(err)
		}
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{"kind": "x509_certificate", "name": name, "owner_id": owner.ID})
		if status != http.StatusCreated {
			t.Fatalf("create identity = %d %s", status, body)
		}
		var ident struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &ident); err != nil {
			t.Fatal(err)
		}
		for _, transition := range []struct{ eventType, from, to string }{
			{projections.EventIdentityIssued, "requested", "issued"},
			{projections.EventIdentityDeployed, "issued", "deployed"},
		} {
			data, err := json.Marshal(map[string]string{"identity_id": ident.ID, "from": transition.from, "to": transition.to, "reason": "fixture lifecycle"})
			if err != nil {
				t.Fatal(err)
			}
			event, err := h.log.Append(t.Context(), events.Event{Type: transition.eventType, TenantID: h.tenant, Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if err := projections.New(h.store).Apply(t.Context(), event); err != nil {
				t.Fatal(err)
			}
		}
		cert := signedNotificationCertificate(t, h, owner.ID, name, 72*time.Hour)
		return ident.ID, cert
	}

	firstTenant := h.tenant
	_, firstCert := seedDueIdentity("first.lifecycle.test")
	h.tenant = operatingTenant
	secondIdentity, secondCert := seedDueIdentity("second.lifecycle.test")
	h.tenant = firstTenant

	renewalAt := time.Now().Add(60 * time.Hour)
	candidates, err := h.store.TenantsWithRenewalIdentityCandidates(t.Context(), renewalAt.Add(24*time.Hour), renewalAt)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(candidates, firstTenant) || !slices.Contains(candidates, operatingTenant) {
		t.Fatalf("renewal candidates = %v, want both tenants", candidates)
	}
	if err := h.store.RecordProjectionTenantQuarantine(t.Context(), firstTenant, 1, "nul_text"); err != nil {
		t.Fatal(err)
	}

	queued, err := h.srv.runLifecycleOnceAt(t.Context(), renewalAt)
	if err != nil || queued != 1 {
		t.Fatalf("operating tenant renewal queued %d, err=%v; want one renewal", queued, err)
	}
	identity, err := h.store.GetIdentity(t.Context(), operatingTenant, secondIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Status != "renewing" {
		t.Fatalf("operating tenant identity status = %q, want renewing", identity.Status)
	}
	cert, err := h.store.GetCertificate(t.Context(), operatingTenant, secondCert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.AlertedAt == nil {
		t.Fatal("operating tenant expiry alert was not queued")
	}
	deferredCert, err := h.store.GetCertificate(t.Context(), firstTenant, firstCert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if deferredCert.AlertedAt != nil {
		t.Fatal("refused tenant alert was marked as queued")
	}
	if queued, err := h.srv.runLifecycleOnceAt(t.Context(), renewalAt); err != nil || queued != 0 {
		t.Fatalf("repeat lifecycle sweep queued %d, err=%v; want no duplicate work", queued, err)
	}
}
