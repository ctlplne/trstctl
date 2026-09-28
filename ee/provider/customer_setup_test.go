// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
)

func TestProviderCustomerSetupDistinguishesAccessFromEmptyInventory(t *testing.T) {
	st, log, _ := authorityReplayFixture(t, events.WithRequiredPrivacyEventPolicies())
	ctx := t.Context()
	id, neighbor := CustomerID("setup-pending"), CustomerID("setup-neighbor")
	runtime := NewAuthorityRuntime(st, log)
	projector := projections.New(st, runtime.ProjectionOptions...)
	idem := orchestrator.NewIdempotency(st)
	handler := NewHandler(Config{License: providerLicense(t, 10), Store: NewPGStore(st), Mutations: runtime.Mutations,
		Idempotency: idem, Authenticator: authorityAuthenticator{}, Delegations: fullyDelegated("op-1", id, neighbor)})
	request := func(method, path, body, key string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer requester")
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, slug := range []string{"setup-pending", "setup-neighbor"} {
		body := `{"slug":"` + slug + `","name":"Setup customer"}`
		if w := request(http.MethodPost, "/provider/v1/tenants", body, "provision-"+slug); w.Code != http.StatusCreated {
			t.Fatalf("provision %s: %d %s", slug, w.Code, w.Body.String())
		}
	}
	if _, err := st.GetTenant(ctx, id); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Provider-only provisioning unexpectedly registered core access: %v", err)
	}
	register := func(tenantID string) {
		t.Helper()
		payload := []byte(`{"name":"Configured customer"}`)
		_, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector, idem,
			orchestrator.TenantRegistrationCommand{TenantID: tenantID, Name: "Configured customer", IdempotencyKey: "register-" + tenantID,
				RequestMaterial: payload, PayloadAt: func(time.Time) ([]byte, error) { return payload, nil }})
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(tenantID, health string, configured bool) {
		t.Helper()
		w := request(http.MethodGet, "/provider/v1/tenants/"+tenantID+"/health", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("health: %d %s", w.Code, w.Body.String())
		}
		var got struct {
			TenantID             string `json:"tenant_id"`
			Health               string `json:"health"`
			ActiveCertificates   int    `json:"active_certificates"`
			WorkspaceInitialized *bool  `json:"workspace_initialized"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.TenantID != tenantID || got.Health != health || got.ActiveCertificates != 0 || got.WorkspaceInitialized == nil || *got.WorkspaceInitialized != configured {
			t.Errorf("customer setup health = %s, want customer=%s health=%s workspace_initialized=%t with zero certificates", w.Body.String(), tenantID, health, configured)
		}
	}
	register(neighbor)
	check(id, "setup_required", false)
	check(neighbor, "no_certificates", true)
	register(id)
	check(id, "no_certificates", true)
	if w := request(http.MethodPost, "/provider/v1/tenants/"+id+"/suspend", `{}`, "suspend"); w.Code != http.StatusNoContent {
		t.Fatalf("suspend: %d %s", w.Code, w.Body.String())
	}
	check(id, "suspended", true)
	if w := request(http.MethodGet, "/provider/v1/tenants/"+CustomerID("undelegated")+"/health", "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("undelegated setup read: %d %s", w.Code, w.Body.String())
	}
	st.Close()
	if w := request(http.MethodGet, "/provider/v1/tenants/"+neighbor+"/health", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable store became a setup verdict: %d %s", w.Code, w.Body.String())
	}
}
