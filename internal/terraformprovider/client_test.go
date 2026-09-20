// SPDX-License-Identifier: BUSL-1.1

package terraformprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestClientUsesServedOpenAPIRoutesAndHeaders(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-test" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Tenant-ID") != "tenant-a" {
			t.Errorf("X-Tenant-ID header = %q", r.Header.Get("X-Tenant-ID"))
		}
		if r.Method != http.MethodGet && r.Header.Get("Idempotency-Key") == "" {
			t.Errorf("%s %s missing Idempotency-Key", r.Method, r.URL.Path)
		}
		key := r.Method + " " + r.URL.Path
		seen[key] = true
		w.Header().Set("Content-Type", "application/json")
		switch key {
		case "POST /api/v1/profiles":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode profile request: %v", err)
			}
			if req["name"] != "web" {
				t.Fatalf("profile name = %v", req["name"])
			}
			_, _ = w.Write([]byte(`{"id":"prof-1","name":"web","version":1,"active":true,"created_by":"terraform","spec":{"ttl":"1h"}}`))
		case "GET /api/v1/profiles/web/versions/1":
			_, _ = w.Write([]byte(`{"id":"prof-1","name":"web","version":1,"active":true,"created_by":"terraform","spec":{"ttl":"1h"}}`))
		case "POST /api/v1/secrets/pki":
			_, _ = w.Write([]byte(`{"serial":"01","common_name":"svc.example.test","certificate":"CERT","private_key":"KEY"}`))
		case "POST /api/v1/secrets/store":
			_, _ = w.Write([]byte(`{"name":"apps/api/password","version":1,"created_at":"2026-06-26T01:00:00Z","updated_at":"2026-06-26T01:00:00Z"}`))
		case "GET /api/v1/secrets/store/apps/api/password":
			_, _ = w.Write([]byte(`{"name":"apps/api/password","value":"fixture-value","version":2}`))
		case "PUT /api/v1/secrets/store/apps/api/password":
			_, _ = w.Write([]byte(`{"name":"apps/api/password","version":2,"created_at":"2026-06-26T01:00:00Z","updated_at":"2026-06-26T01:01:00Z"}`))
		case "DELETE /api/v1/secrets/store/apps/api/password":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s", key)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(ClientConfig{Endpoint: srv.URL, Token: "tok-test", Tenant: "tenant-a", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.CreateProfile(t.Context(), "web", json.RawMessage(`{"ttl":"1h"}`), "idem-profile"); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if _, err := client.GetProfileVersion(t.Context(), "web", 1); err != nil {
		t.Fatalf("GetProfileVersion: %v", err)
	}
	if _, err := client.IssuePKISecret(t.Context(), "svc.example.test", 3600, "idem-pki"); err != nil {
		t.Fatalf("IssuePKISecret: %v", err)
	}
	if _, err := client.CreateSecret(t.Context(), "apps/api/password", "fixture-value", "idem-secret-create"); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if _, err := client.GetSecret(t.Context(), "apps/api/password"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if _, err := client.RotateSecret(t.Context(), "apps/api/password", "fixture-value-2", "idem-secret-rotate"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if err := client.DeleteSecret(t.Context(), "apps/api/password", "idem-secret-delete"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	for _, want := range []string{
		"POST /api/v1/profiles",
		"GET /api/v1/profiles/web/versions/1",
		"POST /api/v1/secrets/pki",
		"POST /api/v1/secrets/store",
		"GET /api/v1/secrets/store/apps/api/password",
		"PUT /api/v1/secrets/store/apps/api/password",
		"DELETE /api/v1/secrets/store/apps/api/password",
	} {
		if !seen[want] {
			t.Errorf("missing request %s", want)
		}
	}
}

func TestProviderHelperValidationAndNotFoundClassification(t *testing.T) {
	if got := stringConfig(types.StringValue("https://cfg.example"), "TRSTCTL_TEST_ENDPOINT"); got != "https://cfg.example" {
		t.Fatalf("stringConfig explicit = %q", got)
	}
	t.Setenv("TRSTCTL_TEST_ENDPOINT", "https://env.example")
	if got := stringConfig(types.StringNull(), "TRSTCTL_TEST_ENDPOINT"); got != "https://env.example" {
		t.Fatalf("stringConfig env = %q", got)
	}
	if got := optionalString(types.StringUnknown()); got != "" {
		t.Fatalf("optionalString unknown = %q", got)
	}
	if _, err := requiredString(types.StringValue(" "), "name"); err == nil {
		t.Fatal("requiredString accepted blank value")
	}
	if got, err := requiredString(types.StringValue("web"), "name"); err != nil || got != "web" {
		t.Fatalf("requiredString = %q, %v", got, err)
	}
	if _, err := parseRawJSON("not-json"); err == nil {
		t.Fatal("parseRawJSON accepted invalid JSON")
	}
	if raw, err := parseRawJSON(`{"ttl":"1h"}`); err != nil || string(raw) != `{"ttl":"1h"}` {
		t.Fatalf("parseRawJSON = %s, %v", raw, err)
	}
	if !maybeNotFound(&Error{StatusCode: http.StatusNotFound}) || maybeNotFound(errors.New("not found")) {
		t.Fatal("maybeNotFound did not classify API 404 only")
	}
	if got := idempotencySeed(types.StringValue(" explicit "), "tenant", "name"); got != "explicit" {
		t.Fatalf("idempotencySeed explicit = %q", got)
	}
	if got := idempotencySeed(types.StringNull(), "tenant", "name"); got == "" || got == "explicit" {
		t.Fatalf("idempotencySeed fallback = %q", got)
	}

	var client *Client
	if err := configureClient(&Client{}, &client); err != nil || client == nil {
		t.Fatalf("configureClient valid = %v client=%v", err, client)
	}
	if err := configureClient("bad", &client); err == nil {
		t.Fatal("configureClient accepted wrong provider data")
	}
}

func TestResourceApplyHelpersUseClientAndStableSeeds(t *testing.T) {
	srv := terraformAcceptanceServer(t)
	t.Cleanup(srv.Close)
	client, err := NewClient(ClientConfig{Endpoint: srv.URL, Token: "tok-test", Tenant: "tenant-a", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	profileRes := &profileResource{client: client}
	profilePlan := profileResourceModel{
		Name:           types.StringValue("web"),
		SpecJSON:       types.StringValue(`{"allowed_key_algorithms":["ECDSA-P256"],"max_validity":"1h"}`),
		IdempotencyKey: types.StringNull(),
	}
	profile, profileSeed, err := profileRes.apply(t.Context(), profilePlan, "create")
	if err != nil {
		t.Fatalf("profile apply: %v", err)
	}
	profilePlan.apply(profile, profileSeed)
	if profilePlan.ID.ValueString() != "prof-1" || profilePlan.Version.ValueInt64() != 1 || profilePlan.IdempotencyKey.ValueString() == "" {
		t.Fatalf("profile model not populated: %+v", profilePlan)
	}

	pkiRes := &pkiCertificateResource{client: client}
	pkiPlan := pkiCertificateResourceModel{
		CommonName: types.StringValue("svc.example.test"),
		TTLSeconds: types.Int64Value(600),
	}
	issued, pkiSeed, ttl, err := pkiRes.issue(t.Context(), pkiPlan, "create")
	if err != nil {
		t.Fatalf("pki issue: %v", err)
	}
	pkiPlan.apply(issued, pkiSeed, ttl)
	if pkiPlan.Serial.ValueString() != "01" || pkiPlan.CertificatePEM.ValueString() == "" || pkiPlan.PrivateKeyPEM.ValueString() == "" {
		t.Fatalf("pki model not populated: %+v", pkiPlan)
	}
	if _, _, _, err := pkiRes.issue(t.Context(), pkiCertificateResourceModel{CommonName: types.StringValue("svc"), TTLSeconds: types.Int64Value(0)}, "create"); err == nil {
		t.Fatal("pki issue accepted non-positive ttl")
	}

	secretPlan := secretResourceModel{
		Name:           types.StringValue("apps/api/password"),
		Value:          types.StringValue("initial-fixture-value"),
		IdempotencyKey: types.StringValue("explicit-secret-seed"),
	}
	name, value, seed, err := secretPlanFields(secretPlan)
	if err != nil {
		t.Fatalf("secretPlanFields: %v", err)
	}
	meta, err := client.CreateSecret(t.Context(), name, value, stableIdempotencyKey(seed, "secret", "create", name))
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	secretPlan.applyMeta(meta, seed)
	if secretPlan.ID.ValueString() != "apps/api/password" || secretPlan.Version.ValueInt64() != 1 || secretPlan.IdempotencyKey.ValueString() != "explicit-secret-seed" {
		t.Fatalf("secret model not populated: %+v", secretPlan)
	}
	if _, _, _, err := secretPlanFields(secretResourceModel{Name: types.StringValue("apps/api/password"), Value: types.StringNull()}); err == nil {
		t.Fatal("secretPlanFields accepted null value")
	}
}
