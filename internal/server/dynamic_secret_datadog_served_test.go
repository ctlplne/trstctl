// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// servedDatadogSite is a stand-in for a Datadog site's key API, built from
// Datadog's API documentation: API keys and service-account application keys
// are created (the key returned once), listed by name filter, read and
// deleted with the administrator's API and application keys, and
// /api/v1/validate accepts a live API key.
type servedDatadogSite struct {
	mu     sync.Mutex
	keys   map[string]servedDatadogKey // id -> key
	serial int
}

type servedDatadogKey struct {
	collection, name, key string
	scopes                []string
}

func (d *servedDatadogSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.URL.Path == "/api/v1/validate" {
		for _, key := range d.keys {
			if key.collection == "/api/v2/api_keys" && key.key == r.Header.Get("DD-API-KEY") {
				_, _ = w.Write([]byte(`{"valid":true}`))
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Header.Get("DD-API-KEY") != "served-admin-api-key" || r.Header.Get("DD-APPLICATION-KEY") != "served-admin-app-key" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	collection, id := r.URL.Path, ""
	if strings.HasPrefix(r.URL.Path, "/api/v2/api_keys/") || strings.Count(r.URL.Path, "/") == 6 {
		cut := strings.LastIndex(r.URL.Path, "/")
		collection, id = r.URL.Path[:cut], r.URL.Path[cut+1:]
	}
	switch {
	case r.Method == http.MethodPost && id == "":
		var body struct {
			Data struct {
				Attributes struct {
					Name   string   `json:"name"`
					Scopes []string `json:"scopes"`
				} `json:"attributes"`
			} `json:"data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		d.serial++
		keyID, key := fmt.Sprintf("dd-key-%04d", d.serial), fmt.Sprintf("%032x", 0xdd00+d.serial)
		d.keys[keyID] = servedDatadogKey{collection: collection, name: body.Data.Attributes.Name, key: key, scopes: body.Data.Attributes.Scopes}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": keyID, "attributes": map[string]any{"key": key, "name": body.Data.Attributes.Name}}})
	case r.Method == http.MethodGet && id == "":
		var data []map[string]any
		for keyID, key := range d.keys {
			if key.collection == collection && strings.Contains(key.name, r.URL.Query().Get("filter")) {
				data = append(data, map[string]any{"id": keyID, "attributes": map[string]any{"name": key.name}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	case r.Method == http.MethodGet:
		key, ok := d.keys[id]
		if !ok || key.collection != collection {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": id, "attributes": map[string]any{"name": key.name}}})
	case r.Method == http.MethodDelete:
		if key, ok := d.keys[id]; !ok || key.collection != collection {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(d.keys, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// validates asks the site whether apiKey is live, as a consumer would.
func (d *servedDatadogSite) validates(t *testing.T, site, apiKey string) bool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, site+"/api/v1/validate", nil)
	req.Header.Set("DD-API-KEY", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (d *servedDatadogSite) applicationKeyScopes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, key := range d.keys {
		if strings.HasSuffix(key.collection, "/application_keys") {
			return key.scopes
		}
	}
	return nil
}

// A240 Datadog, against a stand-in of the key API: a lease is a new API key
// that validates until revocation deletes it. A static rotation is two-phase:
// the successor is created next to the predecessor, both validate until the
// approved deadline, and retirement then deletes only the predecessor. An
// application-key role rotates too; with no side-effect-free proof for a
// scoped key, its command records verify mode not_available.
func TestServedDatadogKeysLeaseAndRotateInTwoPhasesA240(t *testing.T) {
	site := &servedDatadogSite{keys: map[string]servedDatadogKey{}}
	stand := httptest.NewServer(site)
	defer stand.Close()
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "datadog-org", Type: "datadog", Endpoint: stand.URL,
		APIKeyRef:         writeServedCredentialFile(t, "dd-admin-api", "served-admin-api-key"),
		ApplicationKeyRef: writeServedCredentialFile(t, "dd-admin-app", "served-admin-app-key"),
		AllowedRoles:      []string{"datadog/ingest", "datadog/metrics"},
		RoleBindings: map[string]string{"datadog/ingest": "api_key",
			"datadog/metrics": "application_key 3f1e7e1a-1111-4222-8333-444455556666 metrics_read,timeseries_query"},
		MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
	}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "A240 Datadog tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	apiKeyOf := func(credential string) string {
		t.Helper()
		var parsed struct {
			APIKey string `json:"api_key"`
		}
		if err := json.Unmarshal([]byte(credential), &parsed); err != nil || parsed.APIKey == "" {
			t.Fatalf("the credential carries no API key: %v", err)
		}
		return parsed.APIKey
	}

	// A lease is an API key that validates until revocation deletes it.
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a240-dd-lease-1",
		map[string]any{"provider": "datadog-org", "role": "datadog/ingest", "ttl_seconds": 600})
	var lease dynamicLeaseView
	if (status != http.StatusCreated && status != http.StatusOK) || json.Unmarshal(body, &lease) != nil || lease.Credential == "" {
		t.Fatalf("issue: %d %s", status, body)
	}
	leased := apiKeyOf(lease.Credential)
	if !site.validates(t, stand.URL, leased) {
		t.Fatal("the leased key does not validate")
	}
	if status, body := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/leases/"+lease.ID+"/revoke", tok, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("revoke: %d %s", status, body)
	}
	for deadline := time.Now().Add(30 * time.Second); ; {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+lease.ID, tok, nil)
		var view dynamicLeaseView
		if status == http.StatusOK && json.Unmarshal(body, &view) == nil && view.RevocationStatus == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the revocation did not complete: %d %s", status, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if site.validates(t, stand.URL, leased) {
		t.Fatal("the revoked key still validates")
	}

	command := func(id string) staticRotationCommandView {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+id, tok, nil)
		var view staticRotationCommandView
		if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
			t.Fatalf("read command %s: %d %s", id, status, body)
		}
		return view
	}
	await := func(id string, until func(staticRotationCommandView) bool) staticRotationCommandView {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); ; {
			if view := command(id); until(view) {
				return view
			} else if time.Now().After(deadline) {
				t.Fatalf("command %s: %+v", id, view)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	rotate := func(key, idempotencyKey string, request map[string]any) string {
		t.Helper()
		request["provider"], request["key"] = "datadog-org", key
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, idempotencyKey, request)
		var queued struct {
			CommandID string `json:"command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.CommandID == "" {
			t.Fatalf("rotate %s: %d %s", key, status, body)
		}
		return queued.CommandID
	}
	storedAPIKey := func() string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/datadog/ingest", tok, nil)
		var stored struct {
			Value string `json:"value"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &stored) != nil {
			t.Fatalf("read the stored key: %d", status)
		}
		return apiKeyOf(stored.Value)
	}
	terminal := func(view staticRotationCommandView) bool { return view.Terminal }

	// Two-phase rotation: the first creates the stored key; the second creates
	// its successor next to it, both validate until the approved deadline, and
	// retirement deletes only the predecessor.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-dd-ingest",
		map[string]any{"name": "datadog/ingest", "value": `{"api_key":"issued-outside-trstctl"}`}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	first := await(rotate("datadog/ingest", "dd-rotate-1", map[string]any{"old_ref": "none"}), terminal)
	if first.Phase != store.SecretStaticRotationCompleted || first.RotationPhase != "two_phase" || first.VerifyMode != "authenticated" ||
		!first.CredentialValid || !strings.HasPrefix(first.NewRef, "api_key/") {
		t.Fatalf("the first rotation: %+v", first)
	}
	predecessor := storedAPIKey()
	second := rotate("datadog/ingest", "dd-rotate-2", map[string]any{"old_ref": first.NewRef, "retire_after_seconds": 2})
	verified := await(second, func(view staticRotationCommandView) bool {
		return view.Phase == store.SecretStaticRotationVerified || view.Terminal
	})
	if verified.Phase != store.SecretStaticRotationVerified || verified.VerifyMode != "authenticated" || verified.RetireNotBefore == nil {
		t.Fatalf("the second rotation before its deadline: %+v", verified)
	}
	successor := storedAPIKey()
	if successor == predecessor || !site.validates(t, stand.URL, successor) || !site.validates(t, stand.URL, predecessor) {
		t.Fatal("both keys must validate between cutover and retirement")
	}
	retired := await(second, terminal)
	if retired.Phase != store.SecretStaticRotationCompleted || retired.OldRef != first.NewRef || retired.TerminalAt == nil ||
		retired.TerminalAt.Before(*retired.RetireNotBefore) {
		t.Fatalf("the second rotation at retirement: %+v", retired)
	}
	if site.validates(t, stand.URL, predecessor) || !site.validates(t, stand.URL, successor) {
		t.Fatal("retirement must delete the predecessor and only the predecessor")
	}

	// An application-key role rotates without a self-proof.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-dd-metrics",
		map[string]any{"name": "datadog/metrics", "value": `{"application_key":"issued-outside-trstctl"}`}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	scoped := await(rotate("datadog/metrics", "dd-rotate-app-1", map[string]any{"old_ref": "none"}), terminal)
	if scoped.Phase != store.SecretStaticRotationCompleted || scoped.VerifyMode != "not_available" ||
		!strings.HasPrefix(scoped.NewRef, "3f1e7e1a-1111-4222-8333-444455556666/") {
		t.Fatalf("the application-key rotation: %+v", scoped)
	}
	if scopes := strings.Join(site.applicationKeyScopes(), ","); scopes != "metrics_read,timeseries_query" {
		t.Fatalf("the application key's scopes: %q", scopes)
	}
}
