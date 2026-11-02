// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// servedOpenAIOrganization is a stand-in for the OpenAI admin API's project
// service accounts, built from its documentation: creating one returns its
// API key once, the list pages with limit/after/has_more, deleting one deletes
// its key, and GET /v1/models accepts a live key.
type servedOpenAIOrganization struct {
	mu       sync.Mutex
	accounts map[string][3]string // id -> project, name, key
	serial   int
}

func (o *servedOpenAIOrganization) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if r.URL.Path == "/v1/models" {
		for _, account := range o.accounts {
			if "Bearer "+account[2] == r.Header.Get("Authorization") {
				_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "Bearer served-openai-admin-key" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/organization/projects/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	project, rest, _ := strings.Cut(rest, "/service_accounts")
	id := strings.TrimPrefix(rest, "/")
	switch {
	case r.Method == http.MethodPost && id == "":
		var body struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		o.serial++
		accountID, key := fmt.Sprintf("svc_acct_served%04d", o.serial), fmt.Sprintf("sk-svcacct-served-%04d", o.serial)
		o.accounts[accountID] = [3]string{project, body.Name, key}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "organization.project.service_account", "id": accountID, "name": body.Name,
			"role": "member", "api_key": map[string]any{"object": "organization.project.service_account.api_key", "value": key, "id": "key_" + accountID}})
	case r.Method == http.MethodGet && id == "":
		var ids []string
		for accountID, account := range o.accounts {
			if account[0] == project {
				ids = append(ids, accountID)
			}
		}
		sort.Strings(ids)
		var data []map[string]any
		for _, accountID := range ids {
			data = append(data, map[string]any{"id": accountID, "name": o.accounts[accountID][1]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data, "has_more": false})
	case r.Method == http.MethodGet:
		account, ok := o.accounts[id]
		if !ok || account[0] != project {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "name": account[1]})
	case r.Method == http.MethodDelete:
		if account, ok := o.accounts[id]; !ok || account[0] != project {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(o.accounts, id)
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "organization.project.service_account.deleted", "id": id, "deleted": true})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (o *servedOpenAIOrganization) authenticates(t *testing.T, api, key string) bool {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, api+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// A240 OpenAI, against a stand-in of the admin API: a lease is a project
// service account whose key authenticates until revocation deletes the
// account; a static rotation is two-phase, both keys authenticating until the
// approved deadline, after which only the predecessor's account is deleted.
func TestServedOpenAIServiceAccountKeysLeaseAndRotateA240(t *testing.T) {
	organization := &servedOpenAIOrganization{accounts: map[string][3]string{}}
	stand := httptest.NewServer(organization)
	defer stand.Close()
	configs := []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "openai-org", Type: "openai", Endpoint: stand.URL,
		APIKeyRef:    writeServedCredentialFile(t, "openai-admin", "served-openai-admin-key"),
		AllowedRoles: []string{"openai/orders"}, RoleBindings: map[string]string{"openai/orders": "proj_orders"},
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
	registerServedTenant(t, h, "A240 OpenAI tenant")
	startServedExternalCADispatcher(t, h)
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	keyOf := func(credential string) string {
		t.Helper()
		var parsed struct {
			APIKey string `json:"api_key"`
		}
		if err := json.Unmarshal([]byte(credential), &parsed); err != nil || parsed.APIKey == "" {
			t.Fatalf("the credential carries no API key: %v", err)
		}
		return parsed.APIKey
	}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", tok, "a240-openai-lease-1",
		map[string]any{"provider": "openai-org", "role": "openai/orders", "ttl_seconds": 600})
	var lease dynamicLeaseView
	if (status != http.StatusCreated && status != http.StatusOK) || json.Unmarshal(body, &lease) != nil || lease.Credential == "" {
		t.Fatalf("issue: %d %s", status, body)
	}
	leased := keyOf(lease.Credential)
	if !organization.authenticates(t, stand.URL, leased) {
		t.Fatal("the leased key does not authenticate")
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
	if organization.authenticates(t, stand.URL, leased) {
		t.Fatal("the revoked key still authenticates")
	}

	await := func(id string, until func(staticRotationCommandView) bool) staticRotationCommandView {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); ; {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+id, tok, nil)
			var view staticRotationCommandView
			if status != http.StatusOK || json.Unmarshal(body, &view) != nil {
				t.Fatalf("read command %s: %d %s", id, status, body)
			}
			if until(view) {
				return view
			}
			if time.Now().After(deadline) {
				t.Fatalf("command %s: %+v", id, view)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	rotate := func(idempotencyKey string, request map[string]any) string {
		t.Helper()
		request["provider"], request["key"] = "openai-org", "openai/orders"
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, idempotencyKey, request)
		var queued struct {
			CommandID string `json:"command_id"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &queued) != nil || queued.CommandID == "" {
			t.Fatalf("rotate: %d %s", status, body)
		}
		return queued.CommandID
	}
	stored := func() string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/openai/orders", tok, nil)
		var value struct {
			Value string `json:"value"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &value) != nil {
			t.Fatalf("read the stored key: %d", status)
		}
		return keyOf(value.Value)
	}
	terminal := func(view staticRotationCommandView) bool { return view.Terminal }
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "seed-openai-orders",
		map[string]any{"name": "openai/orders", "value": `{"api_key":"issued-outside-trstctl"}`}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed secret: %d %s", status, body)
	}
	first := await(rotate("openai-rotate-1", map[string]any{"old_ref": "none"}), terminal)
	if first.Phase != store.SecretStaticRotationCompleted || first.RotationPhase != "two_phase" || first.VerifyMode != "authenticated" ||
		!strings.HasPrefix(first.NewRef, "proj_orders/svc_acct_") {
		t.Fatalf("the first rotation: %+v", first)
	}
	predecessor := stored()
	second := rotate("openai-rotate-2", map[string]any{"old_ref": first.NewRef, "retire_after_seconds": 2})
	verified := await(second, func(view staticRotationCommandView) bool {
		return view.Phase == store.SecretStaticRotationVerified || view.Terminal
	})
	successor := stored()
	if verified.Phase != store.SecretStaticRotationVerified || successor == predecessor ||
		!organization.authenticates(t, stand.URL, predecessor) || !organization.authenticates(t, stand.URL, successor) {
		t.Fatalf("both keys must authenticate between cutover and retirement: %+v", verified)
	}
	if retired := await(second, terminal); retired.Phase != store.SecretStaticRotationCompleted || retired.OldRef != first.NewRef {
		t.Fatalf("the second rotation at retirement: %+v", retired)
	}
	if organization.authenticates(t, stand.URL, predecessor) || !organization.authenticates(t, stand.URL, successor) {
		t.Fatal("retirement must delete the predecessor's service account and only that one")
	}
}
