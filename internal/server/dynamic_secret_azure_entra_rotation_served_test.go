// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// servedEntra is a stand-in for Microsoft Graph's application password
// operations and the identity platform's client-credentials grant, from their
// API references: addPassword returns the secret once, the application lists
// only key IDs and display names, removePassword takes a key ID, and the token
// endpoint issues a token only for a live secret of the application.
type servedEntra struct {
	mu        sync.Mutex
	passwords map[string][2]string // keyId -> displayName, secretText
	serial    int
}

func (e *servedEntra) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.URL.Path == "/tenant-1/oauth2/v2.0/token" {
		if r.ParseForm() != nil || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "client-1" ||
			r.PostForm.Get("scope") != "https://graph.microsoft.com/.default" {
			hostedJSONReply(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		for _, password := range e.passwords {
			if password[1] == r.PostForm.Get("client_secret") {
				hostedJSONReply(w, http.StatusOK, map[string]any{"token_type": "Bearer", "expires_in": 3600, "access_token": "served-access-token"})
				return
			}
		}
		hostedJSONReply(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer served-graph-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1.0/applications/obj-1" && r.URL.Query().Get("$select") == "passwordCredentials":
		list := []map[string]string{}
		for keyID, password := range e.passwords {
			list = append(list, map[string]string{"keyId": keyID, "displayName": password[0], "hint": password[1][:3]})
		}
		hostedJSONReply(w, http.StatusOK, map[string]any{"passwordCredentials": list})
	case r.Method == http.MethodPost && r.URL.Path == "/v1.0/applications/obj-1/addPassword":
		var body struct {
			PasswordCredential struct {
				DisplayName string `json:"displayName"`
			} `json:"passwordCredential"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.PasswordCredential.DisplayName == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		e.serial++
		keyID, secretText := fmt.Sprintf("served-key-%04d", e.serial), fmt.Sprintf("Served~Secret.%04d", e.serial)
		e.passwords[keyID] = [2]string{body.PasswordCredential.DisplayName, secretText}
		hostedJSONReply(w, http.StatusOK, map[string]string{"keyId": keyID, "displayName": body.PasswordCredential.DisplayName, "secretText": secretText})
	case r.Method == http.MethodPost && r.URL.Path == "/v1.0/applications/obj-1/removePassword":
		var body struct {
			KeyID string `json:"keyId"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := e.passwords[body.KeyID]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(e.passwords, body.KeyID)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// A240 Azure Entra client secrets, against a stand-in of Graph and the
// identity platform: a lease is a client secret that gets a token until
// revocation removes it; a static rotation is two-phase, both secrets getting
// tokens until retirement removes the predecessor; and the application's own
// production secret, which the provider did not add, is never removed.
func TestServedAzureEntraClientSecretsLeaseAndRotateA240(t *testing.T) {
	vendor := &servedEntra{passwords: map[string][2]string{"production-key": {"Production", "Prod~Secret.0001"}}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	tokenFor := func(t *testing.T, clientSecret string) bool {
		t.Helper()
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"client-1"}, "client_secret": {clientSecret},
			"scope": {"https://graph.microsoft.com/.default"}}
		resp, err := http.Post(stand.URL+"/tenant-1/oauth2/v2.0/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "entra-app", Type: "azure-entra", Endpoint: stand.URL, AuthorityHost: stand.URL,
			ApplicationObject: "obj-1", ApplicationClient: "client-1", AzureTenant: "tenant-1",
			BearerTokenRef: writeServedCredentialFile(t, "entra-graph-token", "served-graph-token"),
			AllowedRoles:   []string{"entra/app"}, MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "entra/app", seed: `{"tenant_id":"tenant-1","client_id":"client-1","client_secret":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("client_secret"), authenticates: tokenFor,
		newRefPrefix: "served-key-", leases: true, wantVerifyMode: "authenticated",
	}.run(t)
	vendor.mu.Lock()
	defer vendor.mu.Unlock()
	if _, ok := vendor.passwords["production-key"]; !ok {
		t.Fatal("the application's production secret was removed")
	}
}
