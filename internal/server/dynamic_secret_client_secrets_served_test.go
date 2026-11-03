// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// basicClient reads an HTTP Basic client authentication.
func basicClient(r *http.Request) (string, string, bool) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Basic ")
	if !ok {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", "", false
	}
	id, secretText, ok := strings.Cut(string(decoded), ":")
	return id, secretText, ok
}

// --- Okta ---------------------------------------------------------------------

// servedOkta is a stand-in for Okta's app client-secret API, from its
// reference: an app holds at most two secrets, a new one is ACTIVE, only an
// INACTIVE secret can be deleted, the last active one cannot be deactivated,
// and the introspection endpoint authenticates the client before reading the
// token.
type servedOkta struct {
	mu      sync.Mutex
	secrets map[string][2]string // id -> status, value
	serial  int
}

func (o *servedOkta) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if r.URL.Path == "/oauth2/v1/introspect" {
		id, value, ok := basicClient(r)
		if ok && id == "0oaclient123" {
			for _, secret := range o.secrets {
				if secret[0] == "ACTIVE" && secret[1] == value {
					hostedJSONReply(w, http.StatusOK, map[string]bool{"active": false})
					return
				}
			}
		}
		hostedJSONReply(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.Header.Get("Authorization") != "SSWS served-okta-api-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	const app = "/api/v1/apps/0oa1b2c3d4e5f6g7h8i9"
	switch rest, _ := strings.CutPrefix(r.URL.Path, app); {
	case r.URL.Path == app && r.Method == http.MethodGet:
		hostedJSONReply(w, http.StatusOK, map[string]any{"id": "0oa1b2c3d4e5f6g7h8i9", "credentials": map[string]any{"oauthClient": map[string]string{"client_id": "0oaclient123"}}})
	case rest == "/credentials/secrets" && r.Method == http.MethodPost:
		if len(o.secrets) >= 2 {
			hostedJSONReply(w, http.StatusBadRequest, map[string]string{"errorSummary": "an app has at most two client secrets"})
			return
		}
		o.serial++
		id, value := fmt.Sprintf("ocs%04d", o.serial), fmt.Sprintf("served-okta-secret-%04d-padding", o.serial)
		o.secrets[id] = [2]string{"ACTIVE", value}
		hostedJSONReply(w, http.StatusCreated, map[string]string{"id": id, "client_secret": value, "status": "ACTIVE"})
	case strings.HasPrefix(rest, "/credentials/secrets/"):
		id, action, _ := strings.Cut(strings.TrimPrefix(rest, "/credentials/secrets/"), "/")
		secret, found := o.secrets[id]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case r.Method == http.MethodGet && action == "":
			hostedJSONReply(w, http.StatusOK, map[string]string{"id": id, "status": secret[0]})
		case r.Method == http.MethodPost && action == "lifecycle/deactivate":
			active := 0
			for _, other := range o.secrets {
				if other[0] == "ACTIVE" {
					active++
				}
			}
			if secret[0] == "ACTIVE" && active == 1 {
				hostedJSONReply(w, http.StatusBadRequest, map[string]string{"errorSummary": "cannot deactivate the only active secret"})
				return
			}
			o.secrets[id] = [2]string{"INACTIVE", secret[1]}
			hostedJSONReply(w, http.StatusOK, map[string]string{"id": id, "status": "INACTIVE"})
		case r.Method == http.MethodDelete && action == "":
			if secret[0] != "INACTIVE" {
				hostedJSONReply(w, http.StatusBadRequest, map[string]string{"errorSummary": "only an inactive secret can be deleted"})
				return
			}
			delete(o.secrets, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// A240 Okta, against a stand-in of the apps API: rotation only; the first
// rotation retires the app's original secret (old_ref names it, the bound app
// being the boundary), and each later one keeps both secrets working until
// retirement deactivates and deletes the predecessor, within Okta's two.
func TestServedOktaClientSecretsRotateA240(t *testing.T) {
	vendor := &servedOkta{secrets: map[string][2]string{"ocs-original": {"ACTIVE", "original-okta-secret-value"}}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	authenticates := func(t *testing.T, value string) bool {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, stand.URL+"/oauth2/v1/introspect", strings.NewReader("token=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("0oaclient123", value)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "okta-org", Type: "okta", Endpoint: stand.URL,
			APIKeyRef:    writeServedCredentialFile(t, "okta-api-token", "served-okta-api-token"),
			AllowedRoles: []string{"okta/portal"}, RoleBindings: map[string]string{"okta/portal": "0oa1b2c3d4e5f6g7h8i9"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "okta/portal", seed: `{"client_id":"0oaclient123","client_secret":"original-okta-secret-value"}`,
		firstOldRef: "0oa1b2c3d4e5f6g7h8i9/ocs-original",
		keyOf:       hostedKeyOf("client_secret"), authenticates: authenticates,
		newRefPrefix: "0oa1b2c3d4e5f6g7h8i9/ocs", wantVerifyMode: "authenticated",
	}.run(t)
	vendor.mu.Lock()
	defer vendor.mu.Unlock()
	if _, ok := vendor.secrets["ocs-original"]; ok || len(vendor.secrets) != 1 {
		t.Fatalf("after two rotations the app must hold only the latest secret: %v", vendor.secrets)
	}
}

// --- Databricks -----------------------------------------------------------------

const servedDatabricksAccount = "a1b2c3d4-0000-4000-8000-0123456789ab"

// servedDatabricks is a stand-in for the Databricks account API's service
// principal secrets and account-level OAuth tokens, from its reference.
type servedDatabricks struct {
	mu      sync.Mutex
	secrets map[string]string // id -> value, of service principal 4471234567890123
	tokens  map[string]bool
	serial  int
}

func (d *servedDatabricks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.URL.Path == "/oidc/accounts/"+servedDatabricksAccount+"/v1/token" {
		id, value, ok := basicClient(r)
		if r.ParseForm() != nil || r.PostForm.Get("grant_type") != "client_credentials" || !ok {
			hostedJSONReply(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		live := id == "admin-sp-app-id" && value == "served-databricks-admin-secret"
		for _, secret := range d.secrets {
			live = live || (id == "sp-app-id-4471" && secret == value)
		}
		if !live {
			hostedJSONReply(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
		d.serial++
		token := fmt.Sprintf("served-databricks-token-%04d", d.serial)
		if id == "admin-sp-app-id" {
			d.tokens[token] = true
		}
		hostedJSONReply(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
		return
	}
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !d.tokens[token] {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	const base = "/api/2.0/accounts/" + servedDatabricksAccount
	path := strings.TrimPrefix(r.URL.Path, base)
	switch {
	case path == "/scim/v2/ServicePrincipals/4471234567890123" && r.Method == http.MethodGet:
		hostedJSONReply(w, http.StatusOK, map[string]string{"id": "4471234567890123", "applicationId": "sp-app-id-4471"})
	case path == "/servicePrincipals/4471234567890123/credentials/secrets" && r.Method == http.MethodPost:
		if len(d.secrets) >= 5 {
			hostedJSONReply(w, http.StatusBadRequest, map[string]string{"error_code": "RESOURCE_LIMIT_EXCEEDED"})
			return
		}
		d.serial++
		id, value := fmt.Sprintf("dbs%04d", d.serial), fmt.Sprintf("dose-served-%04d", d.serial)
		d.secrets[id] = value
		hostedJSONReply(w, http.StatusOK, map[string]string{"id": id, "secret": value, "status": "ACTIVE"})
	case path == "/servicePrincipals/4471234567890123/credentials/secrets" && r.Method == http.MethodGet:
		list := []map[string]string{}
		for id := range d.secrets {
			list = append(list, map[string]string{"id": id, "status": "ACTIVE"})
		}
		hostedJSONReply(w, http.StatusOK, map[string]any{"secrets": list})
	case strings.HasPrefix(path, "/servicePrincipals/4471234567890123/credentials/secrets/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/servicePrincipals/4471234567890123/credentials/secrets/")
		if _, ok := d.secrets[id]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(d.secrets, id)
		hostedJSONReply(w, http.StatusOK, map[string]any{})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// A240 Databricks, against a stand-in of the account API: rotation only; a
// new OAuth secret of the bound service principal gets an account-level token
// beside the old one until retirement deletes the old one.
func TestServedDatabricksServicePrincipalSecretsRotateA240(t *testing.T) {
	vendor := &servedDatabricks{secrets: map[string]string{}, tokens: map[string]bool{}}
	stand := httptest.NewServer(vendor)
	defer stand.Close()
	authenticates := func(t *testing.T, value string) bool {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, stand.URL+"/oidc/accounts/"+servedDatabricksAccount+"/v1/token", strings.NewReader("grant_type=client_credentials&scope=all-apis"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("sp-app-id-4471", value)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	hostedKeyProof{
		provider: config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "databricks-account", Type: "databricks", Endpoint: stand.URL,
			ClientID: "admin-sp-app-id", ClientSecretRef: writeServedCredentialFile(t, "databricks-admin", "served-databricks-admin-secret"),
			AllowedRoles: []string{"databricks/etl"}, RoleBindings: map[string]string{"databricks/etl": servedDatabricksAccount + " 4471234567890123"},
			MaxTTL: "1h", AllowStaticRotation: true, AllowInsecureLoopback: true,
		},
		role: "databricks/etl", seed: `{"client_id":"sp-app-id-4471","client_secret":"issued-outside-trstctl"}`,
		keyOf: hostedKeyOf("client_secret"), authenticates: authenticates,
		newRefPrefix: servedDatabricksAccount + ":4471234567890123/dbs", wantVerifyMode: "authenticated",
	}.run(t)
}
