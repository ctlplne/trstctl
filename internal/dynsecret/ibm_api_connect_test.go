// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const apiConnectLabApp = "acme/sandbox/partners/orders-app"

// apiConnectStandIn follows the platform REST API's token and app-credential
// endpoints as IBM documents them: the api_key grant returns a bearer token;
// POST credentials returns a generated client ID and secret (409 for a name
// already taken); DELETE answers 200, or 404 for a credential that is gone.
type apiConnectStandIn struct {
	mu          sync.Mutex
	credentials map[string][2]string // name -> client id, secret
	minted      int
}

func newAPIConnectStandIn(t *testing.T) (*apiConnectStandIn, *httptest.Server) {
	t.Helper()
	lab := &apiConnectStandIn{credentials: map[string][2]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lab.mu.Lock()
		defer lab.mu.Unlock()
		if r.URL.Path == "/api/token" {
			var in struct{ APIKey, ClientID, ClientSecret, GrantType string }
			_ = json.NewDecoder(r.Body).Decode(&struct {
				APIKey       *string `json:"api_key"`
				ClientID     *string `json:"client_id"`
				ClientSecret *string `json:"client_secret"`
				GrantType    *string `json:"grant_type"`
			}{&in.APIKey, &in.ClientID, &in.ClientSecret, &in.GrantType})
			if in.GrantType != "api_key" || in.APIKey != "lab-api-key" || in.ClientID != "toolkit" || in.ClientSecret != "toolkit-secret" { // #nosec G101 -- fabricated stand-in platform credentials (CWE-798)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "apic-lab-token", "token_type": "Bearer", "expires_in": 28800}) // #nosec G101 -- fabricated stand-in token (CWE-798)
			return
		}
		if r.Header.Get("Authorization") != "Bearer apic-lab-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		collection := "/api/apps/" + apiConnectLabApp + "/credentials"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == collection:
			var in struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			if _, exists := lab.credentials[in.Name]; exists {
				w.WriteHeader(http.StatusConflict)
				return
			}
			lab.minted++
			lab.credentials[in.Name] = [2]string{"client-" + strconv.Itoa(lab.minted), "secret-" + strconv.Itoa(lab.minted)}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"name": in.Name, "client_id": lab.credentials[in.Name][0], "client_secret": lab.credentials[in.Name][1]})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, collection+"/"):
			name := strings.TrimPrefix(r.URL.Path, collection+"/")
			if _, exists := lab.credentials[name]; !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(lab.credentials, name)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func TestAPIConnectLeaseIsAnAppCredentialA239(t *testing.T) {
	lab, srv := newAPIConnectStandIn(t)
	b, err := NewAPIConnectBackend(APIConnectConfig{Endpoint: srv.URL, ClientID: "toolkit", ClientSecret: []byte("toolkit-secret"),
		APIKey: []byte("lab-api-key"), RoleBindings: map[string]string{"partner": apiConnectLabApp}, AllowInsecureLoopback: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	req := GenerateRequest{Role: "partner", LeaseID: "lease-0001"}
	ref, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		App          string
	}
	name := strings.TrimPrefix(ref, apiConnectLabApp+"/")
	if err := json.Unmarshal(credential, &got); err != nil || got.App != apiConnectLabApp || lab.credentials[name] != [2]string{got.ClientID, got.ClientSecret} {
		t.Fatalf("credential %+v (%v), stored %v", got, err, lab.credentials)
	}
	// A retry replaces the credential under the same name (the secret can't be
	// read back); no second credential appears.
	again, credential2, err := b.CreateCredential(context.Background(), req)
	var got2 struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(credential2, &got2)
	if err != nil || again != ref || len(lab.credentials) != 1 || got2.ClientID == got.ClientID {
		t.Fatalf("retry: %q (%v); credentials %v", again, err, lab.credentials)
	}
	if err := b.Revoke(context.Background(), ref); err != nil || len(lab.credentials) != 0 {
		t.Fatalf("revoke: %v; credentials %v", err, lab.credentials)
	}
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("a second revocation: %v", err)
	}
	for _, foreign := range []string{"trstctl-partner-0123456789", "acme/sandbox/partners/other-app/" + name, apiConnectLabApp + "/production-key",
		apiConnectLabApp + "/trstctl-admin"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("deleted %q, a credential this provider did not create", foreign)
		}
	}
}

func TestAPIConnectConfigA239(t *testing.T) {
	if app, err := ParseAPIConnectApp(" acme/sandbox/partners/orders-app "); err != nil || app != apiConnectLabApp {
		t.Fatalf("app %q (%v)", app, err)
	}
	for _, bad := range []string{"acme/sandbox/orders-app", "acme/sandbox/partners/orders-app/x", "Acme/sandbox/partners/app", "acme/../partners/app"} {
		if _, err := ParseAPIConnectApp(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	base := APIConnectConfig{Endpoint: "https://apic.example", ClientID: "toolkit", ClientSecret: []byte("s"), APIKey: []byte("k"),
		RoleBindings: map[string]string{"r": apiConnectLabApp}, HTTPClient: http.DefaultClient}
	for name, mutate := range map[string]func(*APIConnectConfig){
		"plain http": func(c *APIConnectConfig) { c.Endpoint = "http://apic.example" },
		"no client":  func(c *APIConnectConfig) { c.ClientID = "" },
		"no api key": func(c *APIConnectConfig) { c.APIKey = nil },
		"no roles":   func(c *APIConnectConfig) { c.RoleBindings = nil },
		"bad app":    func(c *APIConnectConfig) { c.RoleBindings = map[string]string{"r": "orders-app"} },
	} {
		c := base
		mutate(&c)
		if b, err := NewAPIConnectBackend(c); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}
