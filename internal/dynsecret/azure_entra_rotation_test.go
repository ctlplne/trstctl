// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A240: Entra revocation removes only passwords this provider added (a
// static rotation's old_ref is operator input), and a secret is proven with
// a client-credentials token request whose form escapes every byte of it.
func TestAzureEntraRevokeRemovesOnlyIssuedPasswordsA240(t *testing.T) {
	removed := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/applications/obj":
			_ = json.NewEncoder(w).Encode(map[string]any{"passwordCredentials": []map[string]string{
				{"keyId": "issued", "displayName": "trstctl-lease_1"}, {"keyId": "foreign", "displayName": "Production"},
			}})
		case "/v1.0/applications/obj/removePassword":
			var body struct{ KeyID string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			removed = append(removed, body.KeyID)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	b, err := NewAzureEntraBackend(AzureEntraConfig{Endpoint: srv.URL, HTTPClient: srv.Client(), ApplicationObjectID: "obj", ApplicationClientID: "client", TenantID: "tenant", BearerToken: []byte("graph")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Revoke(context.Background(), "foreign"); err == nil || !strings.Contains(err.Error(), "did not add") {
		t.Fatalf("a foreign password: %v", err)
	}
	if err := b.Revoke(context.Background(), "gone"); err != nil {
		t.Fatalf("a password already gone: %v", err)
	}
	if err := b.Revoke(context.Background(), "issued"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, ",") != "issued" {
		t.Fatalf("removed %v", removed)
	}
}

func TestAzureEntraVerifySendsTheSecretFormEncodedA240(t *testing.T) {
	const formSample = "a+b c&d=é~"
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant/oauth2/v2.0/token" || r.ParseForm() != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		got = r.PostForm
		if r.PostForm.Get("client_secret") != formSample {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()
	b, err := NewAzureEntraBackend(AzureEntraConfig{Endpoint: srv.URL, AuthorityHost: srv.URL, HTTPClient: srv.Client(), ApplicationObjectID: "obj", ApplicationClientID: "client", TenantID: "tenant"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	credential := func(tenant, client, secretText string) []byte {
		raw, _ := json.Marshal(map[string]string{"tenant_id": tenant, "client_id": client, "client_secret": secretText})
		return raw
	}
	if err := b.VerifyCredential(context.Background(), credential("tenant", "client", formSample)); err != nil {
		t.Fatal(err)
	}
	if got.Get("grant_type") != "client_credentials" || got.Get("client_id") != "client" || got.Get("scope") != "https://graph.microsoft.com/.default" {
		t.Fatalf("form = %v", got)
	}
	if err := b.VerifyCredential(context.Background(), credential("tenant", "client", "wrong")); err == nil {
		t.Fatal("a wrong secret verified")
	}
	if err := b.VerifyCredential(context.Background(), credential("tenant", "another-client", formSample)); err == nil {
		t.Fatal("another application's credential verified")
	}
}
