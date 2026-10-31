// SPDX-License-Identifier: BUSL-1.1

package mdm_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/mdm"
)

const (
	entraDirectory = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
	entraClient    = "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
	entraSecret    = "client secret with spaces & symbols=+/"                                                          // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	entraToken     = "eyJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6WyJEZXZpY2VNYW5hZ2VtZW50TWFuYWdlZERldmljZXMuUmVhZC5BbGwiXX0.c2ln" // #nosec G101 -- an unsigned stand-in token shape, not a credential (CWE-798)
)

// entraStandIn is a token endpoint built from Microsoft's documented
// client-credentials grant: form POST to /{tenant}/oauth2/v2.0/token with
// grant_type, client_id, client_secret and scope; JSON bearer grant back, or
// an OAuth error object.
func entraStandIn(t *testing.T, requests *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		body, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(body))
		if r.Method != http.MethodPost || r.URL.Path != "/"+entraDirectory+"/oauth2/v2.0/token" || err != nil ||
			r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		if form.Get("grant_type") != "client_credentials" || form.Get("scope") != mdm.GraphApplicationScope || form.Get("client_id") != entraClient {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"unauthorized_client","error_description":"AADSTS700016"}`)
			return
		}
		if form.Get("client_secret") != entraSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token_type":"Bearer","expires_in":3599,"ext_expires_in":3599,"access_token":"`+entraToken+`"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestClientCredentialsExchangeRedeemsTheSecretForAGraphToken(t *testing.T) {
	requests := 0
	srv := entraStandIn(t, &requests)
	cc := mdm.ClientCredentials{Authority: srv.URL, DirectoryTenantID: entraDirectory, ClientID: entraClient}
	token, err := mdm.ExchangeClientCredentials(context.Background(), srv.Client(), cc, []byte(entraSecret))
	if err != nil || string(token) != entraToken {
		t.Fatalf("exchange = %q %v; want the stand-in's bearer", token, err)
	}
	_, err = mdm.ExchangeClientCredentials(context.Background(), srv.Client(), cc, []byte("wrong secret"))
	if !errors.Is(err, mdm.ErrClientCredentialsRefused) || strings.Contains(err.Error(), "wrong secret") {
		t.Fatalf("wrong secret = %v; want a named refusal without the secret", err)
	}
	other := cc
	other.ClientID = "2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f"
	if _, err := mdm.ExchangeClientCredentials(context.Background(), srv.Client(), other, []byte(entraSecret)); !errors.Is(err, mdm.ErrClientNotAuthorized) {
		t.Fatalf("unauthorized app = %v; want the not-authorized refusal", err)
	}
	if requests != 3 {
		t.Fatalf("token endpoint saw %d requests; want 3", requests)
	}
}

func TestClientCredentialsRefuseUnsafeAuthoritiesAndMalformedIDs(t *testing.T) {
	for name, cc := range map[string]mdm.ClientCredentials{
		"plain http off loopback": {Authority: "http://login.example.test", DirectoryTenantID: entraDirectory, ClientID: entraClient},
		"authority with a path":   {Authority: "https://login.example.test/tenant", DirectoryTenantID: entraDirectory, ClientID: entraClient},
		"authority with userinfo": {Authority: "https://user@login.example.test", DirectoryTenantID: entraDirectory, ClientID: entraClient},
		"tenant path injection":   {DirectoryTenantID: "../common", ClientID: entraClient},
		"client not a GUID":       {DirectoryTenantID: entraDirectory, ClientID: "my-app"},
	} {
		if _, err := cc.TokenEndpoint(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cc := mdm.ClientCredentials{DirectoryTenantID: "contoso.onmicrosoft.com", ClientID: entraClient}
	endpoint, err := cc.TokenEndpoint()
	if err != nil || endpoint != "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token" {
		t.Fatalf("default authority endpoint = %q %v", endpoint, err)
	}
}

func TestClientCredentialsRefuseANonBearerOrEmptyToken(t *testing.T) {
	for name, body := range map[string]string{ // #nosec G101 -- malformed stand-in token responses, no credential value (CWE-798)
		"not bearer":     `{"token_type":"pop","access_token":"abc"}`,
		"empty token":    `{"token_type":"Bearer","access_token":""}`,
		"no token field": `{"token_type":"Bearer"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		cc := mdm.ClientCredentials{Authority: srv.URL, DirectoryTenantID: entraDirectory, ClientID: entraClient}
		if _, err := mdm.ExchangeClientCredentials(context.Background(), srv.Client(), cc, []byte(entraSecret)); !errors.Is(err, mdm.ErrTokenExchangeFailed) {
			t.Errorf("%s: err = %v; want the exchange refused", name, err)
		}
		srv.Close()
	}
}
