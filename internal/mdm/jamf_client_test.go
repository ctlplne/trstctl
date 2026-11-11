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
	jamfClient = "00000000-0000-4000-8000-00000000a15c"
	jamfSecret = "jamf api client secret & more=+/" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	jamfToken  = "stand-in-jamf-access-token"       // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
)

// jamfStandIn is a Jamf Pro token endpoint built from Jamf's documented API
// client grant: a form POST to /api/oauth/token with grant_type
// client_credentials, client_id and client_secret; a JSON bearer grant back
// (access_token, scope, token_type, expires_in), or 401 invalid_client for a
// wrong or disabled client.
func jamfStandIn(t *testing.T, requests *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		body, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(body))
		if r.Method != http.MethodPost || r.URL.Path != "/api/oauth/token" || err != nil ||
			r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || form.Get("grant_type") != "client_credentials" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
			return
		}
		if form.Get("client_id") != jamfClient || form.Get("client_secret") != jamfSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"`+jamfToken+`","scope":"api-role:2","token_type":"Bearer","expires_in":299}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A156-L1: a Jamf schedule's API client secret is exchanged at the same Jamf
// Pro server for an access token; a wrong secret is told apart from a broken
// exchange, and no error carries the secret or the token.
func TestJamfAPIClientExchangeRedeemsTheSecretForAnAccessTokenA156L1(t *testing.T) {
	requests := 0
	srv := jamfStandIn(t, &requests)
	client := mdm.JamfAPIClient{ClientID: " " + jamfClient + " "}
	token, err := mdm.ExchangeJamfClientCredentials(context.Background(), srv.Client(), srv.URL+"/", client, []byte(jamfSecret))
	if err != nil || string(token) != jamfToken {
		t.Fatalf("exchange = %q, %v; want the stand-in's access token", token, err)
	}
	_, err = mdm.ExchangeJamfClientCredentials(context.Background(), srv.Client(), srv.URL, client, []byte("not the secret"))
	if !errors.Is(err, mdm.ErrJamfClientRefused) {
		t.Fatalf("a wrong secret = %v, want ErrJamfClientRefused", err)
	}
	if strings.Contains(err.Error(), "not the secret") || strings.Contains(err.Error(), jamfSecret) {
		t.Fatalf("the refusal carries the secret: %v", err)
	}
	if requests != 2 {
		t.Fatalf("token requests = %d, want 2", requests)
	}
	if endpoint, err := mdm.JamfTokenEndpoint("https://jamf.example.test:8443/"); err != nil || endpoint != "https://jamf.example.test:8443/api/oauth/token" {
		t.Fatalf("token endpoint = %q, %v", endpoint, err)
	}
}

// The client secret crosses the network, so a non-loopback base must be
// https and carry no credentials, and the client ID must be a GUID; none of
// these reaches the network.
func TestJamfAPIClientRefusesUnsafeBasesAndMalformedIDsA156L1(t *testing.T) {
	requests := 0
	srv := jamfStandIn(t, &requests)
	for name, tc := range map[string]struct {
		base   string
		client string
	}{
		"plain http":     {"http://jamf.example.test", jamfClient},
		"other scheme":   {"ftp://jamf.example.test", jamfClient},
		"userinfo":       {"https://admin:pw@jamf.example.test", jamfClient},
		"relative":       {"/api", jamfClient},
		"malformed id":   {srv.URL, "not-a-guid"},
		"empty id":       {srv.URL, ""},
		"injected id":    {srv.URL, jamfClient + "&grant_type=password"},
		"path injection": {srv.URL, "../" + jamfClient},
	} {
		if _, err := mdm.ExchangeJamfClientCredentials(context.Background(), srv.Client(), tc.base, mdm.JamfAPIClient{ClientID: tc.client}, []byte(jamfSecret)); err == nil {
			t.Errorf("%s: the exchange was allowed", name)
		}
	}
	if requests != 0 {
		t.Fatalf("a refused exchange reached the token endpoint %d times", requests)
	}
}

// A response that is not a bearer grant is a failed exchange, not a token.
func TestJamfAPIClientRefusesANonBearerOrEmptyTokenA156L1(t *testing.T) {
	for name, body := range map[string]string{
		"no token":    `{"token_type":"Bearer","expires_in":299}`, // #nosec G101 -- a stand-in response with no token in it (CWE-798)
		"not bearer":  `{"access_token":"x","token_type":"MAC","expires_in":299}`,
		"not json":    `<html>login</html>`,
		"other error": `{"error":"unsupported_grant_type"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if name == "other error" {
				w.WriteHeader(http.StatusBadRequest)
			}
			_, _ = io.WriteString(w, body)
		}))
		_, err := mdm.ExchangeJamfClientCredentials(context.Background(), srv.Client(), srv.URL, mdm.JamfAPIClient{ClientID: jamfClient}, []byte(jamfSecret))
		srv.Close()
		if !errors.Is(err, mdm.ErrTokenExchangeFailed) {
			t.Errorf("%s: %v, want ErrTokenExchangeFailed", name, err)
		}
	}
}
