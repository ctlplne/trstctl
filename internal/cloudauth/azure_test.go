// SPDX-License-Identifier: MPL-2.0

package cloudauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExchangeAzureFederatedCredentialUsesExistingOIDCAssertion(t *testing.T) {
	const proof = "header.payload.signature+with/slash"
	before := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "invalid request envelope", http.StatusBadRequest)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		values, err := url.ParseQuery(string(raw))
		if err != nil ||
			values.Get("grant_type") != "client_credentials" ||
			values.Get("client_id") != "22222222-2222-4222-8222-222222222222" ||
			values.Get("scope") != "https://vault.azure.net/.default" ||
			values.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
			values.Get("client_assertion") != proof {
			http.Error(w, "invalid Entra federated-credential request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer","access_token":"azure-federated-token","expires_in":900}`))
	}))
	t.Cleanup(server.Close)

	material, err := ExchangeAzureFederatedCredential(t.Context(), server.Client(), AzureExchangeRequest{
		Endpoint:     server.URL,
		ClientID:     "22222222-2222-4222-8222-222222222222",
		Scope:        "https://vault.azure.net/.default",
		SubjectToken: []byte(proof),
	})
	if err != nil {
		t.Fatalf("ExchangeAzureFederatedCredential: %v", err)
	}
	defer wipeMaterial(&material)
	if material.Identifier != "azure" ||
		string(material.Primary) != "azure-federated-token" ||
		material.ExpiresAt.Before(before.Add(899*time.Second)) ||
		material.ExpiresAt.After(time.Now().UTC().Add(901*time.Second)) {
		t.Fatalf("Azure material = identifier=%q primary=%q expires=%s",
			material.Identifier, material.Primary, material.ExpiresAt)
	}
}

func TestExchangeAzureFederatedCredentialRedactsProviderBody(t *testing.T) {
	const proof = "azure-workload-proof"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "echo "+proof+" and azure-federated-token", http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	_, err := ExchangeAzureFederatedCredential(t.Context(), server.Client(), AzureExchangeRequest{
		Endpoint: server.URL, ClientID: "22222222-2222-4222-8222-222222222222",
		Scope: "https://vault.azure.net/.default", SubjectToken: []byte(proof),
	})
	if err == nil {
		t.Fatal("ExchangeAzureFederatedCredential unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), proof) || strings.Contains(err.Error(), "azure-federated-token") {
		t.Fatalf("provider body leaked through error: %v", err)
	}
}

func FuzzParseAzureTokenResponse(f *testing.F) {
	f.Add([]byte(`{"token_type":"Bearer","access_token":"token","expires_in":900}`))
	f.Add([]byte(`{"token_type":"","access_token":"","expires_in":0}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		material, _ := parseAzureTokenResponse(raw, time.Unix(1_700_000_000, 0).UTC())
		wipeMaterial(&material)
	})
}
