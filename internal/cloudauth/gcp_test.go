// SPDX-License-Identifier: MPL-2.0

package cloudauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExchangeGCPWorkloadIdentityUsesRFC8693ThenImpersonates(t *testing.T) {
	var stsCalls atomic.Int32
	var impersonationCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/token":
			stsCalls.Add(1)
			raw, _ := io.ReadAll(r.Body)
			values, err := url.ParseQuery(string(raw))
			if err != nil ||
				values.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
				values.Get("requested_token_type") != "urn:ietf:params:oauth:token-type:access_token" ||
				values.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:jwt" ||
				values.Get("audience") != "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider" ||
				values.Get("subject_token") != "signed-workload-proof" {
				http.Error(w, "invalid STS request", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gcp-sts-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900}`))
		case "/v1/projects/-/serviceAccounts/sync@example.iam.gserviceaccount.com:generateAccessToken":
			impersonationCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer gcp-sts-token" {
				http.Error(w, "missing STS bearer token", http.StatusUnauthorized)
				return
			}
			var body struct {
				Scope    []string `json:"scope"`
				Lifetime string   `json:"lifetime"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
				len(body.Scope) != 1 || body.Scope[0] != gcpCloudPlatformScope ||
				body.Lifetime != "900s" {
				http.Error(w, "invalid impersonation request", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accessToken":"gcp-impersonated-token","expireTime":"2032-05-06T07:08:09Z"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	material, err := ExchangeGCPWorkloadIdentity(t.Context(), server.Client(), GCPExchangeRequest{
		STSEndpoint:    server.URL + "/v1/token",
		Audience:       "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
		SubjectToken:   []byte("signed-workload-proof"),
		ServiceAccount: "sync@example.iam.gserviceaccount.com",
		ImpersonationEndpoint: server.URL +
			"/v1/projects/-/serviceAccounts/sync@example.iam.gserviceaccount.com:generateAccessToken",
	})
	if err != nil {
		t.Fatalf("ExchangeGCPWorkloadIdentity: %v", err)
	}
	defer wipeMaterial(&material)
	if stsCalls.Load() != 1 || impersonationCalls.Load() != 1 {
		t.Fatalf("exchange calls: sts=%d impersonation=%d", stsCalls.Load(), impersonationCalls.Load())
	}
	if material.Identifier != "gcp" || string(material.Primary) != "gcp-impersonated-token" ||
		!material.ExpiresAt.Equal(time.Date(2032, 5, 6, 7, 8, 9, 0, time.UTC)) {
		t.Fatalf("material = identifier=%q primary=%q expires=%s",
			material.Identifier, material.Primary, material.ExpiresAt)
	}
}

func TestExchangeGCPWorkloadIdentityCanReturnSTSBearerDirectly(t *testing.T) {
	before := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"direct-gcp-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900}`))
	}))
	t.Cleanup(server.Close)

	material, err := ExchangeGCPWorkloadIdentity(t.Context(), server.Client(), GCPExchangeRequest{
		STSEndpoint: server.URL, Audience: "gcp-provider-audience",
		SubjectToken: []byte("signed-workload-proof"),
	})
	if err != nil {
		t.Fatalf("ExchangeGCPWorkloadIdentity: %v", err)
	}
	defer wipeMaterial(&material)
	if string(material.Primary) != "direct-gcp-token" ||
		material.ExpiresAt.Before(before.Add(899*time.Second)) ||
		material.ExpiresAt.After(time.Now().UTC().Add(901*time.Second)) {
		t.Fatalf("direct STS material = primary=%q expires=%s", material.Primary, material.ExpiresAt)
	}
}

func TestExchangeGCPWorkloadIdentityRedactsProviderBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "echo signed-workload-proof and gcp-sts-token", http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	_, err := ExchangeGCPWorkloadIdentity(t.Context(), server.Client(), GCPExchangeRequest{
		STSEndpoint: server.URL, Audience: "gcp-provider-audience",
		SubjectToken: []byte("signed-workload-proof"),
	})
	if err == nil {
		t.Fatal("ExchangeGCPWorkloadIdentity unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "signed-workload-proof") || strings.Contains(err.Error(), "gcp-sts-token") {
		t.Fatalf("provider body leaked through error: %v", err)
	}
}

func FuzzParseGCPSTSResponse(f *testing.F) {
	f.Add([]byte(`{"access_token":"token","token_type":"Bearer","expires_in":900}`))
	f.Add([]byte(`{"access_token":"","expires_in":0}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		material, _ := parseGCPSTSResponse(raw, time.Unix(1_700_000_000, 0).UTC())
		wipeMaterial(&material)
	})
}

func wipeMaterial(material *Material) {
	if material == nil {
		return
	}
	for i := range material.Primary {
		material.Primary[i] = 0
	}
	for i := range material.Secondary {
		material.Secondary[i] = 0
	}
}
