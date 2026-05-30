package azurekv_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"certctl.io/certctl/internal/connector/azurekv"
)

// ClientCredentials acquires an Entra ID token via the OAuth2 client-credentials
// grant and caches it, so repeated deploys do not re-hit the token endpoint.
func TestClientCredentialsAcquiresAndCaches(t *testing.T) {
	var hits int32
	var gotGrant, gotClient, gotSecret, gotScope string
	aad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = r.ParseForm()
		gotGrant = r.PostForm.Get("grant_type")
		gotClient = r.PostForm.Get("client_id")
		gotSecret = r.PostForm.Get("client_secret")
		gotScope = r.PostForm.Get("scope")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"abc.def.ghi","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer aad.Close()

	p := azurekv.NewClientCredentials(aad.URL, "client-123", "s3cr3t", azurekv.WithHTTPClient(aad.Client()))

	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "abc.def.ghi" {
		t.Errorf("token = %q, want abc.def.ghi", tok)
	}
	if gotGrant != "client_credentials" || gotClient != "client-123" || gotSecret != "s3cr3t" {
		t.Errorf("form = grant=%q client=%q secret=%q", gotGrant, gotClient, gotSecret)
	}
	if gotScope != "https://vault.azure.net/.default" {
		t.Errorf("scope = %q, want the Key Vault default scope", gotScope)
	}

	// Second call is served from cache: the token endpoint is not hit again.
	if _, err := p.Token(context.Background()); err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("token endpoint hit %d times, want 1 (cached)", got)
	}
}

// A non-200 from the token endpoint is surfaced as an error, not a silent empty
// token.
func TestClientCredentialsTokenEndpointError(t *testing.T) {
	aad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer aad.Close()

	p := azurekv.NewClientCredentials(aad.URL, "client", "bad", azurekv.WithHTTPClient(aad.Client()))
	if _, err := p.Token(context.Background()); err == nil {
		t.Fatal("expected an error from a 401 token endpoint, got nil")
	}
}
