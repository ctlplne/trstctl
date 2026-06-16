package gcpcm_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/connector/gcpcm"
)

// MetadataToken fetches a token from the GCE/GKE metadata server (the canonical
// crypto-free GCP credential path) with the required Metadata-Flavor header, and
// caches it so repeated deploys don't re-hit the server.
func TestMetadataTokenAcquiresAndCaches(t *testing.T) {
	var hits int32
	var gotPath, gotFlavor string
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotPath = r.URL.Path
		gotFlavor = r.Header.Get("Metadata-Flavor")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"meta-tok","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer md.Close()

	p := gcpcm.NewMetadataToken(gcpcm.WithMetadataBase(md.URL), gcpcm.WithMetadataClient(md.Client()))

	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "meta-tok" {
		t.Errorf("token = %q, want meta-tok", tok)
	}
	if gotPath != "/computeMetadata/v1/instance/service-accounts/default/token" {
		t.Errorf("metadata path = %q", gotPath)
	}
	if gotFlavor != "Google" {
		t.Errorf("Metadata-Flavor = %q, want Google (required by the metadata server)", gotFlavor)
	}

	if _, err := p.Token(context.Background()); err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("metadata server hit %d times, want 1 (cached)", got)
	}
}

// A metadata-server failure surfaces as an error, not a silent empty token.
func TestMetadataTokenServerError(t *testing.T) {
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer md.Close()

	p := gcpcm.NewMetadataToken(gcpcm.WithMetadataBase(md.URL), gcpcm.WithMetadataClient(md.Client()))
	if _, err := p.Token(context.Background()); err == nil {
		t.Fatal("expected an error from a 500 metadata server, got nil")
	}
}
