package acme_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// TestHTTP01Validator validates the real http-01 check against a server serving
// the key authorization, and rejects a wrong one.
func TestHTTP01Validator(t *testing.T) {
	const token = "tok-123"
	const keyAuth = "tok-123.thumbprint"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/acme-challenge/"+token {
			_, _ = w.Write([]byte(keyAuth))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)
	domain := strings.TrimPrefix(ts.URL, "http://") // host:port the validator will dial

	// This test deliberately dials a loopback httptest server, so it opts the
	// default client out of the SSRF guard (SEC-006); production keeps the guard on.
	v := acmesrv.HTTP01Validator{AllowPrivateTargets: true}
	if err := v.Validate(context.Background(), acmesrv.ChallengeHTTP01, domain, token, keyAuth); err != nil {
		t.Errorf("valid http-01 rejected: %v", err)
	}
	if err := v.Validate(context.Background(), acmesrv.ChallengeHTTP01, domain, token, "wrong-key-auth"); err == nil {
		t.Error("http-01 accepted a mismatched key authorization")
	}
}
