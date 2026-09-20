// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/netsec"
)

func TestSupportBundleCommandDoesNotRequireHealthyConfigOrHTTP(t *testing.T) {
	output := filepath.Join(t.TempDir(), "support.tar.gz")
	getenv := func(key string) string {
		if key == "TRSTCTL_POSTGRES_MODE" {
			return "external"
		}
		return ""
	}
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"support-bundle", "--output", output}, getenv, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("support archive missing: %v", err)
	}
	if !strings.Contains(stdout.String(), "wrote redacted support bundle") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestSupportBundleCommandOptInFetchesAuthorizedDiagnosticAddendum(t *testing.T) {
	var authorized bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized = r.URL.Path == "/api/v1/enrollment/diagnostics/support-addendum" &&
			r.Header.Get("Authorization") == "Bearer support-token"
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":1,"rows":[{"protocol":"scep","cause":"client_cert_rejected","actionable":true,"count":1}],"unknown_count":0}`))
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "support-with-diagnostics.tar.gz")
	getenv := func(key string) string {
		switch key {
		case "TRSTCTL_URL":
			return server.URL
		case "TRSTCTL_TOKEN":
			return "support-token"
		default:
			return ""
		}
	}
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{
		"support-bundle", "--output", output, "--include-enrollment-diagnostics",
	}, getenv, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !authorized {
		t.Fatal("diagnostic addendum was not fetched through the authenticated endpoint")
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("support archive missing: %v", err)
	}
}

func TestSupportBundleDiagnosticFetchDoesNotEchoTokenOrUpstreamBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("submitted credentials: upstream-secret"))
	}))
	defer server.Close()
	getenv := func(key string) string {
		if key == "TRSTCTL_URL" {
			return server.URL
		}
		if key == "TRSTCTL_TOKEN" {
			return "support-token-secret"
		}
		return ""
	}
	_, err := fetchEnrollmentDiagnosticsAddendum(context.Background(), getenv)
	if err == nil {
		t.Fatal("upstream failure unexpectedly succeeded")
	}
	for _, secret := range []string{"support-token-secret", "upstream-secret", "submitted credentials"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("fetch error leaked %q: %v", secret, err)
		}
	}
}

func TestSupportBundleDiagnosticFetchRefusesPlaintextRemoteBearerTransport(t *testing.T) {
	getenv := func(key string) string {
		if key == "TRSTCTL_URL" {
			return "http://diagnostics.example.test"
		}
		if key == "TRSTCTL_TOKEN" {
			return "must-not-leave-over-plaintext"
		}
		return ""
	}
	_, err := fetchEnrollmentDiagnosticsAddendum(context.Background(), getenv)
	if err == nil || !strings.Contains(err.Error(), "requires HTTPS") || strings.Contains(err.Error(), "must-not-leave") {
		t.Fatalf("plaintext remote origin refusal = %v", err)
	}
}

func TestSupportBundleDiagnosticFetchRefusesRedirect(t *testing.T) {
	var redirected bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	getenv := func(key string) string {
		switch key {
		case "TRSTCTL_URL":
			return origin.URL
		case "TRSTCTL_TOKEN":
			return "redirect-secret"
		default:
			return ""
		}
	}
	_, err := fetchEnrollmentDiagnosticsAddendum(context.Background(), getenv)
	if err == nil || redirected || strings.Contains(err.Error(), "redirect-secret") {
		t.Fatalf("redirect refusal = err %v redirected=%t", err, redirected)
	}
}

func TestSupportBundleDiagnosticClientHardBlocksMetadata(t *testing.T) {
	endpoint, err := url.Parse("https://169.254.169.254/latest/meta-data/")
	if err != nil {
		t.Fatal(err)
	}
	client, err := supportBundleDiagnosticClient(context.Background(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(request)
	if !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("metadata request error = %v, want SSRF refusal", err)
	}
}
