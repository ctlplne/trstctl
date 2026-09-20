// SPDX-License-Identifier: BUSL-1.1

package terraformprovider

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// This exercises the real provider configuration and TLS handshake. The HTTP
// handler is a unit fixture; it is not evidence of a served product journey.
func TestProviderCAFileTLSVerification(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/api/v1/profiles/web/versions/1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = fmt.Fprint(w, `{"name":"web","version":1}`)
	}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "unrelated.example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRSTCTL_TOKEN", "")
	t.Setenv("TRSTCTL_TENANT", "")
	for _, tc := range []struct {
		name, endpoint, envCA string
		explicitCA            *string
		wantError             string
	}{
		{name: "default roots reject private CA", endpoint: srv.URL, wantError: "unknown authority"},
		{name: "environment bundle trusts private CA", endpoint: srv.URL, envCA: caFile},
		{name: "explicit bundle overrides environment", endpoint: srv.URL, envCA: "absent.pem", explicitCA: &caFile},
		{name: "unrelated CA rejected", endpoint: srv.URL, envCA: unrelated.ControlPlane.PeerCAFile, wantError: "unknown authority"},
		{name: "wrong hostname rejected", endpoint: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), envCA: caFile, wantError: "not localhost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TRSTCTL_CA_FILE", tc.envCA)
			config := map[string]string{"endpoint": tc.endpoint}
			if tc.explicitCA != nil {
				config["ca_file"] = *tc.explicitCA
			}
			resp := configureTLSProvider(t, &Provider{}, config)
			if resp.Diagnostics.HasError() {
				t.Fatalf("configure: %v", resp.Diagnostics)
			}
			client := resp.ResourceData.(*Client)
			t.Cleanup(client.http.CloseIdleConnections)
			before := requests.Load()
			profile, err := client.GetProfileVersion(t.Context(), "web", 1)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("request error = %v, want %q", err, tc.wantError)
				}
				if requests.Load() != before {
					t.Fatal("untrusted request reached the HTTP handler")
				}
				return
			}
			if err != nil || profile.Name != "web" || profile.Version != 1 || requests.Load() != before+1 {
				t.Fatalf("trusted request: profile=%+v err=%v", profile, err)
			}
		})
	}
}

func TestProviderCAFileRejectsInvalidConfiguration(t *testing.T) {
	invalid := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, endpoint, caFile, want string
		httpClient                   *http.Client
	}{
		{name: "missing file", endpoint: "https://example.test", caFile: filepath.Join(t.TempDir(), "absent.pem"), want: "CA file"},
		{name: "invalid PEM", endpoint: "https://example.test", caFile: invalid, want: "no CA certificates"},
		{name: "cleartext endpoint", endpoint: "http://example.test", caFile: invalid, want: "HTTPS"},
		{name: "injected transport", endpoint: "https://example.test", caFile: invalid, httpClient: &http.Client{}, want: "HTTPClient"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TRSTCTL_CA_FILE", tc.caFile)
			resp := configureTLSProvider(t, &Provider{httpClient: tc.httpClient}, map[string]string{"endpoint": tc.endpoint})
			if !resp.Diagnostics.HasError() || !strings.Contains(fmt.Sprint(resp.Diagnostics), tc.want) || resp.ResourceData != nil {
				t.Fatalf("configure = %v, want error containing %q and no client", resp.Diagnostics, tc.want)
			}
		})
	}
}

func TestProviderCAFileRejectsCleartextRedirect(t *testing.T) {
	var cleartextRequests atomic.Int32
	cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleartextRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(cleartext.Close)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cleartext.URL+"/api/v1/profiles/web/versions/1", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := configureTLSProvider(t, &Provider{}, map[string]string{
		"endpoint": srv.URL, "ca_file": caFile, "token": "fixture-token",
	})
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	client := resp.ResourceData.(*Client)
	t.Cleanup(client.http.CloseIdleConnections)
	if _, err := client.GetProfileVersion(t.Context(), "web", 1); err == nil || !strings.Contains(err.Error(), "HTTPS redirects") {
		t.Fatalf("cleartext redirect = %v", err)
	}
	if cleartextRequests.Load() != 0 {
		t.Fatal("redirect sent the request to the cleartext server")
	}
}

func TestProviderCAFilePreservesEnvironmentProxy(t *testing.T) {
	const proxyURL = "http://127.0.0.1:39123"
	if os.Getenv("TRSTCTL_PROVIDER_PROXY_CHILD") == "1" {
		client, err := NewClient(ClientConfig{Endpoint: "https://control-plane.invalid", CAFile: os.Getenv("TRSTCTL_TEST_CA_FILE")})
		if err != nil {
			t.Fatal(err)
		}
		transport := client.http.Transport.(*http.Transport)
		if transport.Proxy == nil {
			t.Fatal("CA file discarded environment proxy routing")
		}
		req, err := http.NewRequest(http.MethodGet, "https://control-plane.invalid", nil)
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := transport.Proxy(req)
		if err != nil || proxy == nil || proxy.String() != proxyURL {
			t.Fatalf("proxy selection = %v, %v; want %s", proxy, err, proxyURL)
		}
		return // Selection only: never dial the .invalid host or the proxy.
	}
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "fixture.example.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Go caches proxy environment variables. A fresh copy of this exact test
	// process checks the configured route without changing another test's cache.
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestProviderCAFilePreservesEnvironmentProxy$", "-test.count=1") // #nosec G204 -- fixed arguments to this test's own executable (CWE-78)
	cmd.Env = append(os.Environ(), "TRSTCTL_PROVIDER_PROXY_CHILD=1", "TRSTCTL_TEST_CA_FILE="+material.ControlPlane.PeerCAFile,
		"HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL, "NO_PROXY=", "no_proxy=")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh-process proxy selection: %v\n%s", err, output)
	}
}

func configureTLSProvider(t *testing.T, p *Provider, values map[string]string) provider.ConfigureResponse {
	t.Helper()
	var schema provider.SchemaResponse
	p.Schema(t.Context(), provider.SchemaRequest{}, &schema)
	attrs := map[string]tftypes.Value{}
	for name := range schema.Schema.Attributes {
		attrs[name] = tftypes.NewValue(tftypes.String, nil)
	}
	for name, value := range values {
		if _, ok := attrs[name]; !ok {
			t.Fatalf("provider schema does not expose %q", name)
		}
		attrs[name] = tftypes.NewValue(tftypes.String, value)
	}
	var resp provider.ConfigureResponse
	p.Configure(t.Context(), provider.ConfigureRequest{Config: tfsdk.Config{
		Schema: schema.Schema,
		Raw:    tftypes.NewValue(schema.Schema.Type().TerraformType(t.Context()), attrs),
	}}, &resp)
	return resp
}
