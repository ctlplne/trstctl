// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestControlPlaneHTTPTrustRequiresAgentServerRole(t *testing.T) {
	agentCA, err := NewCA("trstctl Agent CA")
	if err != nil {
		t.Fatal(err)
	}
	apiCA, err := NewCA("operator API CA")
	if err != nil {
		t.Fatal(err)
	}
	roots := append(apiCA.BundlePEM(), agentCA.BundlePEM()...)
	apiCert, err := apiCA.IssueServerCertificate([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	controlCert, err := agentCA.IssueAgentControlPlaneServerCertificate([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gatewayCert, err := agentCA.IssueServerCertificate([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []struct {
		name string
		new  func() (*http.Transport, error)
	}{
		{"enrollment", func() (*http.Transport, error) { return ControlPlaneHTTPTransport(roots) }},
		{"agent HTTP", func() (*http.Transport, error) { return AgentHTTPTransport(nil, roots, "", nil) }},
	} {
		for _, server := range []struct {
			name   string
			cert   tls.Certificate
			accept bool
		}{
			{"operator API", apiCert, true},
			{"agent control plane", controlCert, true},
			{"agent gateway", gatewayCert, false},
		} {
			t.Run(client.name+"/"+server.name, func(t *testing.T) {
				listener := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))
				listener.TLS = &tls.Config{Certificates: []tls.Certificate{server.cert}, MinVersion: tls.VersionTLS13}
				listener.StartTLS()
				t.Cleanup(listener.Close)
				transport, err := client.new()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(transport.CloseIdleConnections)
				url := strings.Replace(listener.URL, "127.0.0.1", "localhost", 1)
				response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get(url)
				if server.accept {
					if err != nil {
						t.Fatal(err)
					}
					_ = response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						t.Fatalf("HTTP status = %d", response.StatusCode)
					}
				} else if err == nil {
					_ = response.Body.Close()
					t.Fatal("agent gateway certificate satisfied control-plane HTTP trust")
				}
			})
		}
	}
}
