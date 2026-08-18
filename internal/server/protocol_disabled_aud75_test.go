// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestDisabledProtocolNamespacesFailClosedAUD75 drives the assembled control-plane
// mux with every HTTP-served protocol disabled. A disabled machine protocol is not
// a browser route: returning index.html with HTTP 200 makes both stock clients and
// the console's responder register believe a responder exists.
func TestDisabledProtocolNamespacesFailClosedAUD75(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})

	tests := []struct {
		name        string
		protocol    string
		method      string
		path        string
		contentType string
		body        []byte
	}{
		{name: "acme directory", protocol: "acme", method: http.MethodGet, path: "/directory"},
		{name: "acme directory unknown child", protocol: "acme", method: http.MethodGet, path: "/directory/not-a-route"},
		{name: "acme wrong method", protocol: "acme", method: http.MethodDelete, path: "/acme/new-order"},
		{name: "est exact route", protocol: "est", method: http.MethodGet, path: "/.well-known/est/cacerts"},
		{name: "est unknown child", protocol: "est", method: http.MethodPost, path: "/.well-known/est/not-a-route"},
		{name: "scep exact route", protocol: "scep", method: http.MethodGet, path: "/scep?operation=GetCACaps"},
		{name: "scep unknown child", protocol: "scep", method: http.MethodPost, path: "/scep/not-a-route"},
		{name: "cmp exact route", protocol: "cmp", method: http.MethodPost, path: "/cmp", contentType: "application/pkixcmp", body: []byte{0x30, 0x00}},
		{name: "cmp unknown child", protocol: "cmp", method: http.MethodGet, path: "/cmp/not-a-route"},
		{name: "ssh exact route", protocol: "ssh", method: http.MethodGet, path: "/ssh/ca"},
		{name: "ssh wrong method", protocol: "ssh", method: http.MethodDelete, path: "/ssh/issue/user"},
		{name: "tsa exact route", protocol: "tsa", method: http.MethodPost, path: "/tsa", contentType: "application/timestamp-query", body: []byte{0x30, 0x00}},
		{name: "tsa unknown child", protocol: "tsa", method: http.MethodGet, path: "/tsa/not-a-route"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, h.ts.URL+tt.path, bytes.NewReader(tt.body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			resp, err := h.ts.Client().Do(req)
			if err != nil {
				t.Fatalf("request disabled %s namespace: %v", tt.protocol, err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("close disabled %s response: %v", tt.protocol, err)
				}
			}()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}

			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status=%d body=%q, want stable 404 refusal", resp.StatusCode, body)
			}
			if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/problem+json") {
				t.Fatalf("Content-Type=%q body=%q, want application/problem+json", contentType, body)
			}
			if bytes.Contains(bytes.ToLower(body), []byte("<html")) || bytes.Contains(body, []byte(`id="root"`)) {
				t.Fatalf("disabled machine route leaked the console shell: %q", body)
			}

			var problem struct {
				Type     string `json:"type"`
				Title    string `json:"title"`
				Status   int    `json:"status"`
				Protocol string `json:"protocol"`
			}
			if err := json.Unmarshal(body, &problem); err != nil {
				t.Fatalf("decode problem response: %v body=%q", err, body)
			}
			if problem.Type != "urn:trstctl:problem:protocol-not-served" || problem.Title != "Protocol is not served" || problem.Status != http.StatusNotFound || problem.Protocol != tt.protocol {
				t.Fatalf("problem=%+v, want stable %s protocol refusal", problem, tt.protocol)
			}
		})
	}
}

// TestSSHConsoleDeepLinkDoesNotCollideWithMachineNamespaceAUD75 protects the
// one intentional name overlap between the browser console and a machine
// protocol. The console owns exact /ssh; the SSH CA owns children such as
// /ssh/ca and /ssh/krl. Without an explicit exact handler, net/http helpfully
// redirects /ssh to /ssh/, where the protocol namespace correctly returns a
// problem document. That makes the UI look healthy when clicked inside the SPA
// but turns a bookmark or browser refresh into raw JSON.
func TestSSHConsoleDeepLinkDoesNotCollideWithMachineNamespaceAUD75(t *testing.T) {
	for _, tt := range []struct {
		name      string
		protocols config.Protocols
	}{
		{name: "machine protocol disabled", protocols: config.Protocols{}},
		{name: "machine protocol enabled", protocols: config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newServedHarness(t, tt.protocols)
			resp, err := h.ts.Client().Get(h.ts.URL + "/ssh")
			if err != nil {
				t.Fatalf("GET console deep link /ssh: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("close console deep-link response: %v", err)
				}
			}()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read console deep-link response: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d body=%q, want console index", resp.StatusCode, body)
			}
			if resp.Request.URL.Path != "/ssh" {
				t.Fatalf("final path=%q, want exact /ssh without ServeMux slash redirect", resp.Request.URL.Path)
			}
			if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
				t.Fatalf("Content-Type=%q body=%q, want console HTML", contentType, body)
			}
			if !bytes.Contains(body, []byte(`id="root"`)) {
				t.Fatalf("exact /ssh did not serve the embedded console index")
			}
		})
	}
}

// TestEnabledProtocolRoutesSurviveNamespaceReservationAUD75 proves the fail-closed
// reservation is not a blanket block. The exact public discovery/probe route for
// every HTTP protocol still reaches its real enabled handler, while reservation-only
// children fail as machine routes instead of becoming console routes.
func TestEnabledProtocolRoutesSurviveNamespaceReservationAUD75(t *testing.T) {
	dir := t.TempDir()
	enabled := config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}
	h := newServedHarness(t, config.Protocols{
		ACME: enabled, EST: enabled, SCEP: enabled, CMP: enabled, SSH: enabled, TSA: enabled,
		TSACertFile: filepath.Join(dir, "tsa.crt"),
	})

	exact := []struct {
		protocol    string
		path        string
		wantStatus  int
		contentType string
		body        string
	}{
		{protocol: "acme", path: "/directory", wantStatus: http.StatusOK, contentType: "application/json", body: `"newOrder"`},
		{protocol: "est", path: "/.well-known/est/cacerts", wantStatus: http.StatusOK, contentType: "application/pkcs7-mime"},
		{protocol: "scep", path: "/scep?operation=GetCACaps", wantStatus: http.StatusOK, contentType: "text/plain", body: "SCEPStandard"},
		{protocol: "cmp", path: "/cmp", wantStatus: http.StatusMethodNotAllowed, contentType: "text/plain", body: "cmp: POST required (RFC 6712)"},
		{protocol: "ssh", path: "/ssh/ca", wantStatus: http.StatusOK, contentType: "text/plain", body: "ecdsa-sha2-nistp256"},
		{protocol: "tsa", path: "/tsa", wantStatus: http.StatusMethodNotAllowed, contentType: "text/plain", body: "method not allowed"},
	}
	for _, tt := range exact {
		t.Run(tt.protocol+" exact", func(t *testing.T) {
			resp, err := h.ts.Client().Get(h.ts.URL + tt.path)
			if err != nil {
				t.Fatalf("GET enabled %s route: %v", tt.protocol, err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("close enabled %s response: %v", tt.protocol, err)
				}
			}()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read enabled %s response: %v", tt.protocol, err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status=%d body=%q, want %d", resp.StatusCode, body, tt.wantStatus)
			}
			if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, tt.contentType) {
				t.Fatalf("Content-Type=%q, want %q prefix", got, tt.contentType)
			}
			if tt.body != "" && !bytes.Contains(body, []byte(tt.body)) {
				t.Fatalf("body=%q, want marker %q", body, tt.body)
			}
			if bytes.Contains(body, []byte(`id="root"`)) {
				t.Fatalf("enabled %s route leaked the console shell", tt.protocol)
			}
		})
	}

	for _, tt := range []struct {
		protocol string
		path     string
	}{
		{protocol: "acme", path: "/directory/not-a-route"},
		{protocol: "cmp", path: "/cmp/not-a-route"},
		{protocol: "tsa", path: "/tsa/not-a-route"},
	} {
		t.Run(tt.protocol+" reserved child", func(t *testing.T) {
			resp, err := h.ts.Client().Get(h.ts.URL + tt.path)
			if err != nil {
				t.Fatalf("GET enabled %s unknown child: %v", tt.protocol, err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("close enabled %s child response: %v", tt.protocol, err)
				}
			}()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read enabled %s unknown child: %v", tt.protocol, err)
			}
			if resp.StatusCode != http.StatusNotFound || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") {
				t.Fatalf("status=%d Content-Type=%q body=%q, want protocol problem", resp.StatusCode, resp.Header.Get("Content-Type"), body)
			}
			if !bytes.Contains(body, []byte(`"type":"urn:trstctl:problem:protocol-route-not-found"`)) || !bytes.Contains(body, []byte(`"protocol":"`+tt.protocol+`"`)) {
				t.Fatalf("unknown child body=%q, want %s route-not-found problem", body, tt.protocol)
			}
		})
	}
}
