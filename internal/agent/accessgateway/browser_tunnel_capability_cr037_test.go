// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCR037TunnelCapabilityIsRequiredBeforeAnyHTTPRelay(t *testing.T) {
	ticket := "local-ticket-fixture"
	capability := localTunnelCapability(ticket)
	if capability == TicketDigest(ticket) || capability == localTunnelCapability("other-ticket") {
		t.Fatal("local capability is not separated from the stored ticket digest and other sessions")
	}
	for _, tc := range []struct {
		name, header, value string
		kind                tunnelClientKind
		wantAllowed         bool
	}{
		{"AWS without capability", "User-Agent", "aws-cli/2.0", tunnelAWS, false},
		{"AWS stored digest", "X-Amz-Security-Token", TicketDigest(ticket), tunnelAWS, false},
		{"AWS local capability", "X-Amz-Security-Token", capability, tunnelAWS, true},
		{"curl without capability", "User-Agent", "curl/8.0", tunnelHTTPHeader, false},
		{"curl local capability", "X-Trstctl-Tunnel-Token", capability, tunnelHTTPHeader, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080/resource", nil)
			req.Header.Set(tc.header, tc.value)
			w := httptest.NewRecorder()
			refused := refuseUntrustedTunnelRequest(w, req, capability, tc.kind)
			if refused == tc.wantAllowed {
				t.Fatalf("refused=%v status=%d, want allowed=%v", refused, w.Code, tc.wantAllowed)
			}
			if tc.wantAllowed && (req.Header.Get("X-Amz-Security-Token") == capability || req.Header.Get("X-Trstctl-Tunnel-Token") == capability || req.Header.Get("Authorization") == "Bearer "+capability) {
				t.Fatal("local capability remained on the upstream request")
			}
		})
	}
	for _, tc := range []struct {
		name, path, wantPath string
		allowed              bool
	}{
		{"Kubernetes without capability", "/api/v1/pods", "", false},
		{"Kubernetes stored digest", tunnelKubernetesPrefix + TicketDigest(ticket) + "/api/v1/pods", "", false},
		{"Kubernetes local capability", tunnelKubernetesPrefix + capability + "/api/v1/pods", "/api/v1/pods", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080"+tc.path, nil)
			refused := refuseUntrustedTunnelRequest(httptest.NewRecorder(), req, capability, tunnelKubernetes)
			if refused == tc.allowed || tc.allowed && req.URL.Path != tc.wantPath {
				t.Fatalf("refused=%v forwarded path=%q, want allowed=%v path=%q", refused, req.URL.Path, tc.allowed, tc.wantPath)
			}
		})
	}
}

func TestCR037BrowserBootstrapAndCookieAreBoundToTheLocalOrigin(t *testing.T) {
	capability := localTunnelCapability("browser-ticket-fixture")
	bootstrap := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080/?trstctl_tunnel="+capability, nil)
	bootstrap.Header.Set("Sec-Fetch-Site", "none")
	w := httptest.NewRecorder()
	if !refuseUntrustedTunnelRequest(w, bootstrap, capability, tunnelBrowser) || w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("bootstrap = %d Location %q", w.Code, w.Header().Get("Location"))
	}
	response := w.Result()
	defer func() { _ = response.Body.Close() }()
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Value != capability {
		t.Fatalf("bootstrap cookie = %v", cookies)
	}
	local := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18080/action", nil)
	local.Header.Set("Origin", "http://127.0.0.1:18080")
	local.Header.Set("Sec-Fetch-Site", "same-origin")
	local.AddCookie(cookies[0])
	if refuseUntrustedTunnelRequest(httptest.NewRecorder(), local, capability, tunnelBrowser) {
		t.Fatal("same-origin browser with its cookie was refused")
	}
	foreign := local.Clone(local.Context())
	foreign.Header = local.Header.Clone()
	foreign.Header.Set("Origin", "https://attacker.example")
	if !refuseUntrustedTunnelRequest(httptest.NewRecorder(), foreign, capability, tunnelBrowser) {
		t.Fatal("foreign Origin with a cookie was admitted")
	}
	duplicate := local.Clone(local.Context())
	duplicate.Header = local.Header.Clone()
	duplicate.AddCookie(cookies[0])
	if !refuseUntrustedTunnelRequest(httptest.NewRecorder(), duplicate, capability, tunnelBrowser) {
		t.Fatal("ambiguous duplicate capability cookies were admitted")
	}
	queryLeak := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080/resource?trstctl_tunnel="+capability, nil)
	queryLeak.AddCookie(cookies[0])
	if !refuseUntrustedTunnelRequest(httptest.NewRecorder(), queryLeak, capability, tunnelBrowser) {
		t.Fatal("a capability in an upstream URL query was admitted")
	}
}
