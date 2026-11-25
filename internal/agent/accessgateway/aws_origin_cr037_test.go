// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCR037AWSRelayRefusesBrowserOriginsAndReboundHosts(t *testing.T) {
	capability := localTunnelCapability("cr037-local-ticket")
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		_, _ = io.WriteString(w, "<CreateUserResponse/>")
	}))
	defer upstream.Close()

	for _, tc := range []struct {
		name, method, url, origin, fetchSite, userAgent, localToken string
		wantForward                                                 bool
	}{
		{"cross-site form", http.MethodPost, "http://127.0.0.1:18080/", "https://attacker.example", "cross-site", "Mozilla/5.0", "", false},
		{"rebound host", http.MethodPost, "http://rebound.attacker.example:18080/", "", "same-origin", "Mozilla/5.0", "", false},
		{"legacy browser GET", http.MethodGet, "http://127.0.0.1:18080/?Action=CreateUser&UserName=cr037", "", "", "Mozilla/5.0", "", false},
		{"spoofed browser CLI UA", http.MethodGet, "http://127.0.0.1:18080/?Action=CreateUser&UserName=cr037", "", "", "aws-cli/2.0", "", false},
		{"stock CLI", http.MethodPost, "http://127.0.0.1:18080/", "", "", "aws-cli/2.0", capability, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := forwarded.Load()
			expires := time.Now().Add(time.Hour)
			raw := []byte(`{"access_key_id":"id","secret_access_key":"key","session_token":"token","expiration":"` + expires.UTC().Format(time.RFC3339) + `"}`)
			browserEnd, gatewayEnd := net.Pipe()
			done := make(chan error, 1)
			go func() {
				done <- serveAWS(context.Background(), gatewayEnd, raw, httpUpstream{URL: upstream.URL, TunnelCapability: capability}, "iam", "us-east-1", expires, nil, nil)
			}()
			var body io.Reader
			if tc.method == http.MethodPost {
				body = strings.NewReader("Action=CreateUser&UserName=cr037&Version=2010-05-08")
			}
			req, err := http.NewRequest(tc.method, tc.url, body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.fetchSite)
			}
			req.Header.Set("User-Agent", tc.userAgent)
			if tc.localToken != "" {
				req.Header.Set("X-Amz-Security-Token", tc.localToken)
			}
			transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return browserEnd, nil }}
			response, err := (&http.Client{Transport: transport}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			transport.CloseIdleConnections()
			_ = browserEnd.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("AWS relay did not stop after the client closed")
			}
			forwardedThisRequest := forwarded.Load() != before
			if forwardedThisRequest != tc.wantForward {
				t.Errorf("AWS relay forwarded=%v status=%d, want forwarded=%v", forwardedThisRequest, response.StatusCode, tc.wantForward)
			}
		})
	}
}
