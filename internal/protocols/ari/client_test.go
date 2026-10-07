// SPDX-License-Identifier: BUSL-1.1

package ari

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchRenewalInfoValidatesUpstreamResponse(t *testing.T) {
	const certID = "AQID.BAUG"
	valid := `{"suggestedWindow":{"start":"2026-12-05T11:05:38Z","end":"2026-12-07T11:05:38Z"}}`
	tests := []struct {
		name, body, retryAfter string
		status                 int
		wantErr                string
		wantRetry              time.Duration
	}{
		{name: "valid Pebble response", body: valid, retryAfter: "21600", wantRetry: 6 * time.Hour},
		{name: "missing start", body: `{"suggestedWindow":{"end":"2026-12-07T11:05:38Z"}}`, wantErr: "invalid suggested window"},
		{name: "reversed window", body: `{"suggestedWindow":{"start":"2026-12-07T11:05:38Z","end":"2026-12-05T11:05:38Z"}}`, wantErr: "invalid suggested window"},
		{name: "equal endpoints", body: `{"suggestedWindow":{"start":"2026-12-05T11:05:38Z","end":"2026-12-05T11:05:38Z"}}`, wantErr: "invalid suggested window"},
		{name: "oversized body", body: valid + strings.Repeat(" ", maxBody), wantErr: "response exceeds"},
		{name: "server failure", body: `{"detail":"do not persist my arbitrary text"}`, status: http.StatusServiceUnavailable, wantErr: "status 503"},
		{name: "excessive retry", body: valid, retryAfter: "999999999999999999999999", wantRetry: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/renewalInfo/"+certID || r.Method != http.MethodGet {
					t.Errorf("unexpected ARI request: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("User-Agent") == "" {
					t.Error("ARI request omitted User-Agent")
				}
				if tt.retryAfter != "" {
					w.Header().Set("Retry-After", tt.retryAfter)
				}
				if tt.status != 0 {
					w.WriteHeader(tt.status)
				}
				_, _ = fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			info, retry, err := NewClient(server.Client()).FetchRenewalInfo(context.Background(), server.URL+"/renewalInfo/", certID)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !info.SuggestedWindow.End.After(info.SuggestedWindow.Start) || retry != tt.wantRetry {
				t.Fatalf("invalid result: %+v, retry=%v", info, retry)
			}
		})
	}
}

type directoryRoundTrip func(*http.Request) (*http.Response, error)

func (f directoryRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func FuzzDiscoverRenewalInfo(f *testing.F) {
	f.Add([]byte(`{"renewalInfo":"https://acme.example.test/renewal-info"}`))
	f.Add([]byte(`{"renewalInfo":"http://127.0.0.1/private"}`))
	f.Add([]byte(`{"renewalInfo":false}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 2048 {
			t.Skip()
		}
		client := NewClient(&http.Client{Transport: directoryRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, nil
		})})
		endpoint, err := client.DiscoverRenewalInfo(t.Context(), "https://acme.example.test/dir")
		if err == nil {
			parsed, parseErr := renewalInfoEndpoint(endpoint)
			if parseErr != nil || parsed.Scheme != "https" {
				t.Fatalf("accepted unsafe endpoint %q: %v", endpoint, parseErr)
			}
		}
	})
}

func TestFetchRenewalInfoRejectsMalformedCertificateIdentifierBeforeNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("malformed identifier reached the network")
	}))
	defer server.Close()
	for _, id := range []string{"", "AQID", "AQID/../../etc/passwd", "AQID.BAUG?x=y", "AQID.BAUG#fragment"} {
		if _, _, err := NewClient(server.Client()).FetchRenewalInfo(context.Background(), server.URL+"/renewalInfo", id); err == nil {
			t.Errorf("accepted malformed identifier %q", id)
		}
	}
	for _, base := range []string{server.URL + "/renewalInfo?", server.URL + "/renewalInfo?key=value", server.URL + "/renewalInfo#fragment", "file:///etc/passwd"} {
		if _, _, err := NewClient(server.Client()).FetchRenewalInfo(context.Background(), base, "AQID.BAUG"); err == nil {
			t.Errorf("accepted malformed endpoint %q", base)
		}
	}
}

func TestDiscoverRenewalInfoFromDirectory(t *testing.T) {
	const ariPath = "/draft-ietf-acme-ari-03/renewalInfo"
	tests := []struct {
		name, body string
		status     int
		wantErr    string
		absent     bool
	}{
		{name: "advertised", body: `{"renewalInfo":"%s"}`},
		{name: "not advertised", body: `{}`, absent: true},
		{name: "relative URL", body: `{"renewalInfo":"/renewalInfo"}`, wantErr: "invalid renewal info endpoint"},
		{name: "userinfo URL", body: `{"renewalInfo":"https://user@example.test/renewalInfo"}`, wantErr: "invalid renewal info endpoint"},
		{name: "directory failure", body: `{"detail":"arbitrary upstream text"}`, status: http.StatusServiceUnavailable, wantErr: "status 503"},
		{name: "oversized directory", body: `{}` + strings.Repeat(" ", maxBody), wantErr: "response exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var expected string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/dir" || r.Method != http.MethodGet || r.Header.Get("User-Agent") == "" {
					t.Errorf("invalid directory request: %s %s, agent=%q", r.Method, r.URL.Path, r.Header.Get("User-Agent"))
				}
				if tt.status != 0 {
					w.WriteHeader(tt.status)
				}
				_, _ = fmt.Fprint(w, strings.ReplaceAll(tt.body, "%s", expected))
			}))
			defer server.Close()
			expected = server.URL + ariPath
			got, err := NewClient(server.Client()).DiscoverRenewalInfo(context.Background(), server.URL+"/dir")
			if tt.absent {
				if !errors.Is(err, ErrNotAdvertised) {
					t.Fatalf("error = %v, want ErrNotAdvertised", err)
				}
				return
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != expected {
				t.Fatalf("endpoint = %q, error = %v, want %q", got, err, expected)
			}
		})
	}
}
