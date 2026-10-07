// SPDX-License-Identifier: BUSL-1.1

package ari

import (
	"context"
	"fmt"
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
