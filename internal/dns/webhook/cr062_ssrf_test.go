// SPDX-License-Identifier: BUSL-1.1

package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

func TestCR062DefaultWebhookDoesNotSendBearerToLoopback(t *testing.T) {
	var hits atomic.Int64
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer host.Close()
	provider := New(host.URL, Credentials{BearerToken: []byte("fixture-token")})
	if err := provider.PresentTXT(t.Context(), "_acme-challenge.example.test", "fixture"); err == nil || hits.Load() != 0 {
		t.Fatalf("default DNS webhook reached loopback with bearer: hits=%d err=%v", hits.Load(), err)
	}
}

func TestCR062GrantedWebhookRefusesCrossOriginRedirect(t *testing.T) {
	var recipientHits atomic.Int64
	recipient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		recipientHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer recipient.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", recipient.URL+"/latest/meta-data/")
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer source.Close()
	client := netsec.SafeClientWithOptions(2*time.Second, netsec.SafeClientOptions{
		AllowPrivateCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	})
	provider := New(source.URL, Credentials{BearerToken: []byte("fixture-token")}, WithHTTPClient(client))
	if err := provider.PresentTXT(t.Context(), "_acme-challenge.example.test", "fixture"); err == nil || recipientHits.Load() != 0 {
		t.Fatalf("DNS webhook followed a cross-origin 303 with bearer: recipient hits=%d err=%v", recipientHits.Load(), err)
	}
}

func TestCR062DefaultWebhookIgnoresTenantProcessHTTPProxy(t *testing.T) {
	var hits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	provider := New("http://cr062-proxy.invalid", Credentials{BearerToken: []byte("fixture-token")})
	if err := provider.PresentTXT(ctx, "_acme-challenge.example.test", "fixture"); err == nil || hits.Load() != 0 {
		t.Fatalf("default DNS webhook sent a bearer through HTTP_PROXY: hits=%d err=%v", hits.Load(), err)
	}
}
