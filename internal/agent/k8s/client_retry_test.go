// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClientDoesNotRetryMutationRejectedByAPIServer(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	client := New(server.URL, "token", "apps", server.Client())
	status, _, err := client.request(context.Background(), http.MethodPost, "/api/v1/namespaces/apps/secrets", map[string]any{"metadata": map[string]any{"name": "tls"}})
	if err != nil {
		t.Fatalf("POST rejected by API server: %v", err)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("POST status = %d, want 429", status)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("POST attempts = %d, want exactly 1 so an uncertain mutation is never replayed", got)
	}
}

func TestClientBoundsSafeReadRetries(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	client := New(server.URL, "token", "apps", server.Client())
	status, _, err := client.request(context.Background(), http.MethodGet, "/apis/trstctl.com/v1alpha1/clusterissuers", nil)
	if err != nil {
		t.Fatalf("GET after bounded retry budget: %v", err)
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("GET status = %d, want final 503", status)
	}
	if got := attempts.Load(); got != maxReadAttempts {
		t.Fatalf("GET attempts = %d, want bounded maximum %d", got, maxReadAttempts)
	}
}
