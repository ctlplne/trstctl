package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/protocols/acme"
)

func TestProviderPresentsAndCleansThroughWebhook(t *testing.T) {
	var calls []request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), "Bearer webhook-token"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		calls = append(calls, req)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	p := New(srv.URL, Credentials{BearerToken: []byte("webhook-token")}, WithHTTPClient(srv.Client()))
	if err := p.PresentTXT(context.Background(), "_acme-challenge.example.com", "digest"); err != nil {
		t.Fatalf("present: %v", err)
	}
	if err := p.CleanupTXT(context.Background(), "_acme-challenge.example.com", "digest"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	if calls[0].Action != "present" || calls[0].Name != "_acme-challenge.example.com" || calls[0].Value != "digest" {
		t.Fatalf("bad present call: %+v", calls[0])
	}
	if calls[1].Action != "cleanup" || calls[1].Name != "_acme-challenge.example.com" || calls[1].Value != "digest" {
		t.Fatalf("bad cleanup call: %+v", calls[1])
	}
}

func TestProviderConformsWithMemoryWebhook(t *testing.T) {
	mem := &acme.MemoryDNSProvider{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		switch req.Action {
		case "present":
			if err := mem.PresentTXT(r.Context(), req.Name, req.Value); err != nil {
				t.Fatalf("memory present: %v", err)
			}
		case "cleanup":
			if err := mem.CleanupTXT(r.Context(), req.Name, req.Value); err != nil {
				t.Fatalf("memory cleanup: %v", err)
			}
		default:
			t.Fatalf("unknown action %q", req.Action)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	p := New(srv.URL, Credentials{}, WithHTTPClient(srv.Client()))
	if err := acme.ConformDNSProvider(context.Background(), p, mem); err != nil {
		t.Fatalf("conformance: %v", err)
	}
}
