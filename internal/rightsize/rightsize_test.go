// SPDX-License-Identifier: BUSL-1.1

package rightsize_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/rightsize"
)

// fakeEntitlements models the operator's entitlement service: one PATCH that
// removes scopes and attests exactly those removals, one GET that reads the
// effective scopes back.
type fakeEntitlements struct {
	mu          sync.Mutex
	scopes      map[string][]string
	token       string
	patches     int
	reflectBody bool
	stale       bool
}

func (f *fakeEntitlements) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token || r.Header.Get("X-Trstctl-Tenant") == "" || r.Header.Get("Idempotency-Key") == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	target := strings.TrimPrefix(r.URL.Path, "/v1/entitlements/")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodPatch:
		body, _ := io.ReadAll(r.Body)
		var req struct {
			RemoveScopes []string `json:"remove_scopes"`
		}
		_ = json.Unmarshal(body, &req)
		f.patches++
		kept := []string{}
		for _, scope := range f.scopes[target] {
			remove := false
			for _, gone := range req.RemoveScopes {
				if gone == scope {
					remove = true
				}
			}
			if !remove {
				kept = append(kept, scope)
			}
		}
		if !f.stale {
			f.scopes[target] = kept
		}
		w.Header().Set("Content-Type", "application/json")
		rollback := "rollback-" + target
		if f.reflectBody {
			rollback = "Bearer " + f.token
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "applied", "mutation_id": "mutation-" + target, "removed_scopes": req.RemoveScopes, "rollback_ref": rollback})
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"scopes": f.scopes[target]})
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func TestApplyMutatesAndReadsBackTheEffectiveScopes(t *testing.T) {
	fake := &fakeEntitlements{scopes: map[string][]string{"service-1": {"read", "write"}}, token: "right-size-token"}
	srv := httptest.NewServer(http.HandlerFunc(fake.handle))
	defer srv.Close()
	in := rightsize.Input{
		Endpoint: srv.URL, Token: []byte("right-size-token"), TenantID: "tenant-a", IdempotencyKey: "op-1",
		Connector: "least-privilege", Target: "service-1",
		ScopeDelta: json.RawMessage(`{"remove_scopes":["write"],"recommended_scopes":["read"]}`),
	}
	mutation, err := rightsize.Apply(context.Background(), srv.Client(), in)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	readback, _ := json.Marshal(map[string]any{"scopes": []string{"read"}})
	if mutation.MutationID != "mutation-service-1" || mutation.RollbackRef != "rollback-service-1" ||
		mutation.ReadbackDigest != crypto.SHA256Hex(append(readback, '\n')) {
		t.Fatalf("mutation = %+v", mutation)
	}
	if fake.patches != 1 {
		t.Fatalf("patches = %d, want 1", fake.patches)
	}

	// A readback that still carries a removed scope is not a success.
	fake.scopes["service-2"] = []string{"read", "write"}
	fake.stale = true
	in.Target = "service-2"
	if _, err := rightsize.Apply(context.Background(), srv.Client(), in); err == nil || !strings.Contains(err.Error(), "still contains removed scope") {
		t.Fatalf("stale readback = %v, want a refusal naming the scope", err)
	}

	// A response that reflects the bearer token is refused, and the error
	// never carries the token.
	fake.stale = false
	fake.reflectBody = true
	fake.scopes["service-3"] = []string{"read", "write"}
	in.Target = "service-3"
	_, err = rightsize.Apply(context.Background(), srv.Client(), in)
	if err == nil || !strings.Contains(err.Error(), "reflected the request credential") || strings.Contains(err.Error(), "right-size-token") {
		t.Fatalf("reflected credential = %v", err)
	}

	if _, err := rightsize.Apply(context.Background(), srv.Client(), rightsize.Input{Endpoint: srv.URL, TenantID: "t", IdempotencyKey: "k", Target: "x", ScopeDelta: in.ScopeDelta}); err == nil || !strings.Contains(err.Error(), "no bearer token") {
		t.Fatalf("missing token = %v", err)
	}
}
