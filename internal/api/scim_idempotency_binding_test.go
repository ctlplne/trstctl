// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestSCIMMutationBindsTokenRouteMethodAndRawBody(t *testing.T) {
	idem := orchestrator.NewMemoryIdempotency()
	a := New(nil, idem, &orchestrator.Orchestrator{})
	const (
		key      = "shared-scim-sensitive-key"
		sentinel = "scim-cached-response-sentinel-must-not-leak"
	)
	tokenA := scimToken{Name: "okta-a", TenantID: "tenant-a", TokenHash: strings.Repeat("a", 64)}
	tokenB := scimToken{Name: "okta-b", TenantID: "tenant-a", TokenHash: strings.Repeat("b", 64)}
	body := []byte(`{"active":true,"displayName":"Alice"}`)
	invoke := func(tok scimToken, method, path string, raw []byte, fn func(context.Context, string) (int, any, error)) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		recorder := httptest.NewRecorder()
		a.scimMutate(recorder, req, tok, key, "", raw, fn)
		return recorder
	}

	calls := 0
	const escapedRoute = "/scim/v2/Users/alice%2Fops"
	first := invoke(tokenA, http.MethodPatch, escapedRoute, body, func(context.Context, string) (int, any, error) {
		calls++
		return http.StatusOK, map[string]string{"credential": sentinel}, nil
	})
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), sentinel) {
		t.Fatalf("first SCIM mutation status=%d body=%s", first.Code, first.Body.String())
	}
	replayRan := false
	replay := invoke(tokenA, http.MethodPatch, escapedRoute, body, func(context.Context, string) (int, any, error) {
		replayRan = true
		return http.StatusOK, map[string]string{"credential": "wrong-replay"}, nil
	})
	if replay.Code != first.Code || replay.Body.String() != first.Body.String() || replayRan || calls != 1 {
		t.Fatalf("exact SCIM replay status=%d body=%s ran=%v calls=%d; first=%s", replay.Code, replay.Body.String(), replayRan, calls, first.Body.String())
	}

	collisionCallbacks := 0
	conflictCallback := func(context.Context, string) (int, any, error) {
		collisionCallbacks++
		return http.StatusOK, map[string]string{"credential": "must-not-run"}, nil
	}
	conflicts := map[string]*httptest.ResponseRecorder{
		"mapping": invoke(scimToken{Name: tokenA.Name, TenantID: tokenA.TenantID, TokenHash: tokenA.TokenHash, SubjectAttribute: "externalId"}, http.MethodPatch, escapedRoute, body, conflictCallback),
		"token":   invoke(tokenB, http.MethodPatch, escapedRoute, body, conflictCallback),
		"route":   invoke(tokenA, http.MethodPatch, "/scim/v2/Users/alice/ops", body, conflictCallback),
		"method":  invoke(tokenA, http.MethodPut, escapedRoute, body, conflictCallback),
		"body": invoke(tokenA, http.MethodPatch, escapedRoute,
			[]byte(`{"active":false,"displayName":"Alice"}`), conflictCallback),
	}
	for label, conflict := range conflicts {
		if conflict.Code != http.StatusConflict {
			t.Fatalf("changed SCIM %s status=%d body=%s, want 409", label, conflict.Code, conflict.Body.String())
		}
		if !strings.HasPrefix(conflict.Header().Get("Content-Type"), "application/scim+json") {
			t.Fatalf("changed SCIM %s content-type=%q", label, conflict.Header().Get("Content-Type"))
		}
		if strings.Contains(conflict.Body.String(), sentinel) {
			t.Fatalf("changed SCIM %s disclosed cached response: %s", label, conflict.Body.String())
		}
	}
	if collisionCallbacks != 0 {
		t.Fatalf("changed SCIM binding reached callback %d times, want zero", collisionCallbacks)
	}
}
