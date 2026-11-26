// SPDX-License-Identifier: BUSL-1.1

package observ

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestRouteLabelCardinalityIsBounded is the regression guard for the metrics
// memory-exhaustion defect. normalizeRoute collapses IDENTIFIER-shaped segments
// (UUIDs, long hex, digits), but an unauthenticated client can simply request
// paths that look nothing like an id and mint a fresh label value per request.
// The metrics registry then grows without bound, and every /metrics scrape grows
// with it — memory exhaustion plus scrape amplification.
func TestRouteLabelCardinalityIsBounded(t *testing.T) {
	m := &Middleware{}
	seen := map[string]struct{}{}
	for i := 0; i < maxDistinctRouteLabels*4; i++ {
		// Deliberately NOT id-shaped, so normalizeRoute leaves each one distinct.
		seen[m.boundedRoute("/api/v1/wid"+strconv.Itoa(i)+"get")] = struct{}{}
	}
	if len(seen) > maxDistinctRouteLabels+1 { // +1 for the "other" bucket
		t.Fatalf("emitted %d distinct route labels for %d hostile paths, cap is %d (+other); "+
			"an unauthenticated client can exhaust the metrics registry",
			len(seen), maxDistinctRouteLabels*4, maxDistinctRouteLabels)
	}
	if _, ok := seen[otherRouteLabel]; !ok {
		t.Fatalf("overflow routes were not folded into %q", otherRouteLabel)
	}
}

// TestRouteLabelStillDistinguishesRealRoutes keeps the cap honest: the real
// routes a deployment serves are far fewer than the cap, so they must remain
// individually labeled rather than all collapsing to "other".
func TestRouteLabelStillDistinguishesRealRoutes(t *testing.T) {
	m := &Middleware{}
	for _, path := range []string{
		"/api/v1/certificates",
		"/api/v1/secrets",
		"/api/v1/agents",
	} {
		if got := m.boundedRoute(path); got != path {
			t.Fatalf("boundedRoute(%q) = %q, want the route itself", path, got)
		}
		// Stable across repeats — a route already seen is never re-counted.
		if got := m.boundedRoute(path); got != path {
			t.Fatalf("boundedRoute(%q) on repeat = %q, want %q", path, got, path)
		}
	}
	// And id-collapsing still works, so per-id paths share one label.
	a := m.boundedRoute("/api/v1/certificates/123e4567-e89b-12d3-a456-426614174000")
	b := m.boundedRoute("/api/v1/certificates/00000000-0000-0000-0000-000000000001")
	if a != b {
		t.Fatalf("per-id paths produced different labels: %q vs %q", a, b)
	}
}

func TestAnonymousMethodAndPathCannotGrowHTTPMetrics(t *testing.T) {
	r := NewRegistry()
	m := NewMiddleware(Options{Registry: r})
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	for i := 0; i < 3000; i++ {
		req := httptest.NewRequest("HOSTILE"+strconv.Itoa(i), "/"+strings.Repeat("p", 4096)+strconv.Itoa(i), nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if got := len(m.knownRoutes); got > 1 {
		t.Fatalf("oversized paths retained %d route labels", got)
	}
	if got := len(m.reqs.series); got > 1 {
		t.Fatalf("unbounded methods retained %d counter series", got)
	}
	if got := len(m.dur.series); got > 1 {
		t.Fatalf("unbounded methods retained %d histogram series", got)
	}
	var out strings.Builder
	if err := r.WriteProm(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "HOSTILE") || strings.Contains(out.String(), strings.Repeat("p", 100)) {
		t.Fatal("untrusted method or oversized path reached metrics output")
	}
}
