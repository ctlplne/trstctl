package projections_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/ratelimit"
	"trstctl.com/trstctl/internal/server"
)

// TestAssembledServerBulkheadIsolatesHealth is the R2.3 acceptance "one subsystem
// can't starve the others" at the assembled level: when the API subsystem's
// bulkhead is saturated/unavailable, API requests shed (503) but liveness,
// readiness, and metrics — which are not behind the API bulkhead — keep serving.
func TestAssembledServerBulkheadIsolatesHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	// Drive the API subsystem to "fully saturated" by closing its pool; the other
	// subsystems' pools are untouched.
	set := bulkhead.Default()
	set.Pool(bulkhead.SubsystemAPI).Close()

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov, Bulkhead: set})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()
	defer func() { _ = asm.Shutdown(context.Background()) }()

	// API requests are shed.
	if code, _ := req(t, ts, http.MethodGet, "/api/v1/owners", "", ""); code != http.StatusServiceUnavailable {
		t.Errorf("API request under a saturated api bulkhead = %d, want 503", code)
	}
	// Liveness, readiness, and metrics are NOT starved.
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		if code, body := req(t, ts, http.MethodGet, path, "", ""); code != http.StatusOK {
			t.Errorf("%s under a saturated api bulkhead = %d, want 200 (must not be starved): %s", path, code, body)
		}
	}
}

// TestAssembledServerRateLimiterSheds is the R2.3 acceptance "the rate limiter
// sheds load as configured": with a small per-tenant budget, rapid requests start
// returning 429.
func TestAssembledServerRateLimiterSheds(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	// Capacity 2, negligible refill: the 3rd+ rapid request is shed.
	limiter := ratelimit.NewPostgres(st, 2, 0.001)
	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov, RateLimiter: limiter})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()
	defer func() { _ = asm.Shutdown(context.Background()) }()

	token := mintToken(t, st, "owners:read")
	var ok, shed int
	for i := 0; i < 5; i++ {
		code, _ := req(t, ts, http.MethodGet, "/api/v1/owners", token, "")
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			shed++
		}
	}
	if ok != 2 {
		t.Errorf("admitted %d requests, want 2 (the configured budget)", ok)
	}
	if shed == 0 {
		t.Error("the rate limiter did not shed any load (no 429s)")
	}
}
