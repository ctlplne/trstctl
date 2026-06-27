package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

type frontDoorDenyLimiter struct {
	calls      int
	tenantID   string
	retryAfter time.Duration
}

func (l *frontDoorDenyLimiter) Allow(_ context.Context, tenantID string) (bool, time.Duration, error) {
	l.calls++
	l.tenantID = tenantID
	return false, l.retryAfter, nil
}

// TestGuardAppliesPerTenantRateLimiter is the SEC-003 front-door budget guard.
// ELI5: an anonymous caller is stopped before quota is touched, while an
// authenticated tenant over budget gets a precise 429 + Retry-After.
func TestGuardAppliesPerTenantRateLimiter(t *testing.T) {
	cfg, sessions := authConfig()
	limiter := &frontDoorDenyLimiter{retryAfter: 2 * time.Second}
	h := api.New(nil, nil, nil, api.WithAuth(cfg), api.WithRateLimiter(limiter))

	unauth := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	unauthRec := httptest.NewRecorder()
	h.ServeHTTP(unauthRec, unauth)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request = %d, want 401 before rate limiting", unauthRec.Code)
	}
	if limiter.calls != 0 {
		t.Fatalf("unauthenticated request consumed tenant quota: calls=%d", limiter.calls)
	}

	tok, err := sessions.Issue("user-1", testTenant, "u@example.test", []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-trstctl_session", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("authenticated over-budget request = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
	if limiter.calls != 1 {
		t.Fatalf("authenticated request should consume one tenant quota unit, calls=%d", limiter.calls)
	}
	if limiter.tenantID != testTenant {
		t.Fatalf("rate limiter tenant = %q, want %q", limiter.tenantID, testTenant)
	}
}
