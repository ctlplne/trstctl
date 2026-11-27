// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
)

type enrollDenyLimiter struct {
	calls      int
	tenantID   string
	retryAfter time.Duration
}

func (l *enrollDenyLimiter) Allow(_ context.Context, tenantID string) (bool, time.Duration, error) {
	l.calls++
	l.tenantID = tenantID
	return false, l.retryAfter, nil
}

func TestSpecialEnrollBootstrapKeepsAnonymousTrafficOffTenantQuota(t *testing.T) {
	limiter := &enrollDenyLimiter{retryAfter: 3 * time.Second}
	a := api.New(nil, nil, nil, api.WithAgentEnroller(enrollOnlyEnroller{}), api.WithRateLimiter(limiter))

	body, _ := json.Marshal(map[string]string{
		"token": "tok",
		"csr":   base64.StdEncoding.EncodeToString([]byte("csr-der")),
	})
	req := httptest.NewRequest(http.MethodPost, "/enroll/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", testTenant)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /enroll/bootstrap = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if limiter.calls != 0 {
		t.Fatalf("anonymous enrollment charged tenant quota: calls=%d tenant=%q", limiter.calls, limiter.tenantID)
	}
}
