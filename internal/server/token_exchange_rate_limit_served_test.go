// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
)

// M4-L6: POST /oauth2/token is unauthenticated, so each client address gets
// protocols.spiffe.exchange_requests_per_minute requests. With two a minute,
// a client's first two requests reach the exchange (refused there, as these
// carry no subject token); its third answers 429 temporarily_unavailable with
// a Retry-After before anything is read; another address is unaffected.
func TestServedTokenExchangeLimitsEachClientM4L6(t *testing.T) {
	tenant := uuid.NewSHA1(uuid.NameSpaceOID, []byte("m4l6-exchange-tenant")).String()
	h := newOperatingServedHarness(t, config.Protocols{SPIFFE: config.SPIFFEProtocol{
		Enabled: true, TenantID: tenant, TrustDomain: "m4l6.served.test", SocketPath: filepath.Join(t.TempDir(), "cp.sock"),
		ExchangeRequestsPerMinute: 2,
	}})
	exchange := func(remote string) (int, string, map[string]any) {
		t.Helper()
		form := url.Values{"grant_type": {tokenExchangeGrant}, "subject_token_type": {tokenTypeJWT}, "audience": {"https://m4l6.internal"}}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		req.RemoteAddr = remote
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Tenant-ID", tenant)
		rec := httptest.NewRecorder()
		h.ts.Config.Handler.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, rec.Header().Get("Retry-After"), out
	}
	for i := range 2 {
		if status, _, out := exchange("198.51.100.46:40001"); status != http.StatusBadRequest || out["error"] != "invalid_request" {
			t.Fatalf("request %d: HTTP %d %v; want the exchange's own refusal", i+1, status, out)
		}
	}
	status, retry, out := exchange("198.51.100.46:40002")
	if wait, err := strconv.Atoi(retry); status != http.StatusTooManyRequests || err != nil || wait < 1 || wait > 31 || out["error"] != "temporarily_unavailable" {
		t.Fatalf("the third request: HTTP %d Retry-After %q %v; want 429 with the wait", status, retry, out)
	}
	if status, _, out := exchange("198.51.100.47:40001"); status != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Fatalf("another client: HTTP %d %v; want its own requests", status, out)
	}
	t.Logf("M4L6_RATE_LIMIT_OK limit=2/min retry_after=%ss", retry)
}
