// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// F267: a served API token expires. Without expires_at it gets the deployment's
// maximum lifetime (90 days by default, auth.api_tokens.max_lifetime); a longer
// expiry is refused; a shorter one is kept exactly.
func TestServedAPITokensExpireByDefault(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "token-admin", []string{"access:read", "access:write", "certs:read"})
	mint := func(subject, idem string, expiresAt *time.Time) (int, []byte, *time.Time) {
		t.Helper()
		body := map[string]any{"subject": subject, "scopes": []string{"certs:read"}}
		if expiresAt != nil {
			body["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
		}
		code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/api-tokens", admin, idem, body)
		var got struct {
			ExpiresAt *time.Time `json:"expires_at"`
		}
		_ = json.Unmarshal(raw, &got)
		// Never echo a minted bearer into a failure message.
		var shown map[string]any
		if json.Unmarshal(raw, &shown) == nil {
			delete(shown, "token")
			raw, _ = json.Marshal(shown)
		}
		return code, raw, got.ExpiresAt
	}
	before := time.Now()
	code, raw, expires := mint("ci-reader", "f267-default", nil)
	if code != http.StatusCreated {
		t.Fatalf("mint without expires_at = %d body=%s; want 201", code, raw)
	}
	lo, hi := before.Add(90*24*time.Hour-time.Minute), time.Now().Add(90*24*time.Hour+time.Minute)
	if expires == nil || expires.Before(lo) || expires.After(hi) {
		t.Errorf("mint without expires_at stored expiry %v; want about 90 days from now (%v..%v)", expires, lo, hi)
	}
	tooLong := time.Now().Add(400 * 24 * time.Hour)
	if code, raw, _ := mint("ci-reader-long", "f267-long", &tooLong); code != http.StatusUnprocessableEntity || !bytes.Contains(raw, []byte("auth.api_tokens.max_lifetime")) {
		t.Errorf("mint with a 400-day expiry = %d body=%s; want 422 naming auth.api_tokens.max_lifetime", code, raw)
	}
	week := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Second)
	if code, raw, expires := mint("ci-reader-week", "f267-week", &week); code != http.StatusCreated || expires == nil || !expires.Equal(week) {
		t.Errorf("mint with a 7-day expiry = %d expiry=%v body=%s; want 201 keeping %v", code, expires, raw, week)
	}
}
