// SPDX-License-Identifier: BUSL-1.1

package azureappsecrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// graphStandIn answers Microsoft Graph's application listing (two pages) and
// app credential sign-in activity. nextLinkHost, when set, sends the second
// applications page's link to another host.
func graphStandIn(t *testing.T, now time.Time, denyActivity *atomic.Bool, nextLinkHost string) *httptest.Server {
	t.Helper()
	day := func(d int) string { return now.AddDate(0, 0, d).Format(time.RFC3339) }
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph-read-token" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1.0/applications":
			if r.URL.Query().Get("$skiptoken") == "" {
				host := srv.URL
				if nextLinkHost != "" {
					host = nextLinkHost
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
					map[string]any{"id": "o1", "appId": "a1", "displayName": "payments-api", "passwordCredentials": []any{
						map[string]any{"keyId": "s-used", "displayName": "ci", "hint": "Zq7", "startDateTime": day(-200), "endDateTime": day(500)},
						map[string]any{"keyId": "s-idle", "displayName": "old ci", "hint": "Xy1", "startDateTime": day(-300), "endDateTime": day(300)},
					}},
				}, "@odata.nextLink": host + "/v1.0/applications?$skiptoken=2"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]any{"id": "o2", "appId": "a2", "displayName": "batch-job", "passwordCredentials": []any{
					map[string]any{"keyId": "s-never", "displayName": "batch", "startDateTime": day(-120), "endDateTime": day(240)},
					map[string]any{"keyId": "s-expired", "displayName": "expired", "startDateTime": day(-800), "endDateTime": day(-5)},
				}},
			}})
		case "/beta/reports/appCredentialSignInActivities":
			if denyActivity.Load() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if r.URL.Query().Get("$skiptoken") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
					map[string]any{"keyId": "s-used", "signInActivity": map[string]any{"lastSignInDateTime": day(-4)}},
				}, "@odata.nextLink": srv.URL + "/beta/reports/appCredentialSignInActivities?$skiptoken=2"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]any{"keyId": "s-idle", "signInActivity": map[string]any{"lastSignInDateTime": day(-140)}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAppRegistrationSecretsWithLastSignInM3L2 is M3-L2: a tenant's
// app-registration client secrets with their age, expiry and last sign-in,
// across pages. An active secret that has not signed in for 90 days, or never
// did in 90 days since it was created, is stale; one used four days ago and an
// expired one are not. The secret's hint is never read.
func TestAppRegistrationSecretsWithLastSignInM3L2(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	var deny atomic.Bool
	srv := graphStandIn(t, now, &deny, "")
	reader, err := New(Config{Endpoint: srv.URL, Token: []byte("graph-read-token"), HTTPClient: srv.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	res, err := reader.Secrets(context.Background())
	if err != nil || res.LastUseError != nil || len(res.Secrets) != 4 {
		t.Fatalf("Secrets = %+v, %v", res, err)
	}
	if res.Secrets[0].Application != "batch-job" {
		t.Fatalf("secrets not in application order: %+v", res.Secrets)
	}
	byID := map[string]Secret{}
	for _, s := range res.Secrets {
		byID[s.KeyID] = s
	}
	for id, want := range map[string]struct {
		status string
		stale  bool
	}{"s-used": {"Active", false}, "s-idle": {"Active", true}, "s-never": {"Active", true}, "s-expired": {"Expired", false}} {
		s := byID[id]
		if s.Status(now) != want.status || s.Stale(now) != want.stale || !s.LastUseKnown {
			t.Errorf("%s: %s stale %v known %v; want %s %v", id, s.Status(now), s.Stale(now), s.LastUseKnown, want.status, want.stale)
		}
	}
	if s := byID["s-used"]; s.AppID != "a1" || s.Application != "payments-api" || s.Name != "ci" || s.LastSignIn == nil || !s.LastSignIn.Equal(now.AddDate(0, 0, -4)) {
		t.Fatalf("s-used = %+v", s)
	}

	deny.Store(true)
	res, err = reader.Secrets(context.Background())
	if err != nil || res.LastUseError == nil || len(res.Secrets) != 4 {
		t.Fatalf("with the activity refused: %d secrets, %v, %v", len(res.Secrets), res.LastUseError, err)
	}
	for _, s := range res.Secrets {
		if s.LastUseKnown || s.Stale(now) {
			t.Fatalf("%s with unknown last use: known %v stale %v", s.KeyID, s.LastUseKnown, s.Stale(now))
		}
	}
}

// TestNextPageLinksStayOnTheGraphEndpointM3L2: a next-page link to another
// host is refused, so a response cannot send the token elsewhere.
func TestNextPageLinksStayOnTheGraphEndpointM3L2(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	var deny atomic.Bool
	srv := graphStandIn(t, now, &deny, "https://elsewhere.example")
	reader, err := New(Config{Endpoint: srv.URL, Token: []byte("graph-read-token"), HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.Secrets(context.Background()); err == nil || !strings.Contains(err.Error(), "leaves the Graph endpoint") {
		t.Fatalf("a next-page link to another host = %v", err)
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("no token accepted")
	}
}
