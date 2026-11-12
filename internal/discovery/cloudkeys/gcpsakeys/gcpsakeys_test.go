// SPDX-License-Identifier: BUSL-1.1

package gcpsakeys

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

// gcpStandIn answers IAM's service account and key listings and Policy
// Analyzer's key last-authentication activity for project "p".
func gcpStandIn(t *testing.T, now time.Time, denyActivity *atomic.Bool) *httptest.Server {
	t.Helper()
	day := func(d int) string { return now.AddDate(0, 0, d).Format(time.RFC3339) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gcp-read-token" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/v1/projects/p/serviceAccounts":
			if r.URL.Query().Get("pageToken") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{"accounts": []any{map[string]any{"email": "ci@p.iam.gserviceaccount.com"}}, "nextPageToken": "2"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accounts": []any{map[string]any{"email": "batch@p.iam.gserviceaccount.com", "disabled": true}}})
		case r.URL.Path == "/v1/projects/p/serviceAccounts/ci@p.iam.gserviceaccount.com/keys":
			if r.URL.Query().Get("keyTypes") != "USER_MANAGED" {
				http.Error(w, "system keys asked for", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{
				map[string]any{"name": "projects/p/serviceAccounts/ci@p.iam.gserviceaccount.com/keys/k-used", "validAfterTime": day(-200), "validBeforeTime": "9999-12-31T23:59:59Z"},
				map[string]any{"name": "projects/p/serviceAccounts/ci@p.iam.gserviceaccount.com/keys/k-idle", "validAfterTime": day(-200), "validBeforeTime": "9999-12-31T23:59:59Z"},
				map[string]any{"name": "projects/p/serviceAccounts/ci@p.iam.gserviceaccount.com/keys/k-never", "validAfterTime": day(-120), "validBeforeTime": "9999-12-31T23:59:59Z"},
				map[string]any{"name": "projects/p/serviceAccounts/ci@p.iam.gserviceaccount.com/keys/k-expired", "validAfterTime": day(-400), "validBeforeTime": day(-10)},
			}})
		case r.URL.Path == "/v1/projects/p/serviceAccounts/batch@p.iam.gserviceaccount.com/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{
				map[string]any{"name": "projects/p/serviceAccounts/batch@p.iam.gserviceaccount.com/keys/k-off", "validAfterTime": day(-300)},
			}})
		case strings.HasSuffix(r.URL.Path, "/activityTypes/serviceAccountKeyLastAuthentication/activities:query"):
			if denyActivity.Load() {
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			res := func(key string) string {
				return "//iam.googleapis.com/projects/p/serviceAccounts/ci@p.iam.gserviceaccount.com/keys/" + key
			}
			if r.URL.Query().Get("pageToken") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{"activities": []any{
					map[string]any{"fullResourceName": res("k-used"), "activity": map[string]any{"lastAuthenticatedTime": day(-3)}},
				}, "nextPageToken": "2"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"activities": []any{
				map[string]any{"fullResourceName": res("k-idle"), "activity": map[string]any{"lastAuthenticatedTime": day(-95)}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestServiceAccountKeysWithLastAuthenticationM3L1 is M3-L1: a project's
// user-managed service-account keys with their age and last authentication,
// across pages. An active key that has not authenticated for 90 days, or never
// did in 90 days since it was created, is stale; one used three days ago, an
// expired key and a disabled account's key are not.
func TestServiceAccountKeysWithLastAuthenticationM3L1(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	var deny atomic.Bool
	srv := gcpStandIn(t, now, &deny)
	reader, err := New(Config{Endpoint: srv.URL, ActivityEndpoint: srv.URL, Project: "p", Token: []byte("gcp-read-token"), HTTPClient: srv.Client(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	res, err := reader.Keys(context.Background())
	if err != nil || res.LastUseError != nil {
		t.Fatalf("Keys = %+v, %v", res, err)
	}
	byID := map[string]Key{}
	for _, k := range res.Keys {
		byID[k.KeyID] = k
	}
	if len(byID) != 5 || res.Keys[0].ServiceAccount != "batch@p.iam.gserviceaccount.com" {
		t.Fatalf("keys = %+v; want five, accounts in email order", res.Keys)
	}
	for id, want := range map[string]struct {
		status string
		stale  bool
	}{
		"k-used": {"Active", false}, "k-idle": {"Active", true}, "k-never": {"Active", true},
		"k-expired": {"Expired", false}, "k-off": {"Disabled", false},
	} {
		k := byID[id]
		if k.Status(now) != want.status || k.Stale(now) != want.stale || !k.LastUseKnown {
			t.Errorf("%s: status %s stale %v known %v; want %s %v", id, k.Status(now), k.Stale(now), k.LastUseKnown, want.status, want.stale)
		}
	}
	if k := byID["k-used"]; k.LastAuthenticated == nil || !k.LastAuthenticated.Equal(now.AddDate(0, 0, -3)) {
		t.Fatalf("k-used last authenticated = %v", k.LastAuthenticated)
	}
	if k := byID["k-never"]; k.LastAuthenticated != nil || k.Unused(now) != 120*24*time.Hour {
		t.Fatalf("k-never = %+v; want unused since creation", k)
	}

	// Policy Analyzer refused: the keys are still listed, their last use
	// unknown, and none is called stale for want of it.
	deny.Store(true)
	res, err = reader.Keys(context.Background())
	if err != nil || res.LastUseError == nil || len(res.Keys) != 5 {
		t.Fatalf("with the activity refused: %d keys, last-use error %v, %v", len(res.Keys), res.LastUseError, err)
	}
	for _, k := range res.Keys {
		if k.LastUseKnown || k.Stale(now) {
			t.Fatalf("%s with unknown last use = known %v stale %v", k.KeyID, k.LastUseKnown, k.Stale(now))
		}
	}
	if strings.Contains(res.LastUseError.Error(), "gcp-read-token") {
		t.Fatal("the error carries the token")
	}
}

// TestReaderNeedsProjectAndTokenM3L1 refuses a reader with no project or
// token.
func TestReaderNeedsProjectAndTokenM3L1(t *testing.T) {
	if _, err := New(Config{Token: []byte("t")}); err == nil {
		t.Fatal("no project accepted")
	}
	if _, err := New(Config{Project: "p"}); err == nil {
		t.Fatal("no token accepted")
	}
	if _, err := New(Config{Project: "p", Token: []byte("t"), Endpoint: "::not a url"}); err == nil {
		t.Fatal("a bad endpoint accepted")
	}
}
