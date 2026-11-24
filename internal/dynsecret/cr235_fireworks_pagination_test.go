// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func cr235Backend(t *testing.T, handler http.Handler) *HostedKeyBackend {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	b, err := NewHostedKeyBackend("fireworks", HostedKeyConfig{
		Endpoint: srv.URL, AdminKey: []byte("admin-test-key"),
		RoleBindings:          map[string]string{"ci": "acme/ci-bot"},
		AllowInsecureLoopback: true, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestCR235FireworksRevokeFindsKeyOnSecondPage(t *testing.T) {
	var deleted atomic.Bool
	b := cr235Backend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("pageToken") == "":
			_ = json.NewEncoder(w).Encode(map[string]any{"apiKeys": []map[string]string{{"keyId": "foreign-1", "displayName": "other"}}, "nextPageToken": "page-2", "totalSize": 2})
		case r.Method == http.MethodGet && r.URL.Query().Get("pageToken") == "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{"apiKeys": []map[string]string{{"keyId": "issued-2", "displayName": "trstctl-ci-0123456789abcdef"}}, "totalSize": 2})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/accounts/acme/users/ci-bot/apiKeys:delete":
			var body struct {
				KeyID string `json:"keyId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			deleted.Store(body.KeyID == "issued-2")
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	if err := b.Revoke(context.Background(), "acme:ci-bot/issued-2"); err != nil {
		t.Fatal(err)
	}
	if !deleted.Load() {
		t.Fatal("revocation completed without deleting the key on page two")
	}
}

func TestCR235FireworksIncompleteListCannotProveAbsence(t *testing.T) {
	for _, tc := range []struct {
		name, token string
		total       int
	}{
		{"repeated token", "same", 2},
		{"truncated without token", "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := cr235Backend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"apiKeys": []map[string]string{{"keyId": "foreign-1", "displayName": "other"}}, "nextPageToken": tc.token, "totalSize": tc.total})
			}))
			if err := b.Revoke(context.Background(), "acme:ci-bot/issued-2"); err == nil {
				t.Fatal("incomplete key list was treated as proof of absence")
			}
		})
	}
}

func TestCR235FireworksNativeExpiryBoundsLease(t *testing.T) {
	var expires atomic.Value
	expires.Store("")
	b := cr235Backend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"apiKeys": []any{}})
			return
		}
		var body struct {
			APIKey struct {
				ExpireTime string `json:"expireTime"`
			} `json:"apiKey"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		expires.Store(body.APIKey.ExpireTime)
		_ = json.NewEncoder(w).Encode(map[string]string{"keyId": "issued-2", "key": "fireworks-test-key"})
	}))
	start := time.Now()
	_, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "ci", LeaseID: "lease-1", PrincipalSuffix: "0123456789abcdef", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	expiry := expires.Load().(string)
	got, err := time.Parse(time.RFC3339Nano, expiry)
	if err != nil || got.Before(start.Add(time.Hour)) || got.After(time.Now().Add(time.Hour+5*time.Second)) {
		t.Fatalf("native expireTime = %q, parse error %v; want one-hour lease bound", expiry, err)
	}
}
