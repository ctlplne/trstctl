// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// a238l1ControlPlane is a stand-in for the login and read routes: each sign-in
// issues the next session, valid until the expiry it names.
type a238l1ControlPlane struct {
	mu       sync.Mutex
	ttl      time.Duration
	now      func() time.Time
	logins   []string
	sessions map[string]time.Time
}

func (c *a238l1ControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case r.URL.Path == "/api/v1/secrets/login":
		var body struct {
			Method     string `json:"method"`
			Credential string `json:"credential"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Method != "kubernetes" || body.Credential != "pod-token" {
			http.Error(w, `{"title":"refused"}`, http.StatusUnauthorized)
			return
		}
		c.logins = append(c.logins, r.Header.Get("Idempotency-Key"))
		token := "session-" + strconv.Itoa(len(c.logins))
		expires := c.now().Add(c.ttl)
		c.sessions[token] = expires
		_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": expires})
	case strings.HasPrefix(r.URL.Path, "/api/v1/secrets/store/"):
		expires, ok := c.sessions[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok || !c.now().Before(expires) {
			http.Error(w, `{"title":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "db", "value": "v", "version": 1})
	default:
		http.NotFound(w, r)
	}
}

// A238-L1: a session client signs in at its first call, keeps the session
// while it lives, and signs in again — a fresh session, under its own
// idempotency key — a minute before the session expires, without first being
// refused.
func TestSessionClientSignsInAgainBeforeItsSessionExpiresA238L1(t *testing.T) {
	clock := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	cp := &a238l1ControlPlane{ttl: 90 * time.Second, now: now, sessions: map[string]time.Time{}}
	server := httptest.NewServer(cp)
	defer server.Close()
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("pod-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewSessionClient(server.URL, "tenant", "kubernetes", credential, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.now = now
	fetch := func() {
		t.Helper()
		if _, _, err := client.Fetch(t.Context(), "db"); err != nil {
			t.Fatalf("fetch: %v", err)
		}
	}
	fetch()
	fetch()
	if len(cp.logins) != 1 {
		t.Fatalf("signed in %d times while the session lived, want 1", len(cp.logins))
	}
	clock = clock.Add(40 * time.Second) // 50 s left: inside the one-minute margin
	fetch()
	if len(cp.logins) != 2 || cp.logins[0] == cp.logins[1] {
		t.Fatalf("logins = %v; want a second sign-in under its own key before the session expired", cp.logins)
	}
}

// A238-L1: a renderer authenticates with exactly one of a token file or a
// workload sign-in, and the sign-in needs both its method and credential file.
func TestRendererConfigTakesATokenOrAWorkloadSignInA238L1(t *testing.T) {
	base := func() Config {
		return Config{Server: "https://cp.example.test", Consumer: "c", StateDir: "/tmp/state",
			Templates: []Template{{Name: "t", Destination: "/tmp/out", Text: `{{ secret "a" }}`}}}
	}
	for name, tc := range map[string]struct {
		token, method, file string
		ok                  bool
	}{
		"a token file":     {token: "/run/token", ok: true},
		"a sign-in":        {method: "kubernetes", file: "/run/sa-token", ok: true},
		"neither":          {},
		"both":             {token: "/run/token", method: "kubernetes", file: "/run/sa-token"},
		"a method alone":   {method: "kubernetes"},
		"a file alone":     {file: "/run/sa-token"},
		"a token and file": {token: "/run/token", file: "/run/sa-token"},
	} {
		cfg := base()
		cfg.TokenFile, cfg.LoginMethod, cfg.LoginCredentialFile = tc.token, tc.method, tc.file
		if err := cfg.Validate(); (err == nil) != tc.ok {
			t.Fatalf("%s: Validate = %v, want ok=%t", name, err, tc.ok)
		}
	}
}
