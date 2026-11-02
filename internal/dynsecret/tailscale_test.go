// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// tailscaleStandIn follows the v2 API's auth-key endpoints as Tailscale's API
// documentation describes them.
type tailscaleStandIn struct {
	mu       sync.Mutex
	keys     map[string]map[string]any
	next     int
	requests []map[string]any
}

func newTailscaleStandIn(t *testing.T) (*tailscaleStandIn, *httptest.Server) {
	t.Helper()
	lab := &tailscaleStandIn{keys: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tskey-api-lab" { // #nosec G101 -- fabricated stand-in API token (CWE-798)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		lab.mu.Lock()
		defer lab.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/tailnet/-/keys":
			var request map[string]any
			_ = json.NewDecoder(r.Body).Decode(&request)
			lab.requests = append(lab.requests, request)
			lab.next++
			id := fmt.Sprintf("k%dCNTRL", lab.next)
			lab.keys[id] = request
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "key": "tskey-auth-" + id + "-secret",
				"created": "2026-11-02T15:00:00Z", "expires": "2026-11-02T16:00:00Z", "description": request["description"]})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/tailnet/-/keys/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/v2/tailnet/-/keys/")
			if _, ok := lab.keys[id]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(lab.keys, id)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return lab, srv
}

func TestTailscaleLeaseIsASingleUseTaggedAuthKeyA239(t *testing.T) {
	lab, srv := newTailscaleStandIn(t)
	b, err := NewTailscaleBackend(TailscaleConfig{Endpoint: srv.URL, APIToken: []byte("tskey-api-lab"),
		RoleBindings: map[string]string{"ci": "tag:ci, tag:build"}, MaxLifetime: time.Hour,
		AllowInsecureLoopback: true, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	ref, credential, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "ci", LeaseID: "lease-0001"})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ID        string    `json:"id"`
		Key       string    `json:"key"`
		ExpiresAt time.Time `json:"expires_at"`
		Tags      []string  `json:"tags"`
	}
	if err := json.Unmarshal(credential, &got); err != nil || ref != "tailscale-key:"+got.ID || !strings.HasPrefix(got.Key, "tskey-auth-") ||
		strings.Join(got.Tags, ",") != "tag:ci,tag:build" || got.ExpiresAt.IsZero() {
		t.Fatalf("ref %q credential %+v (%v)", ref, got, err)
	}
	request, _ := json.Marshal(lab.requests[0])
	want := `{"capabilities":{"devices":{"create":{"ephemeral":true,"preauthorized":true,"reusable":false,"tags":["tag:ci","tag:build"]}}},"description":"` +
		TailscaleKeyDescription("lease-0001") + `","expirySeconds":3600}`
	if string(request) != want {
		t.Fatalf("request %s\nwant    %s", request, want)
	}
	if err := b.Revoke(context.Background(), ref); err != nil || len(lab.keys) != 0 {
		t.Fatalf("revoke: %v; keys left %d", err, len(lab.keys))
	}
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("a second revocation of a deleted key: %v", err)
	}
	for _, foreign := range []string{"k1CNTRL", "tailscale-key:", "tailscale-key:../x"} {
		if err := b.Revoke(context.Background(), foreign); err == nil {
			t.Errorf("deleted %q, not a key this provider issued", foreign)
		}
	}
}

func TestTailscaleConfigA239(t *testing.T) {
	for _, bad := range []string{"ci", "tag:", "tag:a b", "tag:ci,admin"} {
		if _, err := ParseTailscaleTags(bad); err == nil {
			t.Errorf("tags %q accepted", bad)
		}
	}
	base := TailscaleConfig{APIToken: []byte("t"), MaxLifetime: time.Hour, HTTPClient: http.DefaultClient}
	if b, err := NewTailscaleBackend(base); err != nil || b.endpoint != "https://api.tailscale.com" || b.tailnet != "-" {
		t.Fatalf("defaults: %+v %v", b, err)
	}
	for name, mutate := range map[string]func(*TailscaleConfig){
		"plain http":  func(c *TailscaleConfig) { c.Endpoint = "http://api.example" },
		"bad tailnet": func(c *TailscaleConfig) { c.Tailnet = "a/b" },
		"no token":    func(c *TailscaleConfig) { c.APIToken = nil },
		"no lifetime": func(c *TailscaleConfig) { c.MaxLifetime = 0 },
	} {
		c := base
		mutate(&c)
		if _, err := NewTailscaleBackend(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
