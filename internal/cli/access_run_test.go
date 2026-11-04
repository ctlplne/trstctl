// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/cli"
)

type accessRunServer struct {
	mu       sync.Mutex
	requests []string
	minted   map[string]any
	keys     []string
}

func (s *accessRunServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		if key := r.Header.Get("Idempotency-Key"); key != "" {
			s.keys = append(s.keys, key)
		}
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/access/bundles":
			_, _ = io.WriteString(w, `{"items":[{"id":"7d034937-5c19-45e0-ad7a-2d6cffbaa1c8","name":"deploy"},{"id":"0b1a2c3d-0000-4000-8000-000000000002","name":"owners"}]}`)
		case "POST /api/v1/access/runs":
			if err := json.Unmarshal(body, &s.minted); err != nil {
				t.Errorf("mint body: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"run":{"id":"9e0f0000-0000-4000-8000-000000000009","expires_at":"2026-11-04T05:00:00Z"},"token":"trst_run-token-value"}`)
		case "POST /api/v1/access/runs/9e0f0000-0000-4000-8000-000000000009/revoke":
			_, _ = io.WriteString(w, `{"id":"9e0f0000-0000-4000-8000-000000000009","status":"revoked"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"title":"not found"}`)
		}
	}
}

// A251: `access run` mints a run under the named bundles (by name or ID), gives
// the child only the run's token, keeps the caller's own token out of the
// child, never prints the run's token, and revokes the run when the child
// exits.
func TestAccessRunGivesTheChildOnlyTheRunTokenAndRevokesIt(t *testing.T) {
	envPath, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env command not available")
	}
	t.Setenv("TRSTCTL_TOKEN", "parent-bearer-from-env")
	s := &accessRunServer{}
	srv := httptest.NewServer(s.handler(t))
	t.Cleanup(srv.Close)
	code, stdout, stderr := run(t, []string{"access", "run", "--bundle", "deploy", "--bundle", "0b1a2c3d-0000-4000-8000-000000000002",
		"--ttl", "10m", "--label", "deploy #42", "--", envPath}, cli.Env{Server: srv.URL, Token: "machine-token", HTTPClient: srv.Client()}, "")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "TRSTCTL_TOKEN=trst_run-token-value") || strings.Contains(stdout, "machine-token") ||
		strings.Contains(stdout, "parent-bearer-from-env") || !strings.Contains(stdout, "TRSTCTL_SERVER="+srv.URL) {
		t.Fatalf("child environment:\n%s", stdout)
	}
	if strings.Contains(stderr, "trst_run-token-value") || !strings.Contains(stderr, "revoked") {
		t.Fatalf("stderr = %q", stderr)
	}
	ids, _ := s.minted["bundle_ids"].([]any)
	if len(ids) != 2 || ids[0] != "7d034937-5c19-45e0-ad7a-2d6cffbaa1c8" || s.minted["ttl_seconds"] != float64(600) || s.minted["label"] != "deploy #42" {
		t.Fatalf("mint request = %+v", s.minted)
	}
	want := []string{
		"GET /api/v1/access/bundles Bearer machine-token",
		"POST /api/v1/access/runs Bearer machine-token",
		"POST /api/v1/access/runs/9e0f0000-0000-4000-8000-000000000009/revoke Bearer machine-token",
	}
	if strings.Join(s.requests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s", strings.Join(s.requests, "\n"))
	}
	if len(s.keys) != 2 || s.keys[0] == s.keys[1] {
		t.Fatalf("each mutation needs its own Idempotency-Key: %v", s.keys)
	}
}

func TestAccessRunKeepsTheRunAndPassesTheExitCode(t *testing.T) {
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	s := &accessRunServer{}
	srv := httptest.NewServer(s.handler(t))
	t.Cleanup(srv.Close)
	code, _, stderr := run(t, []string{"access", "run", "--bundle", "deploy", "--keep", "--", shPath, "-c", "exit 7"},
		cli.Env{Server: srv.URL, Token: "machine-token", HTTPClient: srv.Client()}, "")
	if code != 7 {
		t.Fatalf("exit = %d, want 7; stderr = %s", code, stderr)
	}
	for _, req := range s.requests {
		if strings.Contains(req, "/revoke") {
			t.Fatalf("--keep revoked the run: %v", s.requests)
		}
	}
	code, _, stderr = run(t, []string{"access", "run", "--bundle", "nope", "--", shPath, "-c", "exit 0"},
		cli.Env{Server: srv.URL, Token: "machine-token", HTTPClient: srv.Client()}, "")
	if code != 1 || !strings.Contains(stderr, `no live access bundle named "nope"`) {
		t.Fatalf("unknown bundle: exit = %d stderr = %s", code, stderr)
	}
	if code, _, _ := run(t, []string{"access", "run", "--", shPath}, cli.Env{Server: srv.URL}, ""); code != 2 {
		t.Fatalf("no --bundle: exit = %d, want 2", code)
	}
}

func TestAccessActivityExportIsItsOwnCommand(t *testing.T) {
	var cap capture
	srv := mockServer(t, 200, `{"kind":"trstctl.access-activity-export/v1","items":[]}`, &cap)
	code, _, stderr := run(t, []string{"access", "activity", "export", "--principal", "ci:deploy"}, cli.Env{Server: srv.URL, HTTPClient: srv.Client()}, "")
	if code != 0 || cap.Path != "/api/v1/access/activity/export" || cap.Query != "principal=ci%3Adeploy" {
		t.Fatalf("exit=%d path=%s query=%s stderr=%s", code, cap.Path, cap.Query, stderr)
	}
}
