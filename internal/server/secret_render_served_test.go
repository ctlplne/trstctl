// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/secretrender"
	"trstctl.com/trstctl/internal/config"
)

// A238: an application keeps serving through two rotations of the password the
// agent renders for it — atomic writes with the file's mode, the reload hook,
// the old value refused once replaced — and the control plane keeps "injected"
// apart from "application verified". A control-plane outage keeps the last file
// only until the freshness bound, across a restart; logs carry no values.
// With TRSTCTL_A238_LAB_NGINX_URL, TRSTCTL_A238_LAB_NGINX_CONTAINER and
// TRSTCTL_A238_LAB_AUTH_DIR the application is a real nginx container reading
// the rendered htpasswd (runners/a238-nginx-lab-proof.sh).
func TestServedSecretRenderKeepsAnApplicationServingThroughRotationsA238(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A238 render tenant")
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a238-operator", "secrets:read", "secrets:write")
	consumerToken := seedScopedTokenSubject(t, h.store, h.tenant, "web-1-agent", "secrets:read")
	const name = "web238/prod/password"
	rotate := func(method, value string) {
		t.Helper()
		path, body, want := "/api/v1/secrets/store", map[string]any{"name": name, "value": value}, http.StatusCreated
		if method == http.MethodPut {
			path, body, want = "/api/v1/secrets/store/"+name, map[string]any{"value": value}, http.StatusOK
		}
		if status, raw := secretsReqKey(t, h, method, path, operator, "a238-"+value, body); status != want {
			t.Fatalf("%s %s: HTTP %d %s", method, value, status, raw)
		}
	}
	rotate(http.MethodPost, "render-pw-one")

	dir := t.TempDir()
	file := filepath.Join(dir, "htpasswd")
	reload := []string{"touch", filepath.Join(dir, "reloaded")}
	appURL := ""
	var healthy atomic.Bool
	healthy.Store(true)
	if labURL := os.Getenv("TRSTCTL_A238_LAB_NGINX_URL"); labURL != "" {
		dir = os.Getenv("TRSTCTL_A238_LAB_AUTH_DIR")
		file = filepath.Join(dir, "htpasswd")
		reload = []string{"docker", "kill", "-s", "HUP", os.Getenv("TRSTCTL_A238_LAB_NGINX_CONTAINER")}
		appURL = labURL
		t.Logf("A238 lab mode: nginx at %s", labURL)
	} else {
		application := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !healthy.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			raw, err := os.ReadFile(file) // #nosec G304 G703 -- the test's own temp file or the lab directory the runner created (CWE-22)
			user, pass, ok := r.BasicAuth()
			if err != nil || !ok || !bytes.Contains(raw, []byte(user+":{PLAIN}"+pass+"\n")) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(application.Close)
		appURL = application.URL
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(consumerToken), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logs.Write(p)
	}), nil))
	cfg := secretrender.Config{
		Server: h.ts.URL, TokenFile: tokenFile, Consumer: "web-1/app", StateDir: filepath.Join(t.TempDir(), "state"),
		Freshness: 2 * time.Second,
		Templates: []secretrender.Template{{
			Name: "htpasswd", Destination: file, Mode: "0440",
			Text:   "app:{PLAIN}{{ secret \"" + name + "\" }}\n",
			Reload: secretrender.Hook{Command: reload},
			Verify: secretrender.Verify{URL: appURL, Username: "app", PasswordSecret: name, Timeout: 5 * time.Second},
		}},
	}
	renderer := func(server string) *secretrender.Renderer {
		t.Helper()
		c := cfg
		c.Server = server
		client, err := secretrender.NewHTTPClient(server, "", tokenFile, &http.Client{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		r, err := secretrender.New(c, client, client, logger)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	type deliveries struct {
		CurrentVersion int `json:"current_version"`
		Consumers      []struct {
			Consumer        string `json:"consumer"`
			InjectedVersion int    `json:"injected_version"`
			VerifiedVersion int    `json:"verified_version"`
			State           string `json:"state"`
		} `json:"consumers"`
	}
	delivered := func() deliveries {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/deliveries?name="+name, operator, nil)
		var d deliveries
		if status != http.StatusOK || json.Unmarshal(raw, &d) != nil || len(d.Consumers) != 1 {
			t.Fatalf("deliveries: HTTP %d %s", status, raw)
		}
		return d
	}
	login := func(password string) int {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, appURL, nil) // #nosec G704 -- the test application or the lab nginx on loopback (CWE-918)
		req.SetBasicAuth("app", password)
		resp, err := http.DefaultClient.Do(req) // #nosec G704 -- the test application or the lab nginx on loopback (CWE-918)
		if err != nil {
			return 0
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	r := renderer(h.ts.URL)
	r.Once(t.Context())
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o440 { // #nosec G703 -- the test's own temp file or the lab directory the runner created (CWE-22)
		t.Fatalf("rendered file: %v %v", info, err)
	}
	if d := delivered(); d.Consumers[0].State != "verified" || d.Consumers[0].VerifiedVersion != 1 {
		t.Fatalf("first delivery: %+v", d)
	}

	// From here a client keeps calling the application with the current
	// password; through both rotations it must never fail to answer.
	var current atomic.Value
	current.Store("render-pw-one")
	var outages, calls atomic.Int32
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			calls.Add(1)
			if code := login(current.Load().(string)); code == 0 || code >= 500 && healthy.Load() {
				outages.Add(1)
			}
		}
	}()
	previous := "render-pw-one"
	for i, pw := range []string{"render-pw-two", "render-pw-three"} {
		time.Sleep(500 * time.Millisecond)
		rotate(http.MethodPut, pw)
		r.Once(t.Context())
		current.Store(pw)
		time.Sleep(500 * time.Millisecond)
		if code := login(pw); code != http.StatusOK {
			t.Fatalf("rotation %d: the new password answers %d", i+1, code)
		}
		if code := login(previous); code != http.StatusUnauthorized {
			t.Fatalf("rotation %d: the retired password answers %d", i+1, code)
		}
		if d := delivered(); d.Consumers[0].State != "verified" || d.Consumers[0].VerifiedVersion != i+2 {
			t.Fatalf("rotation %d delivery: %+v", i+1, d)
		}
		previous = pw
	}
	close(stop)
	<-done
	if outages.Load() != 0 || calls.Load() < 50 {
		t.Fatalf("the application failed to answer %d of %d calls during the rotations", outages.Load(), calls.Load())
	}
	t.Logf("through two rotations: %d calls, 0 unanswered", calls.Load())

	// Injected is not verified: an application that can't prove it uses the
	// new value leaves the delivery injected only.
	if os.Getenv("TRSTCTL_A238_LAB_NGINX_URL") == "" {
		healthy.Store(false)
		rotate(http.MethodPut, "render-pw-four")
		r.Once(t.Context())
		if d := delivered(); d.Consumers[0].State != "injected" || d.Consumers[0].InjectedVersion != 4 || d.Consumers[0].VerifiedVersion != 3 {
			t.Fatalf("an unverified write: %+v", d)
		}
		healthy.Store(true)
		r.Once(t.Context())
		if d := delivered(); d.Consumers[0].State != "verified" {
			t.Fatalf("a later verification: %+v", d)
		}
	}

	// A control-plane outage: the last file serves until the freshness bound,
	// then goes; a restarted agent writes it again.
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	down := renderer(closedURL)
	down.Once(t.Context())
	if _, err := os.Stat(file); err != nil { // #nosec G703 -- the test's own temp file or the lab directory the runner created (CWE-22)
		t.Fatal("the file was removed inside its freshness bound")
	}
	time.Sleep(2200 * time.Millisecond)
	down.Once(t.Context())
	if _, err := os.Stat(file); !os.IsNotExist(err) { // #nosec G703 -- the test's own temp file or the lab directory the runner created (CWE-22)
		t.Fatal("the file outlived its freshness bound during the outage")
	}
	if code := login(current.Load().(string)); code == http.StatusOK {
		t.Fatal("the application still accepted the password after the stale file was removed")
	}
	renderer(h.ts.URL).Once(t.Context())
	if _, err := os.Stat(file); err != nil { // #nosec G703 -- the test's own temp file or the lab directory the runner created (CWE-22)
		t.Fatal("the restarted agent did not write the file again")
	}

	logMu.Lock()
	logged := logs.String()
	logMu.Unlock()
	for _, pw := range []string{"render-pw-one", "render-pw-two", "render-pw-three", "render-pw-four"} {
		if strings.Contains(logged, pw) || h.logContains(t, pw) {
			t.Fatalf("a value reached the logs (%s)", pw)
		}
	}
	t.Logf("A238_RENDER_OK")
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
