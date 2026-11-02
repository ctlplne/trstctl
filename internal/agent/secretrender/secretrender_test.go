// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"bytes"
	"context"
	"errors"
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
)

type fakeSource struct {
	mu       sync.Mutex
	values   map[string]string
	versions map[string]int
	down     bool
}

func (f *fakeSource) set(name, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[name] = value
	f.versions[name]++
}

func (f *fakeSource) Fetch(_ context.Context, name string) ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, 0, errors.New("the control plane could not be reached")
	}
	v, ok := f.values[name]
	if !ok {
		return nil, 0, errors.New("missing")
	}
	return []byte(v), f.versions[name], nil
}

type report struct {
	state   string
	version int
}

type fakeReporter struct {
	mu      sync.Mutex
	reports []report
}

func (f *fakeReporter) Report(_ context.Context, _ string, state string, versions map[string]int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range versions {
		f.reports = append(f.reports, report{state, v})
	}
	return nil
}

func (f *fakeReporter) take() []report {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.reports
	f.reports = nil
	return out
}

// app is an application that reads its password file on every request.
func app(t *testing.T, file string, healthy *atomic.Bool) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		raw, err := os.ReadFile(file) // #nosec G304 -- the test's own temp file (CWE-22)
		user, pass, ok := r.BasicAuth()
		if err != nil || !ok || string(raw) != user+":{PLAIN}"+pass+"\n" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTemplatesAcceptOnlySecretPlaceholdersA238(t *testing.T) {
	segs, names, err := parseTemplate(`user:{{ secret "web/prod/password" }}` + "\n" + `{{secret "web/prod/password"}}`)
	if err != nil || len(names) != 1 || names[0] != "web/prod/password" || len(segs) != 4 {
		t.Fatalf("segments %d names %v err %v", len(segs), names, err)
	}
	for _, bad := range []string{`{{ .Env.HOME }}`, `{{ secret "x" | printf }}`, `{{ exec "id" }}`} {
		if _, _, err := parseTemplate(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestRendererWritesAtomicallyReloadsAndReportsInjectedThenVerifiedA238(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "htpasswd")
	marker := filepath.Join(dir, "reloaded")
	src := &fakeSource{values: map[string]string{}, versions: map[string]int{}}
	src.set("web/prod/password", "pw-one")
	var healthy atomic.Bool
	healthy.Store(true)
	application := app(t, file, &healthy)
	var logs bytes.Buffer
	rep := &fakeReporter{}
	r, err := New(Config{
		Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, "state"),
		Templates: []Template{{
			Name: "htpasswd", Destination: file, Mode: "0440",
			Text:   "app:{PLAIN}{{ secret \"web/prod/password\" }}\n",
			Reload: Hook{Command: []string{"touch", marker}},
			Verify: Verify{URL: application.URL, Username: "app", PasswordSecret: "web/prod/password", Timeout: 2 * time.Second}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		}},
	}, src, rep, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// A reader running through every write must only ever see whole files.
	stop := make(chan struct{})
	var torn atomic.Int32
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if raw, err := os.ReadFile(file); err == nil && !strings.HasPrefix(string(raw), "app:{PLAIN}pw-") { // #nosec G304 -- the test's own temp file (CWE-22)
				torn.Add(1)
			}
		}
	}()
	r.Once(t.Context())
	if raw, _ := os.ReadFile(file); string(raw) != "app:{PLAIN}pw-one\n" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("file %q", raw)
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o440 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the reload hook did not run")
	}
	if got := rep.take(); len(got) != 2 || got[0] != (report{"injected", 1}) || got[1] != (report{"verified", 1}) {
		t.Fatalf("reports %v", got)
	}
	for _, pw := range []string{"pw-two", "pw-three"} {
		src.set("web/prod/password", pw)
		r.Once(t.Context())
		if raw, _ := os.ReadFile(file); string(raw) != "app:{PLAIN}"+pw+"\n" { // #nosec G304 -- the test's own temp file (CWE-22)
			t.Fatalf("after rotation, file %q", raw)
		}
	}
	close(stop)
	if torn.Load() != 0 {
		t.Fatalf("a reader saw %d partial files", torn.Load())
	}
	if got := rep.take(); len(got) != 4 || got[3] != (report{"verified", 3}) {
		t.Fatalf("rotation reports %v", got)
	}
	r.Once(t.Context())
	if got := rep.take(); len(got) != 0 {
		t.Fatalf("an unchanged pass reported %v", got)
	}

	// An application that can't prove it uses the new value leaves the
	// delivery injected, not verified.
	healthy.Store(false)
	src.set("web/prod/password", "pw-four")
	r.Once(t.Context())
	if got := rep.take(); len(got) != 1 || got[0] != (report{"injected", 4}) {
		t.Fatalf("an unverified write reported %v", got)
	}
	healthy.Store(true)
	r.Once(t.Context())
	if got := rep.take(); len(got) != 1 || got[0] != (report{"verified", 4}) {
		t.Fatalf("a later verification reported %v", got)
	}
	for _, pw := range []string{"pw-one", "pw-two", "pw-three", "pw-four"} {
		if strings.Contains(logs.String(), pw) {
			t.Fatalf("a value reached the logs: %s", logs.String())
		}
	}
}

func TestRendererHonorsTheFreshnessBoundAcrossARestartA238(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	marker := filepath.Join(dir, "reloaded")
	src := &fakeSource{values: map[string]string{}, versions: map[string]int{}}
	src.set("api/token", "tok-one")
	cfg := Config{
		Server: "unused", TokenFile: "unused", Consumer: "web-1/app", StateDir: filepath.Join(dir, "state"),
		Freshness: 5 * time.Minute,
		Templates: []Template{{Name: "token", Destination: file, Text: `{{ secret "api/token" }}`,
			Reload: Hook{Command: []string{"touch", marker}}}},
	}
	start := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	r, err := New(cfg, src, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return start }
	r.Once(t.Context())
	if raw, _ := os.ReadFile(file); string(raw) != "tok-one" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("file %q", raw)
	}
	_ = os.Remove(marker)
	src.down = true
	// Within the bound the last value keeps serving.
	r.now = func() time.Time { return start.Add(4 * time.Minute) }
	r.Once(t.Context())
	if _, err := os.Stat(file); err != nil {
		t.Fatal("the file was removed inside its freshness bound")
	}
	// A restarted renderer remembers the fetch time: past the bound, the
	// file goes and the application is reloaded.
	restarted, err := New(cfg, src, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return start.Add(6 * time.Minute) }
	restarted.Once(t.Context())
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("a file past its freshness bound survived a restart")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("removing the stale file did not reload the application")
	}
	// The control plane comes back: the file is written again.
	src.down = false
	restarted.Once(t.Context())
	if raw, _ := os.ReadFile(file); string(raw) != "tok-one" { // #nosec G304 -- the test's own temp file (CWE-22)
		t.Fatalf("after recovery, file %q", raw)
	}
}

func TestRendererRefusesUnsafeConfigurationA238(t *testing.T) {
	base := Config{Server: "s", TokenFile: "t", Consumer: "c", StateDir: t.TempDir()}
	for name, tpl := range map[string]Template{
		"relative":     {Name: "a", Destination: "relative/path", Text: "x"},
		"others-mode":  {Name: "a", Destination: "/tmp/a", Text: "x", Mode: "0644"},
		"bad-on-stale": {Name: "a", Destination: "/tmp/a", Text: "x", OnStale: "panic"},
		"both-reloads": {Name: "a", Destination: "/tmp/a", Text: "x", Reload: Hook{Command: []string{"true"}, Signal: "HUP", PIDFile: "/p"}},
		"bad-signal":   {Name: "a", Destination: "/tmp/a", Text: "x", Reload: Hook{Signal: "KILL", PIDFile: "/p"}},
	} {
		cfg := base
		cfg.Templates = []Template{tpl}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
