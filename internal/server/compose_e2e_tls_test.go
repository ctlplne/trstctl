//go:build !windows

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// These are stock-client transport regressions, not PostgreSQL, lifecycle or
// independent signing-authority proof. TLS uses the real serveControlPlane path.
type composeTLSFixture struct {
	base, trust  string
	requests     atomic.Int32
	partialReady atomic.Bool
}

func startComposeTLSFixture(t *testing.T, localhostOnly, plaintext bool) *composeTLSFixture {
	t.Helper()
	dir := t.TempDir()
	f := &composeTLSFixture{trust: filepath.Join(dir, "public.crt")}
	state := filepath.Join(dir, "private.pem")
	cfg := config.TLS{Mode: config.TLSInternal, InternalStateFile: state, InternalTrustFile: f.trust}
	if localhostOnly || plaintext {
		cert, err := mtls.LoadOrCreateSelfSignedServerCert(state, []string{"localhost"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.trust, cert.TrustPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg = config.TLS{Mode: config.TLSFile, CertFile: state, KeyFile: state}
	}
	if plaintext {
		cfg.Mode = config.TLSDisabled
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.base = "https://" + ln.Addr().String()
	if plaintext {
		f.base = "http://" + ln.Addr().String()
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true) // A short Content-Length must produce curl's code 18.
	srv := &http.Server{
		ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 2 * time.Second,
		Protocols: protocols, ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.requests.Add(1)
			if r.Method == http.MethodPost && (r.Header.Get("Idempotency-Key") != "fixture-key" || r.Header.Get("Authorization") != "Bearer fixture-token") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.URL.Path == "/unauthorized" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.URL.Path == "/stall" {
				<-r.Context().Done()
				return
			}
			if r.URL.Path == "/short" || (r.URL.Path == "/readyz" && f.partialReady.Load()) {
				w.Header().Set("Content-Length", "64")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		}),
	}
	done := make(chan error, 1)
	go func() { done <- serveControlPlane(srv, ln, cfg, io.Discard) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("serveControlPlane shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("owned TLS server did not stop")
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(f.trust); err == nil && st.Size() > 0 {
			return f
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("serveControlPlane did not publish public trust")
	return nil
}

type composeCurlResult struct {
	stdout, stderr string
	exit           int
	elapsed        time.Duration
}

type composeCurlOutput struct{ bytes.Buffer }

func (b *composeCurlOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("fixture output exceeded 64 KiB")
	}
	return b.Buffer.Write(p)
}

func runComposeCurl(t *testing.T, mode, base, trust, path, curlrc string) composeCurlResult {
	t.Helper()
	for _, tool := range []string{"bash", "curl", "openssl", "awk"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("stock-client regression requires %s: %v", tool, err)
		}
	}
	raw, err := os.ReadFile("../../scripts/ci/compose-e2e.sh")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, ok := strings.Cut(string(raw), "\nsay \"1. control plane is serving (/readyz)\"")
	if !ok {
		t.Fatal("cannot isolate shipped Compose initialization/request functions")
	}
	// Keep the actual old/new shell bytes. This test file alone can be applied to
	// the vulnerable revision: its -k and swallowed native exits must then fail
	// the same wrong-CA, wrong-host and short-response assertions below.
	dir := t.TempDir()
	if helper, err := os.ReadFile("../../scripts/ci/compose-e2e-tls.sh"); err == nil {
		if err := os.WriteFile(filepath.Join(dir, "compose-e2e-tls.sh"), helper, 0o600); err != nil { // #nosec G703 -- fixed helper filename below this test's private t.TempDir; source bytes are never a path (CWE-22).
			t.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".curlrc"), []byte(curlrc), 0o600); err != nil {
		t.Fatal(err)
	}
	var call string
	switch mode {
	case "get":
		call = `"${CURL[@]}" "$BASE_URL$1"`
	case "status":
		call = `"${Q[@]}" "$BASE_URL$1"`
	case "post":
		call = `post fixture-key "$1" '{"probe":true}'`
	case "ready":
		call = `compose_e2e_wait_ready "$BASE_URL$1" "$((SECONDS + 1))"`
	case "ready_zero":
		// Advance the real Bash clock at the exact pre-dispatch boundary. The
		// native curl must never be invoked with a computed zero timeout.
		call = `set -T
trap 'if [[ "$BASH_COMMAND" == "remaining="* ]]; then SECONDS=$deadline; trap - DEBUG; fi' DEBUG
compose_e2e_wait_ready "$BASE_URL$1" "$((SECONDS + 1))"`
	case "ready_late":
		// A real successful stock-curl response is retained, but the clock
		// advances before its completion is admitted as readiness.
		call = `set -T
trap 'if [[ "${code:-}" == 200 ]]; then SECONDS=$deadline; trap - DEBUG; fi' DEBUG
compose_e2e_wait_ready "$BASE_URL$1" "$((SECONDS + 1))"`
	case "copy_zero":
		workflow, err := os.ReadFile("../../.github/workflows/ci.yml")
		if err != nil {
			t.Fatal(err)
		}
		_, job, ok := strings.Cut(string(workflow), "\n  compose-e2e:")
		if !ok {
			t.Fatal("Compose CI job missing")
		}
		_, loop, ok := strings.Cut(job, "          deadline=$((SECONDS + 180))\n")
		if !ok {
			t.Fatal("CI public-copy deadline missing")
		}
		loop, _, ok = strings.Cut(loop, "          if [[ -z \"$copied\" ]]; then")
		if !ok {
			t.Fatal("CI public-copy loop end missing")
		}
		var lines []string
		for _, line := range strings.Split(loop, "\n") {
			lines = append(lines, strings.TrimPrefix(line, "          "))
		}
		// The command spy only proves no dispatch at this boundary. It is
		// not a Docker, GNU timeout, TLS, or successful-creation receipt.
		call = `trustdir="$tmpdir"
timeout() { printf 'unexpected timeout dispatch: %s\n' "$*" >&2; return 99; }
deadline=$((SECONDS + 1))
set -T
trap 'if [[ "$BASH_COMMAND" == "remaining="* ]]; then SECONDS=$deadline; trap - DEBUG; fi' DEBUG
` + strings.Join(lines, "\n") + `
cat "$trustdir/copy.log" 2>/dev/null || true
printf 'copy loop ended\n'`
	case "main_ready":
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, `code=$("${Q[@]}" "$BASE_URL/readyz"`) && i+1 < len(lines) {
				call = line + "\n" + lines[i+1]
				break
			}
		}
		if call == "" {
			t.Fatal("actual /readyz status/transport guard is missing")
		}
	default:
		t.Fatalf("invalid fixed request mode %q", mode)
	}
	script := filepath.Join(dir, "request.sh")
	if err := os.WriteFile(script, []byte(prefix+"\nAUTH=(-H 'Authorization: Bearer fixture-token')\n"+call+"\n"), 0o600); err != nil { // #nosec G703 -- fixed script filename below this test's private t.TempDir; test call text is file content, never a path (CWE-22).
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script, path) // #nosec G204 -- exact shipped prefix plus fixed test invocation, only owned loopback listeners (CWE-78).
	// Inherit the test supervisor's process group. No detached shell or curl.
	// Curl's normal 30s bound is below this 40s parent bound; the outer fixture
	// supervisor remains responsible for whole-group cancellation.
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "CURL_HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "TMPDIR=" + dir,
		"BASE_URL=" + base, "COMPOSE_E2E_CA_FILE=" + trust,
		"TENANT=11111111-1111-4111-8111-111111111111", "IDEM_BASE=fixture",
	}
	var stdout, stderr composeCurlOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err = cmd.Run()
	result := composeCurlResult{stdout: stdout.String(), stderr: stderr.String(), elapsed: time.Since(start)}
	if ctx.Err() != nil {
		t.Fatalf("stock curl exceeded outer test deadline: %v; %s", ctx.Err(), result.stderr)
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("execute shipped client: %v", err)
		}
		result.exit = exit.ExitCode()
	}
	return result
}

func requireComposePositive(t *testing.T, f *composeTLSFixture, base string) {
	t.Helper()
	for _, mode := range []string{"get", "status", "post", "main_ready"} {
		r := runComposeCurl(t, mode, base, f.trust, "/ok", "")
		if r.exit != 0 {
			t.Fatalf("healthy %s failed: exit=%d stdout=%s stderr=%s", mode, r.exit, r.stdout, r.stderr)
		}
		if (mode == "get" || mode == "post") && r.stdout != `{"ok":true}` {
			t.Fatalf("healthy %s body=%q", mode, r.stdout)
		}
		if mode == "status" && r.stdout != "200" {
			t.Fatalf("healthy status=%q", r.stdout)
		}
	}
}

func TestComposeE2EStockCurlTrustAndHostname(t *testing.T) {
	for _, wrongHost := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrongHost=%v", wrongHost), func(t *testing.T) {
			f := startComposeTLSFixture(t, wrongHost, false)
			goodURL := f.base
			if wrongHost {
				goodURL = strings.Replace(f.base, "127.0.0.1", "localhost", 1)
			}
			requireComposePositive(t, f, goodURL)
			badTrust := f.trust
			if !wrongHost {
				other, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				badTrust = filepath.Join(t.TempDir(), "other.crt")
				if err := os.WriteFile(badTrust, other.TrustPEM, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, mode := range []string{"get", "status", "post", "main_ready"} {
				for _, curlrc := range []string{"", "insecure\n"} {
					before := f.requests.Load()
					r := runComposeCurl(t, mode, f.base, badTrust, "/ok", curlrc)
					if r.exit == 0 || !strings.Contains(r.stderr, "curl: (60)") {
						t.Errorf("%s curlrc=%q did not reject peer verification: exit=%d stdout=%s stderr=%s", mode, curlrc, r.exit, r.stdout, r.stderr)
					}
					if got := f.requests.Load(); got != before {
						t.Errorf("unverified %s reached the HTTP handler: before=%d after=%d", mode, before, got)
					}
				}
			}
			requireComposePositive(t, f, goodURL)
		})
	}
}

func TestComposeE2EStockCurlRejectsPartialSuccess(t *testing.T) {
	f := startComposeTLSFixture(t, false, false)
	requireComposePositive(t, f, f.base)
	r := runComposeCurl(t, "post", f.base, f.trust, "/short", "")
	if r.exit != 18 || !strings.Contains(r.stderr, "curl: (18)") || r.stdout != "" {
		t.Errorf("partial HTTP 200 POST accepted: exit=%d stdout=%s stderr=%s", r.exit, r.stdout, r.stderr)
	}
	f.partialReady.Store(true)
	r = runComposeCurl(t, "main_ready", f.base, f.trust, "/readyz", "")
	if r.exit == 0 || !strings.Contains(r.stderr, "curl: (18)") {
		t.Errorf("actual /readyz guard accepted partial 200: %+v", r)
	}
	f.partialReady.Store(false)
	requireComposePositive(t, f, f.base)
}

func TestComposeE2EStockCurlPreservesUnauthorizedStatus(t *testing.T) {
	f := startComposeTLSFixture(t, false, false)
	r := runComposeCurl(t, "status", f.base, f.trust, "/unauthorized", "")
	if r.exit != 0 || r.stdout != "401" {
		t.Fatalf("verified HTTP 401 lost: %+v", r)
	}
}

func TestComposeE2EStockCurlRejectsHTTPAndInvalidTrust(t *testing.T) {
	plain := startComposeTLSFixture(t, false, true)
	for _, mode := range []string{"get", "status", "post", "main_ready"} {
		r := runComposeCurl(t, mode, plain.base, plain.trust, "/ok", "")
		if r.exit == 0 || !strings.Contains(r.stderr, "https://") {
			t.Errorf("cleartext %s accepted: %+v", mode, r)
		}
	}
	if plain.requests.Load() != 0 {
		t.Error("cleartext rejection happened after an HTTP request")
	}
	f := startComposeTLSFixture(t, false, false)
	public, err := os.ReadFile(f.trust)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{nil, []byte("not a certificate"), append(append([]byte{}, public...), []byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n")...)} {
		trust := filepath.Join(t.TempDir(), "invalid.pem")
		if err := os.WriteFile(trust, content, 0o600); err != nil { // #nosec G703 -- fixed invalid.pem filename below this test's private t.TempDir; deliberately invalid public fixture bytes are content only (CWE-22).
			t.Fatal(err)
		}
		r := runComposeCurl(t, "post", f.base, trust, "/ok", "")
		if r.exit == 0 {
			t.Errorf("invalid/private trust accepted: %+v", r)
		}
	}
	r := runComposeCurl(t, "post", f.base, filepath.Join(t.TempDir(), "missing.crt"), "/ok", "")
	if r.exit == 0 {
		t.Errorf("missing trust accepted: %+v", r)
	}
	if f.requests.Load() != 0 {
		t.Error("invalid trust reached an HTTP handler")
	}
}

func TestComposeE2EStockCurlReadinessDeadline(t *testing.T) {
	f := startComposeTLSFixture(t, false, false)
	r := runComposeCurl(t, "ready", f.base, f.trust, "/readyz", "")
	if r.exit != 0 {
		t.Fatalf("verified readiness positive failed: %+v", r)
	}
	r = runComposeCurl(t, "ready", f.base, f.trust, "/stall", "")
	if r.exit == 0 || !strings.Contains(r.stderr, "curl: (28)") || !strings.Contains(r.stderr, "readiness deadline expired") || r.elapsed > 4*time.Second {
		t.Fatalf("readiness failed to clamp curl to remaining budget: %+v", r)
	}
}

func TestComposeE2EStockCurlReadinessRejectsPeer(t *testing.T) {
	f := startComposeTLSFixture(t, true, false)
	goodURL := strings.Replace(f.base, "127.0.0.1", "localhost", 1)
	r := runComposeCurl(t, "ready", goodURL, f.trust, "/readyz", "")
	if r.exit != 0 {
		t.Fatalf("healthy readiness failed: %+v", r)
	}
	other, err := mtls.SelfSignedServerCert([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wrongCA := filepath.Join(t.TempDir(), "other.crt")
	if err := os.WriteFile(wrongCA, other.TrustPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []struct{ base, trust string }{{f.base, f.trust}, {goodURL, wrongCA}} {
		before := f.requests.Load()
		r = runComposeCurl(t, "ready", peer.base, peer.trust, "/readyz", "insecure\n")
		if r.exit != 60 || !strings.Contains(r.stderr, "curl: (60)") || f.requests.Load() != before {
			t.Errorf("readiness accepted unverified peer or reached handler: %+v", r)
		}
	}
	r = runComposeCurl(t, "ready", goodURL, f.trust, "/readyz", "")
	if r.exit != 0 {
		t.Fatalf("healthy readiness failed after negative probes: %+v", r)
	}
}

func TestComposeE2EStockCurlZeroRemainingDoesNotDispatch(t *testing.T) {
	f := startComposeTLSFixture(t, false, false)
	before := f.requests.Load()
	r := runComposeCurl(t, "ready_zero", f.base, f.trust, "/readyz", "")
	if r.exit == 0 || !strings.Contains(r.stderr, "readiness deadline expired") || f.requests.Load() != before {
		t.Fatalf("zero remaining readiness dispatched curl or admitted success: %+v", r)
	}
	r = runComposeCurl(t, "copy_zero", f.base, f.trust, "/readyz", "")
	if r.exit != 0 || r.stdout != "copy loop ended\n" || strings.Contains(r.stderr, "unexpected timeout dispatch") {
		t.Fatalf("CI copy dispatched a zero timeout: %+v", r)
	}
}

func TestComposeE2EStockCurlLateReadinessIsNotSuccess(t *testing.T) {
	f := startComposeTLSFixture(t, false, false)
	before := f.requests.Load()
	r := runComposeCurl(t, "ready_late", f.base, f.trust, "/readyz", "")
	if r.exit == 0 || !strings.Contains(r.stderr, "readiness deadline expired") || f.requests.Load() != before+1 {
		t.Fatalf("late real HTTP 200 was accepted or never served: %+v", r)
	}
}
