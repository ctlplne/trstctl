// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// downloadRetry is the curl retry every Security-scan download carries: a
// failed transfer is retried six times, ten seconds apart, inside the job's
// time limit (the convention scripts/supply-chain/verify-embedded-postgres.sh
// set after curl 56 on CI run 41471582079).
const downloadRetry = "curl -fsSL --retry 6 --retry-all-errors --retry-delay 10 --connect-timeout 30 --max-time 300 "

// installerFetch is the installer's download function, the only place it
// calls curl.
func installerFetch(t *testing.T, installer string) string {
	t.Helper()
	start := strings.Index(installer, "\nfetch() {\n")
	if start < 0 {
		t.Fatal("tools/gitleaks/install.sh has no fetch function, so its downloads are not retried")
	}
	end := strings.Index(installer[start+1:], "\n}\n")
	if end < 0 {
		t.Fatal("tools/gitleaks/install.sh: unterminated fetch function")
	}
	fn := installer[start+1 : start+1+end+3]
	if !strings.Contains(fn, downloadRetry) {
		t.Fatalf("the installer's fetch does not retry as %q:\n%s", downloadRetry, fn)
	}
	if strings.Count(installer, "curl ") != 1 {
		t.Fatal("tools/gitleaks/install.sh calls curl outside fetch, so that download is not retried")
	}
	return fn
}

// The Security scans install gitleaks with tools/gitleaks/install.sh and
// Trivy from its release page, and GitHub's release downloads answer 5xx in
// bursts: on 2026-11-08 a 504 failed the gitleaks job, and so its secret
// scan, twice. Every such download now retries a failed transfer a bounded
// number of times. This runs the installer's own fetch against a server that
// answers 504 twice, and one that never recovers.
func TestSecurityScanDownloadsRetryAFailedTransfer(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	fn := installerFetch(t, readRepoFile(t, root, "tools/gitleaks/install.sh"))
	workflow := readRepoFile(t, root, ".github/workflows/security.yml")
	if downloads, retried := strings.Count(workflow, "curl "), strings.Count(workflow, downloadRetry); downloads == 0 || downloads != retried {
		t.Fatalf("security.yml has %d downloads and %d of them retry as %q", downloads, retried, downloadRetry)
	}
	if runtime.GOOS == "windows" {
		t.Skip("the installer is a bash script for the Linux and macOS runners")
	}
	for _, tool := range []string{"bash", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed: %v", tool, err)
		}
	}

	var flaky, down atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/flaky" && flaky.Add(1) > 2 {
			_, _ = w.Write([]byte("release asset"))
			return
		}
		if r.URL.Path == "/down" {
			down.Add(1)
		}
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	// The shipped function, waiting one second between tries instead of ten.
	dir := t.TempDir()
	script := filepath.Join(dir, "fetch.sh")
	quick := strings.Replace(fn, "--retry-delay 10", "--retry-delay 1", 1)
	if err := os.WriteFile(script, []byte("set -euo pipefail\n"+quick+"fetch \"$1\" \"$2\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fetch := func(path, out string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", script, srv.URL+path, out) // #nosec G204 -- the test's own script, against its own server (CWE-78)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Logf("fetch %s: %v\n%s", path, err, output)
			return err
		}
		return nil
	}
	asset := filepath.Join(dir, "asset")
	if err := fetch("/flaky", asset); err != nil {
		t.Fatalf("a download that answered 504 twice was not retried: %v", err)
	}
	if body, err := os.ReadFile(asset); err != nil || string(body) != "release asset" { // #nosec G304 -- the test's own temporary file (CWE-22)
		t.Fatalf("the retried download wrote %q, %v", body, err)
	}
	if tries := flaky.Load(); tries != 3 {
		t.Fatalf("the download was tried %d times, want 3", tries)
	}
	if err := fetch("/down", filepath.Join(dir, "never")); err == nil {
		t.Fatal("a download that never recovered succeeded")
	}
	if tries := down.Load(); tries != 7 {
		t.Fatalf("a download that never recovered was tried %d times, want 7 (one and six retries)", tries)
	}
}

// registryRetry is how every container registry operation in the Security
// scans runs: through scripts/ci/retry-registry-errors.sh.
const registryRetry = "bash scripts/ci/retry-registry-errors.sh "

// registryCommand is a docker command that reaches a registry.
var registryCommand = regexp.MustCompile(`\bdocker (build|buildx|pull)\b`)

// The Trivy job builds the runtime image before it scans it, and the build
// pulls its stages' images from Docker Hub, which answered 500 on 2026-11-12
// (Security scans run 43163959685): the job failed and nothing was scanned.
// Every registry operation in security.yml now runs through
// scripts/ci/retry-registry-errors.sh. This runs the shipped wrapper around a
// stand-in docker that fails the way the registry did: a registry error is
// retried a bounded number of times, any other failure is not, and the
// command's standard output (the base image's digest) passes through clean.
func TestSecurityScanRegistryOperationsRetryARegistryError(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	workflow := readRepoFile(t, root, ".github/workflows/security.yml")
	calls := 0
	for i, line := range strings.Split(workflow, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, loc := range registryCommand.FindAllStringIndex(line, -1) {
			calls++
			if !strings.HasSuffix(line[:loc[0]], registryRetry) {
				t.Errorf("security.yml line %d reaches a registry without retrying a registry error: %s", i+1, strings.TrimSpace(line))
			}
		}
	}
	if calls == 0 {
		t.Fatal("security.yml builds no image, so the image scan has nothing to scan")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the wrapper is a bash script for the Linux and macOS runners")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash is not installed: %v", err)
	}

	// A stand-in docker that fails as the registry did, as a broken build
	// does, or as a missing image does, counting its runs.
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := `#!/usr/bin/env bash
n=$(( $(cat "$STUB_COUNT" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$STUB_COUNT"
echo "$*" > "$STUB_ARGS"
case "$STUB_MODE" in
  flaky)
    if [ "$n" -le 2 ]; then
      echo "ERROR: failed to build: failed to solve: node:22-bookworm-slim: unexpected status from HEAD request to https://registry-1.docker.io/v2/library/node/manifests/22-bookworm-slim: 500 Internal Server Error" >&2
      exit 1
    fi
    echo "sha256:feed" ;;
  down) echo "ERROR: unexpected status code https://registry-1.docker.io/v2/library/golang/blobs/sha256:5123: 503 Service Unavailable" >&2; exit 1 ;;
  missing) echo "ERROR: unexpected status from HEAD request to https://registry-1.docker.io/v2/library/node/manifests/sha256:512abc: 404 Not Found" >&2; exit 1 ;;
  broken) echo "ERROR: process \"/bin/sh -c go build ./cmd/trstctl\" did not complete successfully: exit code: 1" >&2; exit 7 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
		t.Fatal(err)
	}
	wrapper := filepath.Join(root, "scripts", "ci", "retry-registry-errors.sh")
	run := func(mode string) (string, int, error) {
		t.Helper()
		count := filepath.Join(dir, mode+".count")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", wrapper, "docker", "build", "--target", "release", "-t", "trstctl:ci-scan", ".") // #nosec G204 -- the shipped wrapper around the test's own stand-in (CWE-78)
		cmd.Env = append(os.Environ(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"STUB_MODE="+mode, "STUB_COUNT="+count, "STUB_ARGS="+filepath.Join(dir, mode+".args"),
			"TRSTCTL_REGISTRY_RETRY_DELAY=0")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if err != nil {
			t.Logf("%s: %v\n%s", mode, err, stderr.String())
		}
		raw, _ := os.ReadFile(count) // #nosec G304 -- the test's own temporary file (CWE-22)
		runs, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		return stdout.String(), runs, err
	}

	out, runs, err := run("flaky")
	if err != nil || runs != 3 {
		t.Fatalf("a build the registry failed twice: %v after %d runs, want success after 3", err, runs)
	}
	if out != "sha256:feed\n" {
		t.Fatalf("the command's standard output came through as %q, want only what it printed", out)
	}
	if args, _ := os.ReadFile(filepath.Join(dir, "flaky.args")); string(args) != "build --target release -t trstctl:ci-scan .\n" { // #nosec G304 -- the test's own temporary file (CWE-22)
		t.Fatalf("the wrapper passed %q", args)
	}
	if _, runs, err := run("down"); err == nil || runs != 4 {
		t.Fatalf("a registry that never recovered: %v after %d runs, want a failure after 4", err, runs)
	}
	if _, runs, err := run("missing"); err == nil || runs != 1 {
		t.Fatalf("a missing image (404) was retried: %v after %d runs", err, runs)
	}
	_, runs, err = run("broken")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 || runs != 1 {
		t.Fatalf("a broken build: %v after %d runs, want its own status 7 after one run", err, runs)
	}
}
