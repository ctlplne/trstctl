// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
