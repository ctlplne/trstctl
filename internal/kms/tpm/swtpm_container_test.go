// SPDX-License-Identifier: BUSL-1.1

package tpm_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	swtpmDockerProbeTimeout = 15 * time.Second
	swtpmDockerBuildTimeout = 5 * time.Minute
	swtpmDockerRunTimeout   = 5 * time.Minute
)

func TestSwtpmContainerEdgeCAHandle(t *testing.T) {
	if os.Getenv("TRSTCTL_SWTPM_INNER") == "1" {
		t.Skip("outer swtpm container harness is skipped inside the container")
	}
	requireDockerForSwtpm(t)
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	goModCache := hostTPMGoModCache(t)
	image := "trstctl-swtpm-go:aud-26-edge-custody"
	if out, err := swtpmDockerOutput(t, swtpmDockerProbeTimeout, "image", "inspect", image); err != nil {
		if buildOut, buildErr := swtpmDockerOutput(t, swtpmDockerBuildTimeout, "build", "-t", image, filepath.Join("testdata", "swtpm")); buildErr != nil {
			t.Fatalf("build swtpm image after inspect failed (%v, %s): %v\n%s", err, out, buildErr, buildOut)
		}
	}

	script := strings.Join([]string{
		"set -euo pipefail",
		"export PATH=/usr/local/go/bin:$PATH",
		"mkdir -p /tmp/swtpm-state /tmp/gocache",
		"swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm-state --server type=unixio,path=/tmp/swtpm.sock --ctrl type=unixio,path=/tmp/swtpm.sock.ctrl --flags not-need-init,startup-clear --daemon",
		"for attempt in $(seq 1 50); do test -S /tmp/swtpm.sock && break; sleep 0.1; done",
		"test -S /tmp/swtpm.sock",
		"export TRSTCTL_SWTPM_PATH=/tmp/swtpm.sock",
		"CGO_ENABLED=0 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off go test ./internal/kms/tpm -run TestSwtpmEdgeCAHandleSurvivesDeviceRestart -count=1 -v | tee /tmp/swtpm-go-test.txt",
		"handle=$(sed -n 's/.*SWTPM_EDGE_CA_OK handle=\\(0x[0-9a-fA-F]*\\).*/\\1/p' /tmp/swtpm-go-test.txt | tail -n 1)",
		"test -n \"$handle\"",
		"export TPM2TOOLS_TCTI=swtpm:path=/tmp/swtpm.sock",
		"tpm2_readpublic -c \"$handle\" -f pem -o /tmp/edge-public.pem",
		"grep -q 'BEGIN PUBLIC KEY' /tmp/edge-public.pem",
	}, "\n")
	args := []string{
		"run", "--rm", "-e", "TRSTCTL_SWTPM_INNER=1",
		"-v", repoRoot + ":/work:ro", "-v", goModCache + ":/gomodcache:ro",
		"-w", "/work", image, "bash", "-lc", script,
	}
	out, err := swtpmDockerOutput(t, swtpmDockerRunTimeout, args...)
	if err != nil {
		t.Fatalf("swtpm edge CA integration failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "SWTPM_EDGE_CA_OK") {
		t.Fatalf("swtpm edge CA journey did not report success:\n%s", out)
	}
}

func hostTPMGoModCache(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skipf("go env GOMODCACHE is required: %v", err)
	}
	cache := strings.TrimSpace(string(out))
	if info, err := os.Stat(cache); err != nil || !info.IsDir() {
		t.Skipf("GOMODCACHE %q is unavailable", cache)
	}
	return cache
}

func requireDockerForSwtpm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := swtpmDockerOutput(t, swtpmDockerProbeTimeout, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("docker daemon is required: %v\n%s", err, out)
	}
}

func swtpmDockerOutput(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed Docker test-harness operations bounded by a context deadline (CWE-78)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("docker %s exceeded %s; the daemon may be unresponsive", strings.Join(args, " "), timeout)
	}
	return out, err
}
