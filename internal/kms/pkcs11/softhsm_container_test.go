// SPDX-License-Identifier: MPL-2.0

package pkcs11_test

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
	softHSMDockerProbeTimeout = 15 * time.Second
	softHSMDockerBuildTimeout = 5 * time.Minute
	softHSMDockerRunTimeout   = 5 * time.Minute
)

func TestPKCS11SoftHSMContainerGenerateSign(t *testing.T) {
	if os.Getenv("TRSTCTL_SOFTHSM_INNER") == "1" {
		t.Skip("outer SoftHSM container harness is skipped inside the container")
	}
	requireDockerForSoftHSM(t)

	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	goModCache := hostGoModCache(t)
	image := "trstctl-softhsm-go:aud-26-edge-custody"
	if out, err := softHSMDockerOutput(t, softHSMDockerProbeTimeout, "image", "inspect", image); err != nil {
		if buildOut, buildErr := softHSMDockerOutput(t, softHSMDockerBuildTimeout, "build", "-t", image, filepath.Join("testdata", "softhsm")); buildErr != nil {
			t.Fatalf("build SoftHSM test image after inspect failed (%v, %s): %v\n%s", err, out, buildErr, buildOut)
		}
	}

	script := strings.Join([]string{
		"set -euo pipefail",
		"export PATH=/usr/local/go/bin:$PATH",
		"mkdir -p /tmp/softhsm/tokens /tmp/gocache",
		"cat >/tmp/softhsm/softhsm2.conf <<'EOF'",
		"directories.tokendir = /tmp/softhsm/tokens",
		"objectstore.backend = file",
		"log.level = ERROR",
		"slots.removable = false",
		"EOF",
		"export SOFTHSM2_CONF=/tmp/softhsm/softhsm2.conf",
		"softhsm2-util --init-token --free --label trstctl-kms03 --so-pin 123456 --pin 987654",
		"export TRSTCTL_SOFTHSM_MODULE=\"$(find /usr/lib -name libsofthsm2.so | head -n 1)\"",
		"test -n \"$TRSTCTL_SOFTHSM_MODULE\"",
		"export TRSTCTL_SOFTHSM_TOKEN_LABEL=trstctl-kms03",
		"export TRSTCTL_SOFTHSM_USER_PIN=987654",
		"CGO_ENABLED=1 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off go test -tags=pkcs11cgo ./internal/kms/pkcs11 -run 'TestSoftHSMRealBindingGenerateSign|TestSoftHSMEdgeCAHandleSurvivesSessionRestart' -count=1 -v",
		"pkcs11-tool --module \"$TRSTCTL_SOFTHSM_MODULE\" --token-label trstctl-kms03 --login --pin 987654 --list-objects --type privkey >/tmp/private-objects.txt",
		"grep -qi 'sensitive' /tmp/private-objects.txt",
		"grep -qi 'never extractable' /tmp/private-objects.txt",
	}, "\n")

	args := []string{
		"run", "--rm",
		"-e", "TRSTCTL_SOFTHSM_INNER=1",
		"-v", repoRoot + ":/work:ro",
		"-v", goModCache + ":/gomodcache:ro",
		"-w", "/work",
		image,
		"bash", "-lc", script,
	}
	out, err := softHSMDockerOutput(t, softHSMDockerRunTimeout, args...)
	if err != nil {
		t.Fatalf("SoftHSM integration failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "SOFTHSM_PKCS11_OK") {
		t.Fatalf("SoftHSM integration did not report success:\n%s", out)
	}
	if !strings.Contains(string(out), "SOFTHSM_EDGE_CA_OK") {
		t.Fatalf("SoftHSM edge CA restart journey did not report success:\n%s", out)
	}
}

func hostGoModCache(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skipf("go env GOMODCACHE is required for the offline SoftHSM module cache mount: %v", err)
	}
	cache := strings.TrimSpace(string(out))
	if cache == "" {
		t.Skip("go env GOMODCACHE returned an empty path")
	}
	info, err := os.Stat(cache)
	if err != nil {
		t.Skipf("GOMODCACHE %s is not available for the SoftHSM container mount: %v", cache, err)
	}
	if !info.IsDir() {
		t.Skipf("GOMODCACHE %s is not a directory", cache)
	}
	return cache
}

func requireDockerForSoftHSM(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required for the SoftHSM acceptance test: %v", err)
	}
	if out, err := softHSMDockerOutput(t, softHSMDockerProbeTimeout, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("docker daemon is required for the SoftHSM acceptance test: %v\n%s", err, out)
	}
}

func softHSMDockerOutput(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed Docker test-harness operations bounded by a context deadline (CWE-78)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("docker %s exceeded %s; the daemon may be unresponsive", strings.Join(args, " "), timeout)
	}
	return out, err
}
