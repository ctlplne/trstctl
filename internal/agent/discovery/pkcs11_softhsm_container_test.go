// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	agentSoftHSMDockerProbeTimeout = 15 * time.Second
	agentSoftHSMDockerBuildTimeout = 10 * time.Minute
	agentSoftHSMDockerRunTimeout   = 10 * time.Minute
	agentSoftHSMImage              = "trstctl-softhsm-go:aud-26-edge-custody"
	agentPKCS11ImageTag            = "trstctl-agent-pkcs11:a18-test"
)

// TestPKCS11SoftHSMContainerAgentInventory proves the agent's PKCS#11 source
// against a real module: it builds (or reuses) the SoftHSM Go image the key
// custody tests use, initializes a token and runs the cgo inner test
// (TestSoftHSMAgentInventoryReadsTokenCertificates) inside it.
func TestPKCS11SoftHSMContainerAgentInventory(t *testing.T) {
	if os.Getenv("TRSTCTL_SOFTHSM_INNER") == "1" {
		t.Skip("outer SoftHSM container harness is skipped inside the container")
	}
	requireDockerForAgentSoftHSM(t)
	repoRoot := agentRepoRoot(t)
	goModCache := agentHostGoModCache(t)
	ensureAgentSoftHSMImage(t, repoRoot)

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
		"softhsm2-util --init-token --free --label trstctl-inventory --so-pin 123456 --pin 987654",
		"export TRSTCTL_SOFTHSM_MODULE=\"$(find /usr/lib -name libsofthsm2.so | head -n 1)\"",
		"test -n \"$TRSTCTL_SOFTHSM_MODULE\"",
		"export TRSTCTL_SOFTHSM_TOKEN_LABEL=trstctl-inventory",
		"export TRSTCTL_SOFTHSM_USER_PIN=987654",
		"CGO_ENABLED=1 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off go test -count=1 -v ./internal/agent/discovery -run 'TestSoftHSMAgentInventoryReadsTokenCertificates$'",
		// Independent readback: the key pair the test generated is still on the
		// token and marked sensitive, so the inventory did not touch it.
		"pkcs11-tool --module \"$TRSTCTL_SOFTHSM_MODULE\" --token-label trstctl-inventory --login --pin 987654 --list-objects --type privkey >/tmp/private-objects.txt",
		"grep -qi 'inventory-key' /tmp/private-objects.txt",
		"grep -qi 'sensitive' /tmp/private-objects.txt",
	}, "\n")

	out, err := agentSoftHSMDockerOutput(t, agentSoftHSMDockerRunTimeout,
		"run", "--rm",
		"-e", "TRSTCTL_SOFTHSM_INNER=1",
		"-v", repoRoot+":/work:ro",
		"-v", goModCache+":/gomodcache:ro",
		"-w", "/work",
		agentSoftHSMImage,
		"bash", "-lc", script,
	)
	if err != nil {
		t.Fatalf("SoftHSM agent inventory failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "SOFTHSM_AGENT_INVENTORY_OK") {
		t.Fatalf("SoftHSM agent inventory did not report success:\n%s", out)
	}
}

// TestAgentPKCS11ImageShipsModuleLoading builds deploy/docker/Dockerfile.agent-pkcs11
// from the toolchain's base tags and checks the shipped artifact: a cgo
// (dynamically linked) trstctl-agent at the default path, the SoftHSM and
// OpenSC modules on board, the inventory flags present, running as uid 65532,
// and a module actually loadable from a token initialized inside the image.
func TestAgentPKCS11ImageShipsModuleLoading(t *testing.T) {
	if os.Getenv("TRSTCTL_SOFTHSM_INNER") == "1" {
		t.Skip("image build is skipped inside the container")
	}
	requireDockerForAgentSoftHSM(t)
	repoRoot := agentRepoRoot(t)

	goMod, err := os.ReadFile(filepath.Join(repoRoot, "go.mod")) // #nosec G304 -- the repository's own go.mod under the test's computed repo root (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^toolchain go(\S+)`).FindSubmatch(goMod)
	if m == nil {
		t.Fatal("go.mod has no toolchain line to pick the build image from")
	}
	buildImage := "golang:" + string(m[1]) + "-bookworm"
	out, err := agentSoftHSMDockerOutput(t, agentSoftHSMDockerBuildTimeout,
		"build", "-f", filepath.Join(repoRoot, "deploy", "docker", "Dockerfile.agent-pkcs11"),
		"--build-arg", "BUILD_IMAGE="+buildImage,
		"--build-arg", "BASE_IMAGE=debian:bookworm-slim",
		"-t", agentPKCS11ImageTag, repoRoot)
	if err != nil {
		t.Fatalf("build agent-pkcs11 image: %v\n%s", err, out)
	}

	script := strings.Join([]string{
		"set -eu",
		"test \"$(id -u)\" = 65532",
		"ldd /usr/local/bin/trstctl-agent | grep -q libc.so",
		"test -f /usr/lib/softhsm/libsofthsm2.so",
		"ls /usr/lib/*/opensc-pkcs11.so >/dev/null",
		// Go's flag package prints single-dash names in --help.
		"/usr/local/bin/trstctl-agent --help 2>&1 | grep -q -- '-inventory-pkcs11-module'",
		"/usr/local/bin/trstctl-agent --help 2>&1 | grep -q -- '-inventory-pkcs11-pin-file'",
		"mkdir -p /tmp/softhsm/tokens",
		"printf 'directories.tokendir = /tmp/softhsm/tokens\\nobjectstore.backend = file\\nlog.level = ERROR\\n' >/tmp/softhsm/softhsm2.conf",
		"export SOFTHSM2_CONF=/tmp/softhsm/softhsm2.conf",
		"softhsm2-util --init-token --free --label image-check --so-pin 123456 --pin 987654 >/dev/null",
		"pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-token-slots | grep -q image-check",
		"echo AGENT_PKCS11_IMAGE_OK",
	}, "\n")
	out, err = agentSoftHSMDockerOutput(t, agentSoftHSMDockerRunTimeout,
		"run", "--rm", "--entrypoint", "sh", agentPKCS11ImageTag, "-c", script)
	if err != nil || !strings.Contains(string(out), "AGENT_PKCS11_IMAGE_OK") {
		t.Fatalf("agent-pkcs11 image check failed: %v\n%s", err, out)
	}
}

func ensureAgentSoftHSMImage(t *testing.T, repoRoot string) {
	t.Helper()
	if _, err := agentSoftHSMDockerOutput(t, agentSoftHSMDockerProbeTimeout, "image", "inspect", agentSoftHSMImage); err == nil {
		return
	}
	context := filepath.Join(repoRoot, "internal", "kms", "pkcs11", "testdata", "softhsm")
	if out, err := agentSoftHSMDockerOutput(t, agentSoftHSMDockerBuildTimeout, "build", "-t", agentSoftHSMImage, context); err != nil {
		t.Fatalf("build SoftHSM test image: %v\n%s", err, out)
	}
}

func agentRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	return root
}

func agentHostGoModCache(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skipf("go env GOMODCACHE is required for the offline module cache mount: %v", err)
	}
	cache := strings.TrimSpace(string(out))
	if info, err := os.Stat(cache); cache == "" || err != nil || !info.IsDir() {
		t.Skipf("GOMODCACHE %q is not available for the container mount", cache)
	}
	return cache
}

func requireDockerForAgentSoftHSM(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required for the PKCS#11 container tests: %v", err)
	}
	if out, err := agentSoftHSMDockerOutput(t, agentSoftHSMDockerProbeTimeout, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("docker daemon is required for the PKCS#11 container tests: %v\n%s", err, out)
	}
}

func agentSoftHSMDockerOutput(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed Docker test-harness operations bounded by a context deadline (CWE-78)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("docker %s exceeded %s; the daemon may be unresponsive", strings.Join(args, " "), timeout)
	}
	return out, err
}
