// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A175-L2: the SoftHSM CLI proof runs in the SoftHSM test image, where the
// agent is built with cgo as the HSM images build it; the inner test is
// TestSoftHSMEdgeAttestWritesThePKCS11MintBodyA175L2.
func TestSoftHSMContainerEdgeAttestWritesThePKCS11MintBodyA175L2(t *testing.T) {
	if os.Getenv("TRSTCTL_SOFTHSM_INNER") == "1" {
		t.Skip("outer SoftHSM container harness is skipped inside the container")
	}
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	docker := func(timeout time.Duration, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed docker invocation for the acceptance test (CWE-78)
	}
	if out, err := docker(15*time.Second, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("docker daemon is required: %v\n%s", err, out)
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	modCache, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil || strings.TrimSpace(string(modCache)) == "" {
		t.Skipf("go env GOMODCACHE is required for the offline module cache mount: %v", err)
	}
	image := "trstctl-softhsm-go:aud-26-edge-custody"
	if out, err := docker(15*time.Second, "image", "inspect", image); err != nil {
		if buildOut, buildErr := docker(5*time.Minute, "build", "-t", image, filepath.Join(repoRoot, "internal", "kms", "pkcs11", "testdata", "softhsm")); buildErr != nil {
			t.Fatalf("build the SoftHSM test image after inspect failed (%v, %s): %v\n%s", err, out, buildErr, buildOut)
		}
	}
	script := strings.Join([]string{
		"set -euo pipefail",
		"export PATH=/usr/local/go/bin:$PATH",
		"mkdir -p /tmp/softhsm/tokens /tmp/gocache",
		"printf 'directories.tokendir = /tmp/softhsm/tokens\\nobjectstore.backend = file\\nlog.level = ERROR\\nslots.removable = false\\n' >/tmp/softhsm/softhsm2.conf",
		"export SOFTHSM2_CONF=/tmp/softhsm/softhsm2.conf",
		"softhsm2-util --init-token --free --label trstctl-a175l2 --so-pin 123456 --pin 987654 >/dev/null",
		"export TRSTCTL_SOFTHSM_MODULE=\"$(find /usr/lib -name libsofthsm2.so | head -n 1)\"",
		"export TRSTCTL_SOFTHSM_TOKEN_LABEL=trstctl-a175l2 TRSTCTL_SOFTHSM_USER_PIN=987654",
		"export CGO_ENABLED=1 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off GOFLAGS=-buildvcs=false",
		"go test -tags=pkcs11cgo ./cmd/trstctl-agent -run 'TestSoftHSMEdgeAttestWritesThePKCS11MintBodyA175L2' -count=1 -v",
	}, "\n")
	out, err := docker(15*time.Minute, "run", "--rm",
		"-e", "TRSTCTL_SOFTHSM_INNER=1",
		"-v", repoRoot+":/work:ro",
		"-v", strings.TrimSpace(string(modCache))+":/gomodcache:ro",
		"-w", "/work", image, "bash", "-lc", script)
	if err != nil {
		t.Fatalf("SoftHSM edge-attest through the agent CLI failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "SOFTHSM_EDGE_ATTEST_PKCS11_OK") {
		t.Fatalf("the SoftHSM proof did not report SOFTHSM_EDGE_ATTEST_PKCS11_OK:\n%s", out)
	}
	t.Logf("%s", out)
}
