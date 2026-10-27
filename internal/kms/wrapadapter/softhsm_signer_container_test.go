// SPDX-License-Identifier: BUSL-1.1

package wrapadapter_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A200: the SoftHSM proof runs in the SoftHSM test image, where the adapter is
// built with cgo as the HSM signer image builds it.
func TestSoftHSMContainerSealsTheSignerCAKeyThroughTheAdapter(t *testing.T) {
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
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
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
		"softhsm2-util --init-token --free --label trstctl-a200 --so-pin 123456 --pin 987654 >/dev/null",
		"export TRSTCTL_SOFTHSM_MODULE=\"$(find /usr/lib -name libsofthsm2.so | head -n 1)\"",
		"pkcs11-tool --module \"$TRSTCTL_SOFTHSM_MODULE\" --token-label trstctl-a200 --login --pin 987654 --keygen --key-type AES:32 --label trstctl-signer-keystore --sensitive >/dev/null 2>&1",
		"export TRSTCTL_SOFTHSM_TOKEN_LABEL=trstctl-a200 TRSTCTL_SOFTHSM_USER_PIN=987654",
		"export CGO_ENABLED=1 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off",
		"go build -tags=pkcs11cgo -o /tmp/trstctl-kms-wrap ./cmd/trstctl-kms-wrap",
		"export TRSTCTL_KMS_WRAP_ADAPTER=/tmp/trstctl-kms-wrap",
		"go test -tags=pkcs11cgo ./internal/kms/wrapadapter -run 'TestSoftHSMSealsTheSignerCAKeyThroughTheAdapter' -count=1 -v",
		"pkcs11-tool --module \"$TRSTCTL_SOFTHSM_MODULE\" --token-label trstctl-a200 --login --pin 987654 --list-objects --type secrkey 2>/dev/null | grep -c 'trstctl-signer-keystore' || true",
	}, "\n")
	out, err := docker(10*time.Minute, "run", "--rm",
		"-e", "TRSTCTL_SOFTHSM_INNER=1",
		"-v", repoRoot+":/work:ro",
		"-v", strings.TrimSpace(string(modCache))+":/gomodcache:ro",
		"-w", "/work", image, "bash", "-lc", script)
	if err != nil {
		t.Fatalf("SoftHSM signer key store through the adapter failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "SOFTHSM_SIGNER_KEYSTORE_OK") {
		t.Fatalf("the SoftHSM proof did not report SOFTHSM_SIGNER_KEYSTORE_OK:\n%s", out)
	}
	t.Logf("%s", out)
}
