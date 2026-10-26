// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A123: the tenant KEK custody against SoftHSM, run in the SoftHSM container
// with keys an operator provisions with pkcs11-tool. Beyond the in-container
// test, the token itself is checked: the signer's tenant domain KEKs are never
// HSM objects, so the token holds exactly the operator's two keys afterwards.
func TestSoftHSMContainerSignerKeepsTenantDomainKEKs(t *testing.T) {
	if os.Getenv("TRSTCTL_SOFTHSM_INNER") == "1" {
		t.Skip("outer SoftHSM container harness is skipped inside the container")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required for the SoftHSM acceptance test: %v", err)
	}
	if out, err := dockerOutput(t, 15*time.Second, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("docker daemon is required for the SoftHSM acceptance test: %v\n%s", err, out)
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
	if out, err := dockerOutput(t, 15*time.Second, "image", "inspect", image); err != nil {
		if buildOut, buildErr := dockerOutput(t, 5*time.Minute, "build", "-t", image, filepath.Join(repoRoot, "internal", "kms", "pkcs11", "testdata", "softhsm")); buildErr != nil {
			t.Fatalf("build SoftHSM test image after inspect failed (%v, %s): %v\n%s", err, out, buildErr, buildOut)
		}
	}

	script := strings.Join([]string{
		"set -euo pipefail",
		"export PATH=/usr/local/go/bin:$PATH",
		"mkdir -p /tmp/softhsm/tokens /tmp/gocache",
		"printf 'directories.tokendir = /tmp/softhsm/tokens\\nobjectstore.backend = file\\nlog.level = ERROR\\nslots.removable = false\\n' >/tmp/softhsm/softhsm2.conf",
		"export SOFTHSM2_CONF=/tmp/softhsm/softhsm2.conf",
		"softhsm2-util --init-token --free --label trstctl-a123 --so-pin 123456 --pin 987654 >/dev/null",
		"export TRSTCTL_SOFTHSM_MODULE=\"$(find /usr/lib -name libsofthsm2.so | head -n 1)\"",
		"tool() { pkcs11-tool --module \"$TRSTCTL_SOFTHSM_MODULE\" --token-label trstctl-a123 --login --pin 987654 \"$@\" 2>/dev/null; }",
		"tool --keygen --key-type AES:32 --label trstctl-tenant-kek-a --sensitive >/dev/null",
		"tool --keygen --key-type AES:32 --label trstctl-tenant-kek-extractable --sensitive --extractable >/dev/null",
		"objects() { tool --list-objects | grep -c 'Object;' || true; }",
		"before=$(objects)",
		"export TRSTCTL_SOFTHSM_TOKEN_LABEL=trstctl-a123 TRSTCTL_SOFTHSM_USER_PIN=987654 TRSTCTL_SOFTHSM_AES_KEYS=1",
		"CGO_ENABLED=1 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off go test -tags=pkcs11cgo ./ee/managedkeys/signerwiring -run 'TestSoftHSMSignerKeepsTenantDomainKEKs' -count=1 -v",
		"after=$(objects)",
		"test \"$before\" = 2 && test \"$after\" = 2 && echo SOFTHSM_TOKEN_HOLDS_ONLY_OPERATOR_KEYS",
	}, "\n")
	out, err := dockerOutput(t, 5*time.Minute, "run", "--rm",
		"-e", "TRSTCTL_SOFTHSM_INNER=1",
		"-v", repoRoot+":/work:ro",
		"-v", strings.TrimSpace(string(modCache))+":/gomodcache:ro",
		"-w", "/work",
		image, "bash", "-lc", script)
	if err != nil {
		t.Fatalf("SoftHSM tenant KEK integration failed: %v\n%s", err, out)
	}
	for _, marker := range []string{"SOFTHSM_TENANT_KEK_OK", "SOFTHSM_TOKEN_HOLDS_ONLY_OPERATOR_KEYS"} {
		if !strings.Contains(string(out), marker) {
			t.Fatalf("SoftHSM tenant KEK integration did not report %s:\n%s", marker, out)
		}
	}
}

func dockerOutput(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed Docker test-harness operations bounded by a context deadline (CWE-78)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("docker %s exceeded %s; the daemon may be unresponsive", strings.Join(args, " "), timeout)
	}
	return out, err
}
