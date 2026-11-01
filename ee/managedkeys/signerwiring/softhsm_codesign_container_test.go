// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// P9: code signing with a key held in an HSM, SoftHSM standing in, run in the
// SoftHSM container. After the in-container test the token is read back with
// pkcs11-tool: the code-signing key is a token object that is sensitive and
// was never extractable.
func TestSoftHSMContainerCodeSigningKeyP9(t *testing.T) {
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
		"softhsm2-util --init-token --free --label trstctl-p9 --so-pin 123456 --pin 987654 >/dev/null",
		"export TRSTCTL_SOFTHSM_MODULE=\"$(find /usr/lib -name libsofthsm2.so | head -n 1)\"",
		"export TRSTCTL_SOFTHSM_TOKEN_LABEL=trstctl-p9 TRSTCTL_SOFTHSM_USER_PIN=987654",
		"CGO_ENABLED=1 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off go test -tags=pkcs11cgo ./ee/managedkeys/signerwiring -run 'TestSoftHSMCodeSigningKeyP9' -count=1 -v",
		"pkcs11-tool --module \"$TRSTCTL_SOFTHSM_MODULE\" --token-label trstctl-p9 --login --pin 987654 --list-objects --type privkey 2>/dev/null | tee /tmp/objects.txt",
		"grep -q 'never extractable' /tmp/objects.txt && grep -q 'sensitive' /tmp/objects.txt && echo SOFTHSM_KEY_NEVER_EXTRACTABLE",
	}, "\n")
	out, err := dockerOutput(t, 5*time.Minute, "run", "--rm",
		"-e", "TRSTCTL_SOFTHSM_INNER=1",
		"-v", repoRoot+":/work:ro",
		"-v", strings.TrimSpace(string(modCache))+":/gomodcache:ro",
		"-w", "/work",
		image, "bash", "-lc", script)
	if err != nil {
		t.Fatalf("SoftHSM code signing failed: %v\n%s", err, out)
	}
	for _, marker := range []string{"SOFTHSM_CODE_SIGNING_OK", "SOFTHSM_KEY_NEVER_EXTRACTABLE"} {
		if !strings.Contains(string(out), marker) {
			t.Fatalf("the SoftHSM code-signing proof did not report %s:\n%s", marker, out)
		}
	}
	t.Logf("%s", out)
}
