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

// A199: one signer holding a SoftHSM token and AWS KMS (the DoD census's
// SigV4-checking emulator) at once, run in the SoftHSM container. Beyond the
// in-container test, each provider is read back independently: the token
// lists tenant A's key object, and the emulator counts the key it created for
// tenant B with no authentication failure.
func TestSoftHSMContainerSignerHoldsTwoManagedKeyProviders(t *testing.T) {
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
		"softhsm2-util --init-token --free --label trstctl-a199 --so-pin 123456 --pin 987654 >/dev/null",
		"export TRSTCTL_SOFTHSM_MODULE=\"$(find /usr/lib -name libsofthsm2.so | head -n 1)\"",
		"export TRSTCTL_SOFTHSM_TOKEN_LABEL=trstctl-a199 TRSTCTL_SOFTHSM_USER_PIN=987654",
		// The census emulator in AWS mode, on loopback inside this container.
		"TRSTCTL_DOD_CHALLENGE=a199 TRSTCTL_DOD_ENTRY_ID=hsm_kms.aws_kms TRSTCTL_DOD_SUBSTRATE_IDENTITY=a199 TRSTCTL_DOD_CONTRACT_DIGEST=a199 " +
			"python3 /work/tools/dodcensus/substrates/managed_keys.py >/tmp/emulator.out 2>/tmp/emulator.err &",
		"emulator=$!",
		"for _ in $(seq 1 100); do grep -q '\"ready\":true' /tmp/emulator.out 2>/dev/null && break; sleep 0.1; done",
		"export TRSTCTL_KMS_EMULATOR_ENDPOINT=\"$(python3 -c 'import json; print(json.loads(open(\"/tmp/emulator.out\").readline())[\"endpoint\"])')\"",
		"CGO_ENABLED=1 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off go test -tags=pkcs11cgo ./ee/managedkeys/signerwiring -run 'TestSoftHSMAndKMSEmulatorInOneSigner' -count=1 -v",
		"objects=$(pkcs11-tool --module \"$TRSTCTL_SOFTHSM_MODULE\" --token-label trstctl-a199 --login --pin 987654 --list-objects 2>/dev/null | grep -c 'trstctl-a199' || true)",
		"test \"$objects\" -ge 1 && echo SOFTHSM_HOLDS_TENANT_A_KEY",
		"python3 -c 'import json,sys,urllib.request; d=json.load(urllib.request.urlopen(sys.argv[1]+\"/dod/diagnostics\")); print(json.dumps(d)); sys.exit(0 if d[\"create_count\"]>=1 and d[\"auth_failures\"]==0 else 1)' \"$TRSTCTL_KMS_EMULATOR_ENDPOINT\" && echo KMS_EMULATOR_HOLDS_TENANT_B_KEY",
		"kill $emulator",
	}, "\n")
	out, err := dockerOutput(t, 5*time.Minute, "run", "--rm",
		"-e", "TRSTCTL_SOFTHSM_INNER=1",
		"-v", repoRoot+":/work:ro",
		"-v", strings.TrimSpace(string(modCache))+":/gomodcache:ro",
		"-w", "/work",
		image, "bash", "-lc", script)
	if err != nil {
		t.Fatalf("SoftHSM + KMS emulator two-provider signer failed: %v\n%s", err, out)
	}
	for _, marker := range []string{"SOFTHSM_KMS_TWO_PROVIDERS_OK", "SOFTHSM_HOLDS_TENANT_A_KEY", "KMS_EMULATOR_HOLDS_TENANT_B_KEY"} {
		if !strings.Contains(string(out), marker) {
			t.Fatalf("the two-provider signer proof did not report %s:\n%s", marker, out)
		}
	}
	t.Logf("%s", out)
}
