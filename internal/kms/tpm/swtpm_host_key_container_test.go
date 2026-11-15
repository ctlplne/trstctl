// SPDX-License-Identifier: BUSL-1.1

package tpm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSwtpmContainerHostKeyJourneyTPMO1 runs TPM-O1's swtpm proofs in the
// host-key image (testdata/swtpm-hostkey: the swtpm image plus Debian 12's
// tpm2-openssl, tpm2-abrmd and nginx, built from the local swtpm image with no
// base pull): the TPM makes, signs with and certifies a host key and the
// attestation verifies (deviceattest); stock OpenSSL and nginx serve TLS with
// the TPM's key file through the tpm2 provider (kms/tpm); and the relay's host
// renewal with a TPM-held key runs end to end into nginx (agent/relay). The
// real-TPM repeat is Track B row TB-TPM-O1.
func TestSwtpmContainerHostKeyJourneyTPMO1(t *testing.T) {
	if os.Getenv("TRSTCTL_SWTPM_INNER") == "1" {
		t.Skip("outer swtpm container harness is skipped inside the container")
	}
	requireDockerForSwtpm(t)
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	goModCache := hostTPMGoModCache(t)
	base, image := "trstctl-swtpm-go:aud-26-edge-custody", "trstctl-swtpm-go:tpm-o1-host-key"
	if out, err := swtpmDockerOutput(t, swtpmDockerProbeTimeout, "image", "inspect", base); err != nil {
		if buildOut, buildErr := swtpmDockerOutput(t, swtpmDockerBuildTimeout, "build", "-t", base, filepath.Join("testdata", "swtpm")); buildErr != nil {
			t.Fatalf("build swtpm image after inspect failed (%v, %s): %v\n%s", err, out, buildErr, buildOut)
		}
	}
	if out, err := swtpmDockerOutput(t, swtpmDockerProbeTimeout, "image", "inspect", image); err != nil {
		if buildOut, buildErr := swtpmDockerOutput(t, swtpmDockerBuildTimeout, "build", "--pull=false", "--build-arg", "BASE="+base,
			"-t", image, filepath.Join("testdata", "swtpm-hostkey")); buildErr != nil {
			t.Fatalf("build the host-key image after inspect failed (%v, %s): %v\n%s", err, out, buildErr, buildOut)
		}
	}
	goTest := "CGO_ENABLED=0 GOCACHE=/tmp/gocache GOMODCACHE=/gomodcache GOPROXY=off GOFLAGS=-mod=mod go test -count=1 -v"
	script := strings.Join([]string{
		"set -euo pipefail",
		"export PATH=/usr/local/go/bin:$PATH",
		"mkdir -p /tmp/swtpm-state /tmp/gocache",
		"dpkg-query -W -f '${Package} ${Version}\\n' swtpm tpm2-tools tpm2-openssl libtss2-tcti-swtpm0 libtss2-tcti-tabrmd0 tpm2-abrmd dbus nginx openssl",
		"swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm-state --server type=unixio,path=/tmp/swtpm.sock --ctrl type=unixio,path=/tmp/swtpm.sock.ctrl --flags not-need-init,startup-clear --daemon",
		"for attempt in $(seq 1 50); do test -S /tmp/swtpm.sock && break; sleep 0.1; done",
		"test -S /tmp/swtpm.sock",
		"export TRSTCTL_SWTPM_PATH=/tmp/swtpm.sock TRSTCTL_TPM2_PROVIDER=1",
		goTest + " ./internal/crypto/deviceattest -run 'TestSwtpmHostKeyIsCertifiedAndVerifiedTPMO1$' | tee /tmp/host-key.txt",
		"grep -q SWTPM_HOST_KEY_OK /tmp/host-key.txt",
		// Each later test starts tpm2-abrmd in front of swtpm and stops it at
		// its end, so the next one reaches swtpm again.
		goTest + " ./internal/kms/tpm -run 'TestSwtpmHostKeyServesTLSThroughTheTPM2ProviderTPMO1$' | tee /tmp/provider.txt",
		"grep -q TPMO1_PROVIDER_NGINX_OK /tmp/provider.txt",
		"grep -q TPMO1_PROVIDER_TLS12_REFUSED_AS_DOCUMENTED /tmp/provider.txt",
		goTest + " ./internal/agent/relay -run 'TestSwtpmHostRenewalJourneyTPMO1$' | tee /tmp/journey.txt",
		"grep -q TPMO1_JOURNEY_OK /tmp/journey.txt",
	}, "\n")
	out, err := swtpmDockerOutput(t, 20*time.Minute,
		"run", "--rm", "-e", "TRSTCTL_SWTPM_INNER=1",
		"-v", repoRoot+":/work:ro", "-v", goModCache+":/gomodcache:ro",
		"-w", "/work", image, "bash", "-lc", script)
	if err != nil {
		t.Fatalf("TPM-O1 swtpm journey failed: %v\n%s", err, out)
	}
	for _, marker := range []string{"SWTPM_HOST_KEY_OK", "TPMO1_PROVIDER_S_SERVER_OK", "TPMO1_PROVIDER_NGINX_OK",
		"TPMO1_PROVIDER_TLS12_REFUSED_AS_DOCUMENTED", "TPMO1_JOURNEY_OK"} {
		if !strings.Contains(string(out), marker) {
			t.Fatalf("the TPM-O1 swtpm journey did not report %s:\n%s", marker, out)
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "_OK") || strings.HasPrefix(line, "tpm2-") || strings.HasPrefix(line, "nginx ") ||
			strings.HasPrefix(line, "openssl ") || strings.HasPrefix(line, "swtpm ") || strings.HasPrefix(line, "libtss2") || strings.HasPrefix(line, "dbus ") {
			t.Log(strings.TrimSpace(line))
		}
	}
}
