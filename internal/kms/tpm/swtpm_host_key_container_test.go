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
// renewal with a TPM-held key runs end to end into nginx (agent/relay). For
// TPM-O1-L3 the lab also shows the two nginx limits (an in-place reload, two
// workers) and the journey runs the stock nginx, re-executed through its init
// script, including a renewal under load. For TPM-O1-L2 it shows why apache,
// postgresql and mariadb cannot serve a TPM-held key and haproxy only with one
// thread, and the relay renews one into haproxy and into postfix with dovecot.
// The real-TPM repeat is Track B row TB-TPM-O1.
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
	// tpm-o1-l2: the image adds the lab's tpmrm bridge (TPM-O1-L1) and the
	// other OpenSSL-based host services (TPM-O1-L2).
	base, image := "trstctl-swtpm-go:aud-26-edge-custody", "trstctl-swtpm-go:tpm-o1-l2-host-key"
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
		"export TRSTCTL_SWTPM_PATH=/tmp/swtpm.sock TRSTCTL_TPM2_PROVIDER=1 TRSTCTL_TPMRM_BRIDGE=/usr/local/bin/tpmrm-bridge",
		"dpkg-query -W -f '${Package} ${Version}\\n' gcc libtss2-dev haproxy postfix dovecot-core apache2 postgresql-15 mariadb-server",
		goTest + " ./internal/crypto/deviceattest -run 'TestSwtpmHostKeyIsCertifiedAndVerifiedTPMO1$' | tee /tmp/host-key.txt",
		"grep -q SWTPM_HOST_KEY_OK /tmp/host-key.txt",
		// Each later test starts tpm2-abrmd in front of swtpm and stops it at
		// its end, so the next one reaches swtpm again.
		goTest + " ./internal/kms/tpm -run 'TestSwtpmHostKeyServesTLSThroughTheTPM2ProviderTPMO1$' | tee /tmp/provider.txt",
		"grep -q TPMO1_PROVIDER_NGINX_OK /tmp/provider.txt",
		"grep -q TPMO1_PROVIDER_TLS12_REFUSED_AS_DOCUMENTED /tmp/provider.txt",
		// TPM-O1-L3: the nginx limits its requirements rest on.
		goTest + " ./internal/kms/tpm -run 'TestSwtpmNginxCannotReloadATPMHeldKeyInPlaceOrShareItAcrossWorkersTPMO1L3$' | tee /tmp/nginx-limits.txt",
		"grep -q TPMO1L3_INPLACE_RELOAD_FAILS_AS_DOCUMENTED /tmp/nginx-limits.txt",
		"grep -q TPMO1L3_TWO_WORKERS_FAIL_AS_DOCUMENTED /tmp/nginx-limits.txt",
		// TPM-O1-L2: why apache, postgresql and mysql take no TPM-held key,
		// and haproxy only with one thread.
		goTest + " ./internal/kms/tpm -run 'TestSwtpmServicesSharingTheTPM2ProviderFailConcurrentHandshakesTPMO1L2$' | tee /tmp/services.txt",
		"grep -q TPMO1L2_APACHE_EVENT_FAILS_AS_DOCUMENTED /tmp/services.txt",
		"grep -q TPMO1L2_HAPROXY_THREADS_FAIL_AS_DOCUMENTED /tmp/services.txt",
		"grep -q TPMO1L2_POSTGRESQL_FAILS_AS_DOCUMENTED /tmp/services.txt",
		"grep -q TPMO1L2_MARIADB_FAILS_AS_DOCUMENTED /tmp/services.txt",
		goTest + " ./internal/agent/relay -run 'TestSwtpmHostRenewalJourneyTPMO1$' | tee /tmp/journey.txt",
		"grep -q TPMO1_JOURNEY_OK /tmp/journey.txt",
		"grep -q TPMO1L3_RENEWAL_UNDER_LOAD_OK /tmp/journey.txt",
		"grep -q TPMO1L1_REPROTECT_OK /tmp/journey.txt",
		"grep -q TPMO1L3L1_STOPPED_NGINX_STARTED_OK /tmp/journey.txt",
		goTest + " ./internal/agent/relay -run 'TestSwtpmHostRenewalJourneysHAProxyAndPostfixTPMO1L2$' | tee /tmp/l2-journeys.txt",
		"grep -q TPMO1L2_HAPROXY_OK /tmp/l2-journeys.txt",
		"grep -q TPMO1L2_POSTFIX_DOVECOT_OK /tmp/l2-journeys.txt",
	}, "\n")
	out, err := swtpmDockerOutput(t, 20*time.Minute,
		"run", "--rm", "-e", "TRSTCTL_SWTPM_INNER=1",
		"-v", repoRoot+":/work:ro", "-v", goModCache+":/gomodcache:ro",
		"-w", "/work", image, "bash", "-lc", script)
	if err != nil {
		t.Fatalf("TPM-O1 swtpm journey failed: %v\n%s", err, out)
	}
	for _, marker := range []string{"SWTPM_HOST_KEY_OK", "TPMO1_PROVIDER_S_SERVER_OK", "TPMO1_PROVIDER_NGINX_OK",
		"TPMO1_PROVIDER_TLS12_REFUSED_AS_DOCUMENTED", "TPMO1L3_INPLACE_RELOAD_FAILS_AS_DOCUMENTED", "TPMO1L3_TWO_WORKERS_FAIL_AS_DOCUMENTED",
		"TPMO1L2_APACHE_EVENT_FAILS_AS_DOCUMENTED", "TPMO1L2_HAPROXY_THREADS_FAIL_AS_DOCUMENTED", "TPMO1L2_POSTGRESQL_FAILS_AS_DOCUMENTED",
		"TPMO1L2_MARIADB_FAILS_AS_DOCUMENTED", "TPMO1_JOURNEY_OK", "TPMO1L3_RENEWAL_UNDER_LOAD_OK", "TPMO1L1_REPROTECT_OK",
		"TPMO1L3L1_STOPPED_NGINX_STARTED_OK",
		"TPMO1L2_HAPROXY_OK", "TPMO1L2_POSTFIX_DOVECOT_OK"} {
		if !strings.Contains(string(out), marker) {
			t.Fatalf("the TPM-O1 swtpm journey did not report %s:\n%s", marker, out)
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "_OK") || strings.Contains(line, "_DOCUMENTED") || strings.Contains(line, "after the in-place reload") ||
			strings.Contains(line, "concurrent handshakes completed") || strings.Contains(line, "did not start with the TPM-held key") ||
			strings.HasPrefix(line, "haproxy ") || strings.HasPrefix(line, "postfix ") || strings.HasPrefix(line, "dovecot") ||
			strings.HasPrefix(line, "apache2 ") || strings.HasPrefix(line, "postgresql") || strings.HasPrefix(line, "mariadb") ||
			strings.HasPrefix(line, "tpm2-") || strings.HasPrefix(line, "nginx ") ||
			strings.HasPrefix(line, "openssl ") || strings.HasPrefix(line, "swtpm ") || strings.HasPrefix(line, "libtss2") || strings.HasPrefix(line, "dbus ") {
			t.Log(strings.TrimSpace(line))
		}
	}
}
