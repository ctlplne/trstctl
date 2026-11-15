// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package tpm_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// labTPMServerCert has the TPM make a host key and a lab CA certify it for
// web.lab.test, as a renewal installs it: the TSS2 key file, the chain and the
// leaf.
func labTPMServerCert(t *testing.T, host tpm.HostKeyDevice, ca *crypto.LockedSigner, caDER []byte) (keyFile, chainPEM, leafDER []byte) {
	t.Helper()
	file, publicDER, err := host.CreateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "web.lab.test", DNSNames: []string{"web.lab.test"}},
		tpm.HostKeySigner(host, file, publicDER))
	if err != nil {
		t.Fatalf("CSR signed by the TPM: %v", err)
	}
	chain, err := crypto.SignServerCertFromCSR(caDER, ca, csrDER, []string{"web.lab.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pem.Decode(chain)
	if leaf == nil {
		t.Fatal("the issued chain has no certificate")
	}
	return file, chain, leaf.Bytes
}

// concurrentHandshakes runs n TLS handshakes at once and returns how many
// completed with leaf.
func concurrentHandshakes(addr string, n int, leaf []byte) int {
	var mu sync.Mutex
	var wg sync.WaitGroup
	ok := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := tlsprobe.Probe(context.Background(), addr, tlsprobe.WithTimeout(30*time.Second))
			if err == nil && len(res.PeerCertificates) > 0 && bytes.Equal(res.PeerCertificates[0], leaf) {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return ok
}

// TestSwtpmNginxCannotReloadATPMHeldKeyInPlaceOrShareItAcrossWorkersTPMO1L3
// (swtpm + tpm2-abrmd + Debian 12's tpm2-openssl and nginx; run by the
// container harness): the two nginx limits the TPM-O1-L3 requirements rest on.
// An in-place reload (SIGHUP) of an nginx that serves a TPM-held key, here in
// the single-process mode the TPM-O1 journey ran, leaves nginx failing its
// handshakes or still serving the previous certificate; and two nginx workers,
// which share the master's tpm2 provider context, fail concurrent handshakes.
// Each check fails when a package changes the behavior, so the requirements
// in docs/features/deployment-connectors.md can be revisited. The working
// path, a re-execution of nginx, is the relay's journey.
func TestSwtpmNginxCannotReloadATPMHeldKeyInPlaceOrShareItAcrossWorkersTPMO1L3(t *testing.T) {
	sock := os.Getenv("TRSTCTL_SWTPM_PATH")
	if sock == "" || os.Getenv("TRSTCTL_TPM2_PROVIDER") != "1" || os.Getenv("TRSTCTL_SWTPM_INNER") != "1" {
		t.Skip("the swtpm container harness (TRSTCTL_SWTPM_INNER=1, TRSTCTL_SWTPM_PATH, TRSTCTL_TPM2_PROVIDER=1) is required")
	}
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: sock, PersistentHandleBase: 0x8101d000})
	if err != nil {
		t.Fatal(err)
	}
	host := dev.(tpm.HostKeyDevice)
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "TPM-O1-L3 lab CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key1, chain1, leaf1 := labTPMServerCert(t, host, ca, caDER)
	key2, chain2, leaf2 := labTPMServerCert(t, host, ca, caDER)
	_ = dev.Close()

	dir := t.TempDir()
	keyPath, certPath, confPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "openssl.cnf")
	install := func(key, chain []byte) {
		t.Helper()
		for path, body := range map[string][]byte{keyPath: key, certPath: chain} {
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(confPath, []byte(tpm2ProviderConf), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(startResourceManager(t, sock), "OPENSSL_CONF="+confPath)
	nginxConf := filepath.Join(dir, "nginx.conf")
	writeConf := func(main string, port int) {
		t.Helper()
		conf := fmt.Sprintf(`%s
error_log %[2]s/error.log info;
pid %[2]s/nginx.pid;
env OPENSSL_CONF;
env TPM2OPENSSL_TCTI;
env DBUS_SESSION_BUS_ADDRESS;
events { worker_connections 64; }
http {
  access_log off;
  server {
    listen 127.0.0.1:%[3]d ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate %[4]s;
    ssl_certificate_key %[5]s;
    location / { return 200 "ok"; }
  }
}
`, main, dir, port, certPath, keyPath)
		if err := os.WriteFile(nginxConf, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	logs := func() string {
		errLog, _ := os.ReadFile(filepath.Join(dir, "error.log")) // #nosec G304 -- the test's own temp directory (CWE-22)
		return string(errLog)
	}
	stop := func() {
		stopCmd := exec.Command("nginx", "-c", nginxConf, "-p", dir, "-s", "stop") // #nosec G204 -- fixed tool and test paths (CWE-78)
		stopCmd.Env = env
		_ = stopCmd.Run()
		time.Sleep(time.Second)
	}

	// An in-place reload, in the single-process mode the TPM-O1 journey ran.
	port := freeLoopbackPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	install(key1, chain1)
	writeConf("daemon off;\nmaster_process off;\nworker_processes 1;", port)
	single := exec.Command("nginx", "-c", nginxConf, "-p", dir) // #nosec G204 -- fixed tool and test paths (CWE-78)
	single.Env = env
	if err := single.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = single.Process.Kill(); _ = single.Wait() })
	if leaf := servedLeaf(t, addr, logs); !bytes.Equal(leaf, leaf1) {
		t.Fatalf("nginx served another certificate before the reload\n%s", logs())
	}
	install(key2, chain2)
	if err := single.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if ok := concurrentHandshakes(addr, 8, leaf2); ok == 8 {
		t.Fatal("nginx now serves a TPM-held key across an in-place reload: revisit the TPM-O1-L3 requirement in docs/features/deployment-connectors.md")
	}
	res, probeErr := tlsprobe.Probe(context.Background(), addr, tlsprobe.WithTimeout(15*time.Second))
	switch {
	case probeErr != nil:
		t.Logf("after the in-place reload nginx fails its handshakes: %v", probeErr)
	case len(res.PeerCertificates) > 0 && bytes.Equal(res.PeerCertificates[0], leaf1):
		t.Log("after the in-place reload nginx still serves the previous certificate")
	default:
		t.Log("after the in-place reload nginx serves the new certificate to some handshakes and fails others")
	}
	_ = single.Process.Kill()
	_ = single.Wait()
	time.Sleep(time.Second)
	t.Log("TPMO1L3_INPLACE_RELOAD_FAILS_AS_DOCUMENTED")

	// Two workers under one master share its tpm2 provider context.
	port = freeLoopbackPort(t)
	addr = fmt.Sprintf("127.0.0.1:%d", port)
	install(key1, chain1)
	_ = os.Remove(filepath.Join(dir, "error.log"))
	writeConf("worker_processes 2;", port)
	start := exec.Command("nginx", "-c", nginxConf, "-p", dir) // #nosec G204 -- fixed tool and test paths (CWE-78)
	start.Env = env
	if out, err := start.CombinedOutput(); err != nil {
		t.Fatalf("start nginx with two workers: %v\n%s", err, out)
	}
	t.Cleanup(stop)
	if leaf := servedLeaf(t, addr, logs); !bytes.Equal(leaf, leaf1) {
		t.Fatalf("nginx with two workers served another certificate\n%s", logs())
	}
	pids, _ := os.ReadFile(filepath.Join(dir, "nginx.pid")) // #nosec G304 -- the test's own temp directory (CWE-22)
	ok := concurrentHandshakes(addr, 8, leaf1)
	if ok == 8 {
		t.Fatal("two nginx workers now serve a TPM-held key to concurrent handshakes: revisit the TPM-O1-L3 worker requirement in docs/features/deployment-connectors.md")
	}
	t.Logf("two workers (master %s): %d of 8 concurrent handshakes completed", strings.TrimSpace(string(pids)), ok)
	stop()
	t.Log("TPMO1L3_TWO_WORKERS_FAIL_AS_DOCUMENTED")
}
