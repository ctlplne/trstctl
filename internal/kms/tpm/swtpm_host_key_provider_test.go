// SPDX-License-Identifier: BUSL-1.1

//go:build linux

package tpm_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/kms/tpm"
)

const tpm2ProviderConf = `openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
alg_section = evp_properties
[provider_sect]
default = default_sect
tpm2 = tpm2_sect
[default_sect]
activate = 1
[tpm2_sect]
activate = 1
[evp_properties]
default_properties = ?provider=tpm2
`

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// labWait bounds each wait in the provider lab: through tpm2-abrmd every
// handshake digest runs in the TPM, which a loaded host makes slow.
const labWait = 60 * time.Second

func servedLeaf(t *testing.T, addr string, logs func() string) []byte {
	t.Helper()
	deadline := time.Now().Add(labWait)
	for {
		res, err := tlsprobe.Probe(context.Background(), addr, tlsprobe.WithTimeout(15*time.Second))
		if err == nil && len(res.PeerCertificates) > 0 {
			return res.PeerCertificates[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no TLS handshake at %s: %v\n%s", addr, err, logs())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitFor polls ready for up to labWait, failing with logs.
func waitFor(t *testing.T, what string, ready func() bool, logs func() string) {
	t.Helper()
	deadline := time.Now().Add(labWait)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not come up\n%s", what, logs())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startResourceManager starts tpm2-abrmd, the user-space TPM resource
// manager, on a private D-Bus session bus in front of swtpm, and returns the
// environment the tpm2 provider reaches it with. On a host the kernel's
// /dev/tpmrm0 swaps the TPM's object contexts for every process; swtpm swaps
// none, and a TLS handshake through the provider holds more contexts than its
// three slots. tpm2-abrmd takes swtpm's one connection, so it starts once
// trstctl's own TPM work is done.
func startResourceManager(t *testing.T, sock string) []string {
	t.Helper()
	dir := t.TempDir()
	busPath := filepath.Join(dir, "bus")
	bus := exec.Command("dbus-daemon", "--session", "--nofork", "--nopidfile", "--address=unix:path="+busPath) // #nosec G204 -- fixed tool and test paths (CWE-78)
	var busLog bytes.Buffer
	bus.Stdout, bus.Stderr = &busLog, &busLog
	if err := bus.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bus.Process.Kill(); _ = bus.Wait() })
	waitFor(t, "the D-Bus session bus", func() bool { _, err := os.Stat(busPath); return err == nil }, busLog.String)
	env := append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS=unix:path="+busPath)

	rm := exec.Command("tpm2-abrmd", "--session", "--allow-root", "--tcti=swtpm:path="+sock) // #nosec G204,G702 -- a fixed tool; the socket path is the container harness's own swtpm (CWE-78)
	rm.Env = env
	var rmLog bytes.Buffer
	rm.Stdout, rm.Stderr = &rmLog, &rmLog
	if err := rm.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rm.Process.Kill(); _ = rm.Wait() })
	const tcti = "tabrmd:bus_type=session"
	waitFor(t, "tpm2-abrmd", func() bool {
		probe := exec.Command("tpm2_getrandom", "-T", tcti, "8") // #nosec G204 -- fixed tool and arguments (CWE-78)
		probe.Env = env
		return probe.Run() == nil
	}, rmLog.String)
	return append(env, "TPM2OPENSSL_TCTI="+tcti)
}

// TestSwtpmHostKeyServesTLSThroughTheTPM2ProviderTPMO1 (swtpm + OpenSSL 3's
// tpm2 provider): a host key file trstctl's TPM code writes loads in stock
// OpenSSL through the tpm2 provider and serves TLS, in openssl s_server and in
// nginx, with the private key never outside the TPM: each handshake's server
// signature is made by the TPM, and the probe sees the certificate for that key.
func TestSwtpmHostKeyServesTLSThroughTheTPM2ProviderTPMO1(t *testing.T) {
	sock := os.Getenv("TRSTCTL_SWTPM_PATH")
	if sock == "" || os.Getenv("TRSTCTL_TPM2_PROVIDER") != "1" {
		t.Skip("TRSTCTL_SWTPM_PATH and TRSTCTL_TPM2_PROVIDER=1 (an image with tpm2-openssl and nginx) are required")
	}
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: sock, PersistentHandleBase: 0x8101b000})
	if err != nil {
		t.Fatal(err)
	}
	host := dev.(tpm.HostKeyDevice)
	file, publicDER, err := host.CreateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	// A server certificate over a CSR the TPM signed, from a lab CA, as a
	// renewal installs it.
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "web.lab.test", DNSNames: []string{"web.lab.test"}},
		tpm.HostKeySigner(host, file, publicDER))
	if err != nil {
		t.Fatalf("CSR signed by the TPM: %v", err)
	}
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := crypto.SelfSignedCACert(ca, "TPM-O1 lab CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, err := crypto.SignServerCertFromCSR(caDER, ca, csrDER, []string{"web.lab.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafBlock, _ := pem.Decode(chainPEM)
	if leafBlock == nil {
		t.Fatal("the issued chain has no certificate")
	}
	certDER := leafBlock.Bytes
	dir := t.TempDir()
	keyPath, certPath, confPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "openssl.cnf")
	for path, body := range map[string][]byte{keyPath: file, certPath: chainPEM, confPath: []byte(tpm2ProviderConf)} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// go-tpm's socket transport opens a connection per command, so the device
	// holds none now (Close reports that), and the resource manager takes
	// swtpm's next.
	_ = dev.Close()
	env := append(startResourceManager(t, sock), "OPENSSL_CONF="+confPath)

	port := freeLoopbackPort(t)
	server := exec.Command("openssl", "s_server", "-accept", fmt.Sprintf("127.0.0.1:%d", port), "-key", keyPath, "-cert", certPath, "-www") // #nosec G204 -- fixed tool and test paths (CWE-78)
	server.Env = env
	var serverLog bytes.Buffer
	server.Stdout, server.Stderr = &serverLog, &serverLog
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	if leaf := servedLeaf(t, fmt.Sprintf("127.0.0.1:%d", port), serverLog.String); !bytes.Equal(leaf, certDER) {
		t.Fatalf("openssl s_server served another certificate\n%s", serverLog.String())
	}
	_ = server.Process.Kill()
	_ = server.Wait()
	t.Log("TPMO1_PROVIDER_S_SERVER_OK")

	nginxPort := freeLoopbackPort(t)
	conf := fmt.Sprintf(`daemon off;
master_process off;
worker_processes 1;
error_log %s/error.log info;
pid %s/nginx.pid;
env OPENSSL_CONF;
env TPM2OPENSSL_TCTI;
env DBUS_SESSION_BUS_ADDRESS;
events { worker_connections 16; }
http {
  access_log off;
  client_body_temp_path %s;
  server {
    listen 127.0.0.1:%d ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate %s;
    ssl_certificate_key %s;
    location / { return 200 "ok"; }
  }
}
`, dir, dir, dir, nginxPort, certPath, keyPath)
	nginxConf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(nginxConf, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	nginx := exec.Command("nginx", "-c", nginxConf, "-p", dir) // #nosec G204 -- fixed tool and test paths (CWE-78)
	nginx.Env = env
	var nginxLog bytes.Buffer
	nginx.Stdout, nginx.Stderr = &nginxLog, &nginxLog
	if err := nginx.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nginx.Process.Kill(); _ = nginx.Wait() })
	nginxLogs := func() string {
		errLog, _ := os.ReadFile(filepath.Join(dir, "error.log")) // #nosec G304 -- the test's own temp directory (CWE-22)
		return nginxLog.String() + string(errLog)
	}
	if leaf := servedLeaf(t, fmt.Sprintf("127.0.0.1:%d", nginxPort), nginxLogs); !bytes.Equal(leaf, certDER) {
		t.Fatalf("nginx served another certificate\n%s", nginxLogs())
	}
	t.Log("TPMO1_PROVIDER_NGINX_OK")

	// The documented limit: with the provider preferred, OpenSSL 3.0 drops
	// P-256 from its TLS groups (tpm2-openssl 1.1.1 advertises none of its
	// own), so a TLS 1.2 handshake finds no ECDSA suite for the TPM-held
	// P-256 key; TLS 1.3, which does not tie the certificate's curve to a
	// group, is served. If a later package serves TLS 1.2 too, this says so.
	_, err = tlsprobe.Probe(context.Background(), fmt.Sprintf("127.0.0.1:%d", nginxPort),
		tlsprobe.WithTimeout(15*time.Second), tlsprobe.WithMaxVersion(tlsprobe.TLSVersion12))
	if err == nil {
		t.Fatal("nginx now serves TLS 1.2 with the TPM-held P-256 key: update the TPM-O1 host requirements in docs/features/certificate-lifecycle.md")
	}
	if !strings.Contains(err.Error(), "handshake failure") {
		t.Fatalf("TLS 1.2 failed otherwise than documented: %v\n%s", err, nginxLogs())
	}
	// nginx may write the line just after the client reads the alert.
	waitFor(t, "nginx's no-shared-cipher line for the TLS 1.2 handshake", func() bool {
		return strings.Contains(nginxLogs(), "no shared cipher")
	}, nginxLogs)
	t.Log("TPMO1_PROVIDER_TLS12_REFUSED_AS_DOCUMENTED")
}
