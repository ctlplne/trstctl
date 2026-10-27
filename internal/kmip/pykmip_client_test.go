// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/server"
)

const pykmipClientImage = "trstctl-pykmip-client:a197"

// The independent client proof (A197): PyKMIP, a KMIP implementation trstctl
// shares no code with, drives the shipped listener over mutual TLS. It creates
// and reads an AES key, then creates RSA and ECDSA key pairs, finds them
// Pre-Active and unable to sign, activates and signs with them, verifies on
// the server and on its own with the public key it reads back, is refused the
// private key, and revokes one for compromise. The proof builds a Python image
// from PyPI, so it runs only when asked:
//
//	TRSTCTL_PYKMIP_PROOF=1 go test ./internal/kmip -run PyKMIP -v
func TestPyKMIPClientDrivesTheServedListener(t *testing.T) {
	if os.Getenv("TRSTCTL_PYKMIP_PROOF") != "1" {
		t.Skip("set TRSTCTL_PYKMIP_PROOF=1 to run the PyKMIP client proof (needs Docker and PyPI)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	docker := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed docker subcommands with test-owned arguments (CWE-78)
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	docker("build", "-q", "-t", pykmipClientImage, filepath.Join("testdata", "pykmip-client"))

	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "kmip.pykmip.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pki := t.TempDir()
	for dst, src := range map[string]string{
		"ca.pem": material.ControlPlane.PeerCAFile, "client.pem": material.ControlPlane.CertFile, "client-key.pem": material.ControlPlane.KeyFile,
	} {
		raw, err := os.ReadFile(src) // #nosec G304 -- test-generated TLS material in the test's temp dir (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pki, dst), raw, 0o644); err != nil { // #nosec G306 G703 -- test-named files in the test's temp dir, readable by the container user (CWE-22, CWE-276)
			t.Fatal(err)
		}
	}

	poolSet := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemKMIP, Workers: 2, Queue: 4})
	t.Cleanup(poolSet.Close)
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	kekBytes, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := seal.NewLocalKEK(kekBytes)
	secret.Wipe(kekBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrapper.Destroy)
	runtime, err := NewFactory()(server.KMIPFactoryDeps{
		StartupContext: context.Background(),
		Protocols: config.Protocols{KMIP: config.KMIPProtocol{
			Enabled: true, TenantID: "tenant-pykmip", Addr: "0.0.0.0:0",
			CertFile: material.Signer.CertFile, KeyFile: material.Signer.KeyFile, ClientCAFile: material.Signer.PeerCAFile,
		}},
		ProtocolTenant: "tenant-pykmip",
		Bulkhead:       poolSet,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		EventLog:       log,
		KeyWrapper:     wrapper,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The container reaches the host through host.docker.internal, so the
	// listener takes every interface for the length of the proof.
	ln, err := net.Listen("tcp", "0.0.0.0:0") // #nosec G102 -- a test listener the PyKMIP container dials through the Docker host gateway; mutual TLS still applies (CWE-200)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
		runtime.Close()
	})
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	run := func(flow string) string {
		t.Helper()
		return docker("run", "--rm", "--add-host=host.docker.internal:host-gateway", "-v", pki+":/pki:ro", pykmipClientImage,
			"--host", "host.docker.internal", "--port", port,
			"--ca", "/pki/ca.pem", "--cert", "/pki/client.pem", "--key", "/pki/client-key.pem", flow)
	}
	if out := run("aes"); !strings.Contains(out, "PYKMIP_AES_OK") {
		t.Fatalf("PyKMIP AES flow:\n%s", out)
	}
	out := run("keypair")
	if !strings.Contains(out, "PYKMIP_KEYPAIR_OK") {
		t.Fatalf("PyKMIP key pair flow:\n%s", out)
	}
	t.Logf("PyKMIP: %s", strings.TrimSpace(out))
}
