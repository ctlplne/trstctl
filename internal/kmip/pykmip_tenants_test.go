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

// A197: PyKMIP clients of two tenants share one listener. Each enrolls its own
// certificate with its tenant's username and password and creates a key pair;
// tenant B is told tenant A's object does not exist, every object each one
// locates carries only its own tenant's name, and tenant A's certificate is
// served again on a later connection with no credential. Opt-in like the
// other PyKMIP proof:
//
//	TRSTCTL_PYKMIP_PROOF=1 go test ./internal/kmip -run PyKMIP -v
func TestPyKMIPClientsOfTwoTenantsShareOneListener(t *testing.T) {
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

	deployment, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "kmip.pykmip.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pkiFor := func(name string) string {
		t.Helper()
		own, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), name+".test", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		for dst, src := range map[string]string{
			"ca.pem": deployment.ControlPlane.PeerCAFile, "client.pem": own.ControlPlane.CertFile, "client-key.pem": own.ControlPlane.KeyFile,
		} {
			raw, err := os.ReadFile(src) // #nosec G304 -- test-generated TLS material in the test's temp dir (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, dst), raw, 0o644); err != nil { // #nosec G306 G703 -- test-named files in the test's temp dir, readable by the container user (CWE-22, CWE-276)
				t.Fatal(err)
			}
		}
		return dir
	}
	const userA, userB = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	directory := &fakeClientDirectory{bound: map[string]string{}, enrollments: map[string][2]string{
		userA: {"tenant-a", "secret-a"}, userB: {"tenant-b", "secret-b"},
	}}
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
			Enabled: true, ClientRegistrations: true, Addr: "0.0.0.0:0",
			CertFile: deployment.Signer.CertFile, KeyFile: deployment.Signer.KeyFile,
		}},
		Bulkhead:   poolSet,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		EventLog:   log,
		KeyWrapper: wrapper,
		Clients:    directory,
	})
	if err != nil {
		t.Fatal(err)
	}
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
	run := func(pki string, args ...string) string {
		t.Helper()
		base := []string{"run", "--rm", "--add-host=host.docker.internal:host-gateway", "-v", pki + ":/pki:ro", pykmipClientImage,
			"--host", "host.docker.internal", "--port", port, "--ca", "/pki/ca.pem", "--cert", "/pki/client.pem", "--key", "/pki/client-key.pem"}
		out := docker(append(base, args...)...)
		if !strings.Contains(out, "PYKMIP_TENANT_OK") {
			t.Fatalf("PyKMIP isolation flow %v:\n%s", args, out)
		}
		return out
	}
	pkiA, pkiB := pkiFor("appliance-a"), pkiFor("appliance-b")
	first := run(pkiA, "--username", userA, "--password", "secret-a", "--name", "tenant-a", "isolation")
	privateA := strings.TrimPrefix(strings.Fields(first[strings.Index(first, "private="):])[0], "private=")
	run(pkiB, "--username", userB, "--password", "secret-b", "--name", "tenant-b", "--foreign", privateA, "isolation")
	again := run(pkiA, "--name", "tenant-a", "isolation")
	t.Logf("PyKMIP tenants: A %s; A again %s", strings.TrimSpace(first), strings.TrimSpace(again))
}
