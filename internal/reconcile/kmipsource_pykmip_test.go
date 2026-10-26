// SPDX-License-Identifier: BUSL-1.1

package reconcile_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/canon"
)

const pykmipImage = "trstctl-pykmip-test:a124"

// A124's independent proof: the KMIP source observes a PyKMIP server, an
// implementation trstctl does not share code with, over mutual TLS. PyKMIP's
// TLS stops at 1.2, so the default TLS 1.3 floor is refused and the per-server
// opt-in reaches it. The proof builds a Python image from PyPI, so it runs
// only when asked:
//
//	TRSTCTL_PYKMIP_PROOF=1 go test ./internal/reconcile -run PyKMIP -v
func TestKMIPSourceObservesAPyKMIPServer(t *testing.T) {
	if os.Getenv("TRSTCTL_PYKMIP_PROOF") != "1" {
		t.Skip("set TRSTCTL_PYKMIP_PROOF=1 to run the PyKMIP proof (needs Docker and PyPI)")
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
	docker("build", "-q", "-t", pykmipImage, filepath.Join("testdata", "pykmip"))

	// TLS material: the server certificate names kmip.lab.test, the client
	// certificate seeds the objects and then observes them, and a CA
	// certificate is the object registered for observation.
	material, err := mtls.GenerateSignerPeerMaterial(t.TempDir(), "kmip.lab.test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pki := t.TempDir()
	for dst, src := range map[string]string{
		"ca.pem": material.Signer.PeerCAFile, "server.pem": material.Signer.CertFile, "server-key.pem": material.Signer.KeyFile,
		"client.pem": material.ControlPlane.CertFile, "client-key.pem": material.ControlPlane.KeyFile,
	} {
		raw, err := os.ReadFile(src) // #nosec G304 -- test-generated TLS material in the test's temp dir (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pki, dst), raw, 0o644); err != nil { // #nosec G306 G703 -- test-named files in the test's temp dir, readable by the container's server user (CWE-22, CWE-276)
			t.Fatal(err)
		}
	}
	observedKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(observedKey.Destroy)
	observedDER, err := crypto.SelfSignedCACert(observedKey, "PyKMIP Observed CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "observed-ca.der"), observedDER, 0o644); err != nil { // #nosec G306 -- a public certificate (CWE-276)
		t.Fatal(err)
	}
	conf := strings.Join([]string{
		"[server]", "hostname=0.0.0.0", "port=5696",
		"certificate_path=/pki/server.pem", "key_path=/pki/server-key.pem", "ca_path=/pki/ca.pem",
		"auth_suite=TLS1.2", "policy_path=/opt/kmip/policies", "enable_tls_client_auth=True",
		"tls_cipher_suites=", "    ECDHE-ECDSA-AES128-GCM-SHA256", "    ECDHE-ECDSA-AES256-GCM-SHA384",
		"logging_level=INFO", "database_path=/tmp/pykmip.db", "",
	}, "\n")
	if err := os.WriteFile(filepath.Join(pki, "server.conf"), []byte(conf), 0o644); err != nil { // #nosec G306 -- test server configuration (CWE-276)
		t.Fatal(err)
	}

	name := fmt.Sprintf("trstctl-pykmip-a124-%d", time.Now().UnixNano())
	docker("run", "-d", "--name", name, "-p", "127.0.0.1::5696", "-v", pki+":/pki:ro", pykmipImage,
		"pykmip-server", "-f", "/pki/server.conf", "-l", "/tmp/pykmip-server.log")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() }) // #nosec G204 -- removes the test's own container (CWE-78)
	port := strings.TrimSpace(docker("port", name, "5696/tcp"))
	addr := port[strings.LastIndex(port, "\n")+1:]
	deadline := time.Now().Add(60 * time.Second)
	for {
		seeded, err := exec.Command("docker", "exec", name, "python", "/opt/kmip/seed.py").CombinedOutput() // #nosec G204 -- fixed seeding script inside the test's own container (CWE-78)
		if err == nil {
			t.Logf("seeded objects: %s", bytes.TrimSpace(seeded))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("seed the PyKMIP server: %v\n%s\n%s", err, seeded, docker("exec", name, "cat", "/tmp/pykmip-server.log"))
		}
		time.Sleep(2 * time.Second)
	}

	observe := func(allowTLS12 bool) (canon.Set, error) {
		rt, err := reconcile.NewRuntime(reconcile.RuntimeConfig{KMIPSources: []reconcile.KMIPSourceConfig{{
			AuthorityID: "kmip-pykmip", Address: addr, ServerName: "kmip.lab.test",
			CAFile: material.ControlPlane.PeerCAFile, ClientCertFile: material.ControlPlane.CertFile,
			ClientKeyFile: material.ControlPlane.KeyFile, AllowTLS12: allowTLS12, AllowLoopback: true,
			Dial: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		}}})
		if err != nil {
			return canon.Set{}, err
		}
		obs, err := rt.Reducers.Observe(context.Background(), "kmip-pykmip", "11111111-1111-1111-1111-111111111111")
		return obs.Set, err
	}
	if _, err := observe(false); err == nil {
		t.Fatal("the TLS 1.3 floor reached PyKMIP, whose TLS stops at 1.2; the opt-in proves nothing")
	}
	set, err := observe(true)
	if err != nil {
		t.Fatalf("observe PyKMIP with the TLS 1.2 opt-in: %v\nserver log:\n%s", err, docker("exec", name, "cat", "/tmp/pykmip-server.log"))
	}
	byType, byStatus := map[string]int{}, map[string]int{}
	var certificate canon.CanonicalRecord
	for _, rec := range set.Records {
		byType[rec.RecordType]++
		byStatus[rec.Status]++
		if rec.RecordType == canon.RecordTypeX509Certificate {
			certificate = rec
		}
	}
	t.Logf("observed %d records: types %v statuses %v", len(set.Records), byType, byStatus)
	if byType[canon.RecordTypeKey] != 2 || byType[canon.RecordTypeX509Certificate] != 1 {
		t.Fatalf("record types = %v, want the two AES keys and the certificate", byType)
	}
	if byStatus[canon.StatusActive] < 1 {
		t.Fatalf("statuses = %v, want the activated key active", byStatus)
	}
	issuer, serial, err := crypto.CertificateIssuerAndSerial(observedDER)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canon.X509StableID(issuer, serial)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.RecordKey.StableID != want {
		t.Fatalf("certificate identity = %q, want the registered certificate's issuer and serial (%q)", certificate.RecordKey.StableID, want)
	}
}
