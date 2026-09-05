// SPDX-License-Identifier: MPL-2.0

package traefik_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/traefik"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

var (
	certA = []byte(`-----BEGIN CERTIFICATE-----
MIIBiDCCAS2gAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDExpjb25mb3Jt
YW5jZS5jb25uZWN0b3IudGVzdDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAw
MDBaMCUxIzAhBgNVBAMTGmNvbmZvcm1hbmNlLmNvbm5lY3Rvci50ZXN0MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE4TYNtNbbVlPcVpyznJuujANXTbsaRNL5D41K
VfB5GdJEG372Pgtn59Mp7+1+PUbyHTbaKJ1RU0n6vgW5/BCC1aNOMEwwDgYDVR0P
AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCUGA1UdEQQeMByCGmNvbmZv
cm1hbmNlLmNvbm5lY3Rvci50ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQD2NqiRyoq8
T1vJogCsCMRDiEMMsA04Qhbs5uF149egpgIhALTX3I6Xe4dQk3GMTEaXC5GWXkaj
O9xXOtFRqPTY0dXn
-----END CERTIFICATE-----
`)
	keyA  = []byte("-----BEGIN PRIVATE KEY-----\ntraefik-key-a\n-----END PRIVATE KEY-----\n")
	certB = []byte("-----BEGIN CERTIFICATE-----\ntraefik-cert-b\n-----END CERTIFICATE-----\n")
	keyB  = []byte("-----BEGIN PRIVATE KEY-----\ntraefik-key-b\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesIdempotently(t *testing.T) {
	base := connector.NewMemoryOps()
	if err := base.WriteFile("/etc/traefik/dynamic.yml", []byte("tls: {}\n")); err != nil {
		t.Fatal(err)
	}
	ops := &countingOps{MemoryOps: base}
	c := traefik.New("/etc/traefik/certs/site.pem", "/etc/traefik/certs/site.key",
		traefik.WithDynamicConfigPath("/etc/traefik/dynamic.yml"))
	dep := connector.NewDeployment("edge", certA, keyA)
	assertShippedFingerprint(t, dep.Fingerprint, certA)

	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("first Deploy: %v", err)
	}
	assertFile(t, base, "/etc/traefik/certs/site.pem", certA)
	assertFile(t, base, "/etc/traefik/certs/site.key", keyA)
	if ops.writes != 3 {
		t.Fatalf("first deploy writes = %d, want cert+key plus a dynamic-config watcher event", ops.writes)
	}

	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("second Deploy: %v", err)
	}
	if ops.writes != 3 {
		t.Fatalf("idempotent deploy writes = %d, want still 3", ops.writes)
	}
}

func assertShippedFingerprint(t *testing.T, got string, cert []byte) {
	t.Helper()
	info, err := certinfo.Inspect(cert)
	if err != nil {
		t.Fatalf("inspect certificate fixture: %v", err)
	}
	if got != info.SHA256Fingerprint {
		t.Fatalf("deployment fingerprint = %q, want shipped DER fingerprint %q", got, info.SHA256Fingerprint)
	}
}

func TestDeployRollsBackWhenKeyWriteFails(t *testing.T) {
	base := connector.NewMemoryOps()
	if err := base.WriteFile("/etc/traefik/certs/site.pem", certA); err != nil {
		t.Fatal(err)
	}
	if err := base.WriteFile("/etc/traefik/certs/site.key", keyA); err != nil {
		t.Fatal(err)
	}
	ops := &failWriteOps{
		MemoryOps: base,
		failPath:  "/etc/traefik/certs/site.key",
		err:       errors.New("disk full"),
	}
	c := traefik.New("/etc/traefik/certs/site.pem", "/etc/traefik/certs/site.key")

	_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("edge", certB, keyB))
	if err == nil {
		t.Fatal("Deploy succeeded; want key-write failure")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("Deploy error = %q, want rollback context", err)
	}
	assertFile(t, base, "/etc/traefik/certs/site.pem", certA)
	assertFile(t, base, "/etc/traefik/certs/site.key", keyA)
}

type countingOps struct {
	*connector.MemoryOps
	writes int
}

func (c *countingOps) WriteFile(path string, data []byte) error {
	c.writes++
	return c.MemoryOps.WriteFile(path, data)
}

type failWriteOps struct {
	*connector.MemoryOps
	failPath string
	err      error
}

func (f *failWriteOps) WriteFile(path string, data []byte) error {
	if path == f.failPath {
		return f.err
	}
	return f.MemoryOps.WriteFile(path, data)
}

func assertFile(t *testing.T, ops *connector.MemoryOps, path string, want []byte) {
	t.Helper()
	got, ok := ops.File(path)
	if !ok {
		t.Fatalf("%s was not written", path)
	}
	if string(got) != string(want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
