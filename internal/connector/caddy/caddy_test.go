// SPDX-License-Identifier: MPL-2.0

package caddy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/caddy"
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
	keyA  = []byte("-----BEGIN PRIVATE KEY-----\nkey-a\n-----END PRIVATE KEY-----\n")
	certB = []byte("-----BEGIN CERTIFICATE-----\ncert-b\n-----END CERTIFICATE-----\n")
	keyB  = []byte("-----BEGIN PRIVATE KEY-----\nkey-b\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesIdempotentlyAndReloads(t *testing.T) {
	ops := connector.NewMemoryOps()
	c := caddy.New("/etc/caddy/cert.pem", "/etc/caddy/key.pem", caddy.WithReloadCommand([]string{"caddy", "reload"}))
	dep := connector.NewDeployment("edge", certA, keyA)
	assertShippedFingerprint(t, dep.Fingerprint, certA)

	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("first Deploy: %v", err)
	}
	assertFile(t, ops, "/etc/caddy/cert.pem", certA)
	assertFile(t, ops, "/etc/caddy/key.pem", keyA)
	if got := ops.Execs(); len(got) != 1 || strings.Join(got[0], " ") != "caddy reload" {
		t.Fatalf("execs after first deploy = %v, want one caddy reload", got)
	}

	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("second Deploy: %v", err)
	}
	if got := ops.Execs(); len(got) != 1 {
		t.Fatalf("idempotent deploy exec count = %d, want still 1", len(got))
	}
	assertFile(t, ops, "/etc/caddy/cert.pem", certA)
	assertFile(t, ops, "/etc/caddy/key.pem", keyA)
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

func TestDeployRollbackRestoresPreviousFilesOnReloadFailure(t *testing.T) {
	base := connector.NewMemoryOps()
	if err := base.WriteFile("/etc/caddy/cert.pem", certA); err != nil {
		t.Fatal(err)
	}
	if err := base.WriteFile("/etc/caddy/key.pem", keyA); err != nil {
		t.Fatal(err)
	}
	ops := &failingExecOps{MemoryOps: base, err: errors.New("reload rejected config")}
	c := caddy.New("/etc/caddy/cert.pem", "/etc/caddy/key.pem")

	_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("edge", certB, keyB))
	if err == nil {
		t.Fatal("Deploy succeeded; want reload failure")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("Deploy error = %q, want rollback context", err)
	}
	assertFile(t, base, "/etc/caddy/cert.pem", certA)
	assertFile(t, base, "/etc/caddy/key.pem", keyA)
}

func TestValidateReloadCommandRejectsInjection(t *testing.T) {
	cases := [][]string{
		{"caddy;rm", "reload"},
		{"caddy", "reload|whoami"},
		{"sh", "-c", "caddy reload"},
		{"caddy", "reload\nagain"},
	}
	for _, tc := range cases {
		if err := caddy.ValidateReloadCommand(tc); err == nil {
			t.Fatalf("ValidateReloadCommand(%q) succeeded; want rejection", tc)
		}
	}
}

type failingExecOps struct {
	*connector.MemoryOps
	err error
}

func (f *failingExecOps) Exec(name string, args []string) error {
	_ = f.MemoryOps.Exec(name, args)
	return f.err
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
