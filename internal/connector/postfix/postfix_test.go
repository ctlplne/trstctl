// SPDX-License-Identifier: MPL-2.0

package postfix_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/postfix"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/pluginhost"
)

var (
	mailCertA = []byte(`-----BEGIN CERTIFICATE-----
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
	mailKeyA  = []byte("-----BEGIN PRIVATE KEY-----\nmail-key-a\n-----END PRIVATE KEY-----\n")
	mailCertB = []byte("-----BEGIN CERTIFICATE-----\nmail-cert-b\n-----END CERTIFICATE-----\n")
	mailKeyB  = []byte("-----BEGIN PRIVATE KEY-----\nmail-key-b\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesBothServicesIdempotentlyAndReloads(t *testing.T) {
	ops := connector.NewMemoryOps()
	registry := observ.NewRegistry()
	c := postfix.New(testConfig(), postfix.WithMetrics(registry))
	dep := connector.NewDeployment("mail/edge", mailCertA, mailKeyA)
	assertShippedFingerprint(t, dep.Fingerprint, mailCertA)

	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("first deploy: %v", err)
	}
	assertFile(t, ops, "/etc/postfix/certs/server.pem", mailCertA)
	assertFile(t, ops, "/etc/postfix/certs/server.key", mailKeyA)
	assertFile(t, ops, "/etc/dovecot/certs/server.pem", mailCertA)
	assertFile(t, ops, "/etc/dovecot/certs/server.key", mailKeyA)
	assertExecs(t, ops.Execs(),
		"postfix check",
		"doveconf -n",
		"postfix reload",
		"doveadm reload",
	)

	if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
		t.Fatalf("idempotent deploy: %v", err)
	}
	assertExecs(t, ops.Execs(),
		"postfix check",
		"doveconf -n",
		"postfix reload",
		"doveadm reload",
	)

	var metrics bytes.Buffer
	if err := registry.WriteProm(&metrics); err != nil {
		t.Fatalf("render metrics: %v", err)
	}
	text := metrics.String()
	if !strings.Contains(text, `trstctl_postfix_deployments_total{target="mail/edge",result="deployed"} 1`) {
		t.Fatalf("missing deployed counter:\n%s", text)
	}
	if !strings.Contains(text, `trstctl_postfix_deployments_total{target="mail/edge",result="noop"} 1`) {
		t.Fatalf("missing noop counter:\n%s", text)
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

func TestDeployRollsBackAllFilesOnReloadFailure(t *testing.T) {
	base := connector.NewMemoryOps()
	seedMailFiles(t, base, mailCertA, mailKeyA)
	ops := &mailFailExecOps{
		MemoryOps: base,
		failName:  "doveadm",
		failArgs:  []string{"reload"},
		err:       errors.New("dovecot rejected reload"),
	}
	c := postfix.New(testConfig())

	_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("mail/edge", mailCertB, mailKeyB))
	if err == nil {
		t.Fatal("deploy succeeded; want reload failure")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("deploy error = %q, want rollback context", err)
	}
	assertFile(t, base, "/etc/postfix/certs/server.pem", mailCertA)
	assertFile(t, base, "/etc/postfix/certs/server.key", mailKeyA)
	assertFile(t, base, "/etc/dovecot/certs/server.pem", mailCertA)
	assertFile(t, base, "/etc/dovecot/certs/server.key", mailKeyA)
}

func TestValidateCommandRejectsInjection(t *testing.T) {
	cases := [][]string{
		{"postfix;rm", "reload"},
		{"postfix", "reload|whoami"},
		{"sh", "-c", "postfix reload"},
		{"doveadm", "reload\nagain"},
	}
	for _, tc := range cases {
		if err := postfix.ValidateCommand(tc); err == nil {
			t.Fatalf("ValidateCommand(%q) succeeded; want rejection", tc)
		}
	}
}

func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	c := postfix.New(testConfig())
	g := c.Capabilities()
	if !g.Has(pluginhost.CapFSRead) || !g.Has(pluginhost.CapFSWrite) || !g.Has(connector.CapExec) {
		t.Fatal("mail connector must request fs.read, fs.write, and process.exec")
	}
	if g.Has(pluginhost.CapNetDial) {
		t.Fatal("mail connector must not request net.dial")
	}
	if g.Allows(pluginhost.CapFSWrite, "/etc/nginx/certs/server.pem") {
		t.Fatal("mail connector must scope filesystem writes to Postfix/Dovecot cert directories")
	}
}

func testConfig() postfix.Config {
	return postfix.Config{
		Postfix: postfix.ServiceConfig{
			CertPath:        "/etc/postfix/certs/server.pem",
			KeyPath:         "/etc/postfix/certs/server.key",
			ValidateCommand: []string{"postfix", "check"},
			ReloadCommand:   []string{"postfix", "reload"},
		},
		Dovecot: postfix.ServiceConfig{
			CertPath:        "/etc/dovecot/certs/server.pem",
			KeyPath:         "/etc/dovecot/certs/server.key",
			ValidateCommand: []string{"doveconf", "-n"},
			ReloadCommand:   []string{"doveadm", "reload"},
		},
	}
}

func seedMailFiles(t *testing.T, ops *connector.MemoryOps, cert, key []byte) {
	t.Helper()
	for _, service := range []postfix.ServiceConfig{testConfig().Postfix, testConfig().Dovecot} {
		if err := ops.WriteFile(service.CertPath, cert); err != nil {
			t.Fatal(err)
		}
		if err := ops.WriteFile(service.KeyPath, key); err != nil {
			t.Fatal(err)
		}
	}
}

type mailFailExecOps struct {
	*connector.MemoryOps
	failName string
	failArgs []string
	err      error
}

func (m *mailFailExecOps) Exec(name string, args []string) error {
	_ = m.MemoryOps.Exec(name, args)
	if name == m.failName && strings.Join(args, " ") == strings.Join(m.failArgs, " ") {
		return m.err
	}
	return nil
}

func assertFile(t *testing.T, ops *connector.MemoryOps, path string, want []byte) {
	t.Helper()
	got, ok := ops.File(path)
	if !ok {
		t.Fatalf("%s was not written", path)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func assertExecs(t *testing.T, got [][]string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("exec count = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if strings.Join(got[i], " ") != want[i] {
			t.Fatalf("exec[%d] = %q, want %q; all execs=%v", i, strings.Join(got[i], " "), want[i], got)
		}
	}
}
