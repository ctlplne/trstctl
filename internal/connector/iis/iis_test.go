// SPDX-License-Identifier: MPL-2.0

package iis_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/iis"
	"trstctl.com/trstctl/internal/connector/iis/iistest"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/pluginhost"
)

const binding = "0.0.0.0:443"

// A real ECDSA P-256 certificate and key: the IIS connector parses the
// certificate (to compute its thumbprint) and packages it (PFX), so the test
// material must be valid.
var (
	realCert = []byte(`-----BEGIN CERTIFICATE-----
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
	realKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2drNvkGQeqFUx3xE
zejpKQlXChZFd7J3qw/JXoL+x72hRANCAAThNg201ttWU9xWnLOcm66MA1dNuxpE
0vkPjUpV8HkZ0kQbfvY+C2fn0ynv7X49RvIdNtoonVFTSfq+Bbn8EILV
-----END PRIVATE KEY-----
`)
	badCert = []byte("this is not a certificate\n")
)

func deploy(t *testing.T, ops connector.Ops, cert, key []byte) error {
	t.Helper()
	_, err := connector.Run(context.Background(), iis.New(binding), ops, connector.NewDeployment("site", cert, key))
	return err
}

// TestIISImportsAndBinds is the acceptance: the renewed cert is imported into
// the Windows store and its thumbprint is bound to the HTTPS site binding.
func TestIISImportsAndBinds(t *testing.T) {
	srv := iistest.New()
	if err := deploy(t, srv, realCert, realKey); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	if srv.Imports() == 0 {
		t.Error("certificate was not imported into the store")
	}
	thumb, err := certinfo.Thumbprint(realCert)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := srv.Binding(binding)
	if !ok {
		t.Fatalf("no SSL binding was created for %s", binding)
	}
	if got != thumb {
		t.Errorf("bound certhash = %q, want the cert thumbprint %q", got, thumb)
	}
}

// TestIISBadCertRejectedBeforeBinding is the safety property: a malformed
// certificate is rejected before anything is imported or bound.
func TestIISBadCertRejectedBeforeBinding(t *testing.T) {
	srv := iistest.New()
	if err := deploy(t, srv, badCert, realKey); err == nil {
		t.Fatal("deploying a malformed certificate should error")
	}
	if srv.Imports() != 0 {
		t.Error("a malformed certificate was imported")
	}
	if _, ok := srv.Binding(binding); ok {
		t.Error("a binding was created for a malformed certificate")
	}
}

// TestIISIsIdempotent: redeploying the same certificate leaves the site bound to
// exactly that certificate's thumbprint.
func TestIISIsIdempotent(t *testing.T) {
	srv := iistest.New()
	for i := 0; i < 2; i++ {
		if err := deploy(t, srv, realCert, realKey); err != nil {
			t.Fatalf("Deploy %d: %v", i, err)
		}
	}
	thumb, _ := certinfo.Thumbprint(realCert)
	if got, _ := srv.Binding(binding); got != thumb {
		t.Errorf("after redeploy the binding = %q, want %q", got, thumb)
	}
}

func TestIISStagesPFXSecretsOutsideProcessArguments(t *testing.T) {
	srv := iistest.New()
	if err := deploy(t, srv, realCert, realKey); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	var staged [][]byte
	for _, writes := range srv.Writes() {
		for _, data := range writes {
			if len(data) > 0 {
				staged = append(staged, data)
			}
		}
	}
	if len(staged) < 2 {
		t.Fatalf("expected non-empty PFX and password file writes, got %d", len(staged))
	}

	var args string
	for _, exec := range srv.Execs() {
		args += strings.Join(exec, "\x00")
	}
	if strings.Contains(args, string(realKey)) {
		t.Fatal("process arguments contain the private-key PEM")
	}
	for _, data := range staged {
		if strings.Contains(args, string(data)) {
			t.Fatal("process arguments contain staged secret file bytes")
		}
		if encoded := base64.StdEncoding.EncodeToString(data); encoded != "" && strings.Contains(args, encoded) {
			t.Fatal("process arguments contain base64-encoded staged secret bytes")
		}
	}
	for path, data := range srv.Files() {
		if len(data) != 0 {
			t.Fatalf("staged file %q retained %d secret bytes after cleanup", path, len(data))
		}
	}
}

// TestIISIsLeastPrivilege: the IIS connector runs commands (import + netsh) and
// writes only its scoped transient import files — no network and no arbitrary fs.
func TestIISIsLeastPrivilege(t *testing.T) {
	const tempDir = "C:/secure/trstctl-iis"
	g := iis.New(binding, iis.WithImportDir(tempDir)).Capabilities()
	if !g.Has(connector.CapExec) {
		t.Error("iis connector must be able to run commands")
	}
	if !g.Has(pluginhost.CapFSWrite) {
		t.Error("iis connector must write scoped transient import files")
	}
	if !g.Allows(pluginhost.CapFSWrite, tempDir+"/credential.pfx") {
		t.Error("iis connector must be able to write inside its import temp dir")
	}
	if g.Allows(pluginhost.CapFSWrite, "C:/secure/other/credential.pfx") {
		t.Error("iis connector must not write outside its import temp dir")
	}
	if g.Has(pluginhost.CapNetDial) {
		t.Error("iis connector should not request network access")
	}
}

// TestIISPassesConformance: the connector passes the shared conformance suite.
func TestIISPassesConformance(t *testing.T) {
	report := connector.Conformance(context.Background(), iis.New(binding))
	if !report.OK() {
		t.Errorf("iis connector failed conformance: %+v", report.Checks)
	}
}
