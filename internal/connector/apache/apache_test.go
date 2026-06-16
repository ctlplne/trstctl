package apache_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/apache"
	"trstctl.com/trstctl/internal/connector/apache/apachetest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	certPath = "/etc/apache2/tls/site.crt"
	keyPath  = "/etc/apache2/tls/site.key"
)

var (
	goodCert = []byte("-----BEGIN CERTIFICATE-----\nMIIB-renewed-leaf\n-----END CERTIFICATE-----\n")
	tlsKey   = []byte("-----BEGIN PRIVATE KEY-----\nMIIB-key\n-----END PRIVATE KEY-----\n")
	badCert  = []byte("this is not a certificate\n")
)

func deploy(t *testing.T, ops connector.Ops, cert, key []byte) error {
	t.Helper()
	_, err := connector.Run(context.Background(), apache.New(certPath, keyPath), ops, connector.NewDeployment("web-1", cert, key))
	return err
}

// TestApacheDeploysAndReloads is the acceptance: a renewed cert is written to the
// SSLCertificateFile/SSLCertificateKeyFile paths, the configuration passes
// `apachectl configtest`, and `apachectl graceful` activates it.
func TestApacheDeploysAndReloads(t *testing.T) {
	srv := apachetest.New(certPath)
	if err := deploy(t, srv, goodCert, tlsKey); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	if got, ok := srv.File(certPath); !ok || !bytes.Equal(got, goodCert) {
		t.Errorf("certificate not written to %s", certPath)
	}
	if got, ok := srv.File(keyPath); !ok || !bytes.Equal(got, tlsKey) {
		t.Errorf("key not written to %s", keyPath)
	}
	if srv.Reloads() != 1 {
		t.Errorf("apache gracefully reloaded %d times, want 1", srv.Reloads())
	}
	if !bytes.Equal(srv.Active(), goodCert) {
		t.Error("apache is not serving the renewed certificate after graceful reload")
	}
}

// TestApacheBadCertIsNotReloaded is the safety property: a certificate that fails
// `apachectl configtest` is never made live, so apache keeps serving the
// previous certificate.
func TestApacheBadCertIsNotReloaded(t *testing.T) {
	srv := apachetest.New(certPath)
	if err := deploy(t, srv, badCert, tlsKey); err == nil {
		t.Fatal("deploying a certificate that fails configtest should error")
	}
	if srv.Reloads() != 0 {
		t.Error("apache was gracefully reloaded despite a failed configtest")
	}
	if srv.Active() != nil {
		t.Error("apache activated a certificate that failed configtest")
	}
}

// TestApacheIsIdempotent: redeploying the same certificate leaves apache serving
// exactly that certificate.
func TestApacheIsIdempotent(t *testing.T) {
	srv := apachetest.New(certPath)
	for i := 0; i < 2; i++ {
		if err := deploy(t, srv, goodCert, tlsKey); err != nil {
			t.Fatalf("Deploy %d: %v", i, err)
		}
	}
	if !bytes.Equal(srv.Active(), goodCert) {
		t.Error("idempotent redeploy corrupted the served certificate")
	}
}

// TestApacheIsLeastPrivilege: write under the cert directory and run apachectl,
// never the network.
func TestApacheIsLeastPrivilege(t *testing.T) {
	g := apache.New(certPath, keyPath).Capabilities()
	if !g.Has(pluginhost.CapFSWrite) || !g.Has(connector.CapExec) {
		t.Error("apache connector must be able to write the cert and run apachectl")
	}
	if g.Has(pluginhost.CapNetDial) {
		t.Error("apache connector should not request network access")
	}
	if !g.Allows(pluginhost.CapFSWrite, certPath) {
		t.Error("grant does not cover the certificate path")
	}
	if g.Allows(pluginhost.CapFSWrite, "/etc/passwd") {
		t.Error("grant is not scoped to the certificate directory")
	}
}

// TestApachePassesConformance: the connector passes the shared conformance suite.
func TestApachePassesConformance(t *testing.T) {
	report := connector.Conformance(context.Background(), apache.New(certPath, keyPath))
	if !report.OK() {
		t.Errorf("apache connector failed conformance: %+v", report.Checks)
	}
}
