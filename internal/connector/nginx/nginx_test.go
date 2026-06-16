package nginx_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/nginx"
	"trstctl.com/trstctl/internal/connector/nginx/nginxtest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	certPath = "/etc/nginx/tls/site.crt"
	keyPath  = "/etc/nginx/tls/site.key"
)

var (
	goodCert = []byte("-----BEGIN CERTIFICATE-----\nMIIB-renewed-leaf\n-----END CERTIFICATE-----\n")
	tlsKey   = []byte("-----BEGIN PRIVATE KEY-----\nMIIB-key\n-----END PRIVATE KEY-----\n")
	badCert  = []byte("this is not a certificate\n")
)

func deploy(t *testing.T, ops connector.Ops, cert, key []byte) error {
	t.Helper()
	return mustErr(connector.Run(context.Background(), nginx.New(certPath, keyPath), ops, connector.NewDeployment("web-1", cert, key)))
}

func mustErr(_ connector.Stats, err error) error { return err }

// TestNginxDeploysAndReloads is the acceptance: a renewed cert is written to the
// paths nginx.conf references, the configuration is validated, and nginx is
// reloaded to serve it.
func TestNginxDeploysAndReloads(t *testing.T) {
	srv := nginxtest.New(certPath)
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
		t.Errorf("nginx reloaded %d times, want 1", srv.Reloads())
	}
	if !bytes.Equal(srv.Active(), goodCert) {
		t.Error("nginx is not serving the renewed certificate after reload")
	}
}

// TestNginxBadCertIsNotReloaded is the safety property: a certificate that fails
// `nginx -t` is never reloaded, so nginx keeps serving the previous certificate.
func TestNginxBadCertIsNotReloaded(t *testing.T) {
	srv := nginxtest.New(certPath)
	err := deploy(t, srv, badCert, tlsKey)
	if err == nil {
		t.Fatal("deploying a certificate that fails validation should error")
	}
	if srv.Reloads() != 0 {
		t.Error("nginx was reloaded despite a failed configuration test")
	}
	if srv.Active() != nil {
		t.Error("nginx activated a certificate that failed validation")
	}
}

// TestNginxIsIdempotent: redeploying the same certificate leaves nginx serving
// exactly that certificate (the basis for at-least-once outbox delivery).
func TestNginxIsIdempotent(t *testing.T) {
	srv := nginxtest.New(certPath)
	for i := 0; i < 2; i++ {
		if err := deploy(t, srv, goodCert, tlsKey); err != nil {
			t.Fatalf("Deploy %d: %v", i, err)
		}
	}
	if !bytes.Equal(srv.Active(), goodCert) {
		t.Error("idempotent redeploy corrupted the served certificate")
	}
	if got, _ := srv.File(certPath); !bytes.Equal(got, goodCert) {
		t.Error("idempotent redeploy corrupted the cert file")
	}
}

// TestNginxIsLeastPrivilege: the connector needs only to write under its cert
// directory and run nginx — never the network.
func TestNginxIsLeastPrivilege(t *testing.T) {
	g := nginx.New(certPath, keyPath).Capabilities()
	if !g.Has(pluginhost.CapFSWrite) {
		t.Error("nginx connector must be able to write its certificate")
	}
	if !g.Has(connector.CapExec) {
		t.Error("nginx connector must be able to run nginx (-t / reload)")
	}
	if g.Has(pluginhost.CapNetDial) {
		t.Error("nginx connector should not request network access")
	}
	if !g.Allows(pluginhost.CapFSWrite, certPath) {
		t.Error("grant does not cover the certificate path")
	}
	if g.Allows(pluginhost.CapFSWrite, "/etc/passwd") {
		t.Error("grant is not scoped to the certificate directory")
	}
}

// TestNginxPassesConformance: the connector passes the shared conformance suite.
func TestNginxPassesConformance(t *testing.T) {
	report := connector.Conformance(context.Background(), nginx.New(certPath, keyPath))
	if !report.OK() {
		t.Errorf("nginx connector failed conformance: %+v", report.Checks)
	}
}
