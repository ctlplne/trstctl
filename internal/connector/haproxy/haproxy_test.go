package haproxy_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/haproxy"
	"trstctl.com/trstctl/internal/connector/haproxy/haproxytest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	crtPath = "/etc/haproxy/certs/site.pem"
	cfgPath = "/etc/haproxy/haproxy.cfg"
)

var (
	goodCert = []byte("-----BEGIN CERTIFICATE-----\nMIIB-renewed-leaf\n-----END CERTIFICATE-----\n")
	tlsKey   = []byte("-----BEGIN PRIVATE KEY-----\nMIIB-key\n-----END PRIVATE KEY-----\n")
	badCert  = []byte("this is not a certificate\n")
)

func deploy(t *testing.T, ops connector.Ops, cert, key []byte) error {
	t.Helper()
	_, err := connector.Run(context.Background(), haproxy.New(crtPath, cfgPath), ops, connector.NewDeployment("fe", cert, key))
	return err
}

// TestHAProxyDeploysAndReloads is the acceptance: the renewed cert and key are
// written as one combined PEM to the ssl crt path, the configuration passes
// `haproxy -c`, and `systemctl reload haproxy` activates it.
func TestHAProxyDeploysAndReloads(t *testing.T) {
	srv := haproxytest.New(crtPath)
	if err := deploy(t, srv, goodCert, tlsKey); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	bundle, ok := srv.File(crtPath)
	if !ok {
		t.Fatalf("no certificate bundle written to %s", crtPath)
	}
	// HAProxy reads the certificate and key from one file.
	if !bytes.Contains(bundle, goodCert) || !bytes.Contains(bundle, tlsKey) {
		t.Error("crt file does not contain both the certificate and the key")
	}
	if srv.Reloads() != 1 {
		t.Errorf("haproxy reloaded %d times, want 1", srv.Reloads())
	}
	if !bytes.Equal(srv.Active(), bundle) {
		t.Error("haproxy is not serving the renewed bundle after reload")
	}
}

// TestHAProxyBadBundleIsNotReloaded is the safety property: a bundle that fails
// `haproxy -c` is never reloaded; haproxy keeps serving the previous bundle.
func TestHAProxyBadBundleIsNotReloaded(t *testing.T) {
	srv := haproxytest.New(crtPath)
	if err := deploy(t, srv, badCert, tlsKey); err == nil {
		t.Fatal("deploying a bundle that fails the config check should error")
	}
	if srv.Reloads() != 0 {
		t.Error("haproxy was reloaded despite a failed config check")
	}
	if srv.Active() != nil {
		t.Error("haproxy activated a bundle that failed the config check")
	}
}

// TestHAProxyIsIdempotent: redeploying the same credential leaves haproxy
// serving exactly that bundle.
func TestHAProxyIsIdempotent(t *testing.T) {
	srv := haproxytest.New(crtPath)
	for i := 0; i < 2; i++ {
		if err := deploy(t, srv, goodCert, tlsKey); err != nil {
			t.Fatalf("Deploy %d: %v", i, err)
		}
	}
	bundle, _ := srv.File(crtPath)
	if !bytes.Equal(srv.Active(), bundle) {
		t.Error("idempotent redeploy corrupted the served bundle")
	}
}

// TestHAProxyIsLeastPrivilege: write under the cert directory and run haproxy /
// the reload command, never the network.
func TestHAProxyIsLeastPrivilege(t *testing.T) {
	g := haproxy.New(crtPath, cfgPath).Capabilities()
	if !g.Has(pluginhost.CapFSWrite) || !g.Has(connector.CapExec) {
		t.Error("haproxy connector must be able to write the bundle and reload")
	}
	if g.Has(pluginhost.CapNetDial) {
		t.Error("haproxy connector should not request network access")
	}
	if !g.Allows(pluginhost.CapFSWrite, crtPath) {
		t.Error("grant does not cover the certificate path")
	}
	if g.Allows(pluginhost.CapFSWrite, "/etc/passwd") {
		t.Error("grant is not scoped to the certificate directory")
	}
}

// TestHAProxyPassesConformance: the connector passes the shared conformance suite.
func TestHAProxyPassesConformance(t *testing.T) {
	report := connector.Conformance(context.Background(), haproxy.New(crtPath, cfgPath))
	if !report.OK() {
		t.Errorf("haproxy connector failed conformance: %+v", report.Checks)
	}
}
