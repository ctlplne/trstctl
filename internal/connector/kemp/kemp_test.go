// SPDX-License-Identifier: MPL-2.0

package kemp_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/kemp/kemptest"
	"trstctl.com/trstctl/internal/pluginhost"
)

var (
	kempCert = []byte("-----BEGIN CERTIFICATE-----\nkemp-leaf\n-----END CERTIFICATE-----\n")
	kempKey  = []byte("-----BEGIN PRIVATE KEY-----\nkemp-key\n-----END PRIVATE KEY-----\n")
)

func TestDeployBindsVirtualServiceCertificate(t *testing.T) {
	srv := kemptest.New("token")
	defer srv.Close()

	c := kemp.New(srv.URL(), []byte("token"))
	t.Cleanup(c.Close)
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("vs-payments-443", kempCert, kempKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	b, ok := srv.Binding("vs-payments-443")
	if !ok {
		t.Fatal("virtual service was not bound")
	}
	if !bytes.Equal(b.Certificate, kempCert) || !bytes.Equal(b.PrivateKey, kempKey) {
		t.Fatalf("bound credential mismatch: %+v", b)
	}
}

func TestDeployFailsWithoutAuth(t *testing.T) {
	srv := kemptest.New("token")
	defer srv.Close()

	c := kemp.New(srv.URL(), []byte("wrong"))
	t.Cleanup(c.Close)
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("vs-payments-443", kempCert, kempKey)); err == nil {
		t.Fatal("expected bad token to fail")
	}
	if _, ok := srv.Binding("vs-payments-443"); ok {
		t.Fatal("virtual service bound despite failed auth")
	}
}

func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := kemptest.New("token")
	defer srv.Close()
	c := kemp.New(srv.URL(), []byte("token"))
	t.Cleanup(c.Close)

	grant := c.Capabilities()
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("Kemp connector must request net.dial")
	}
	if grant.Has(pluginhost.CapFSWrite) || grant.Has(connector.CapExec) {
		t.Fatal("Kemp connector must not request filesystem write or process exec")
	}
	other, _ := http.NewRequest(http.MethodGet, "https://other.example/access", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Fatal("Kemp net.dial grant must be scoped to the management host")
	}
}

func TestKempPassesConformance(t *testing.T) {
	c := kemp.New("https://kemp.example", []byte("token"))
	t.Cleanup(c.Close)
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
