// SPDX-License-Identifier: MPL-2.0

package a10_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/a10/a10test"
	"trstctl.com/trstctl/internal/pluginhost"
)

var (
	a10Cert = []byte("-----BEGIN CERTIFICATE-----\na10-leaf\n-----END CERTIFICATE-----\n")
	a10Key  = []byte("-----BEGIN PRIVATE KEY-----\na10-key\n-----END PRIVATE KEY-----\n")
)

func TestDeployBindsClientSSLTemplate(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()

	c := a10.New(srv.URL(), "admin", []byte("s3cret"))
	t.Cleanup(c.Close)
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("payments-client-ssl", a10Cert, a10Key)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	b, ok := srv.Binding("payments-client-ssl")
	if !ok {
		t.Fatal("client-ssl template was not bound")
	}
	if !bytes.Equal(b.Certificate, a10Cert) || !bytes.Equal(b.PrivateKey, a10Key) {
		t.Fatalf("bound credential mismatch: %+v", b)
	}
}

func TestDeployFailsWithoutAuth(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()

	c := a10.New(srv.URL(), "admin", []byte("wrong"))
	t.Cleanup(c.Close)
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("payments-client-ssl", a10Cert, a10Key)); err == nil {
		t.Fatal("expected bad credentials to fail")
	}
	if _, ok := srv.Binding("payments-client-ssl"); ok {
		t.Fatal("template bound despite failed auth")
	}
}

func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()
	c := a10.New(srv.URL(), "admin", []byte("s3cret"))
	t.Cleanup(c.Close)

	grant := c.Capabilities()
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("A10 connector must request net.dial")
	}
	if grant.Has(pluginhost.CapFSWrite) || grant.Has(connector.CapExec) {
		t.Fatal("A10 connector must not request filesystem write or process exec")
	}
	other, _ := http.NewRequest(http.MethodGet, "https://other.example/axapi/v3", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Fatal("A10 net.dial grant must be scoped to the management host")
	}
}

func TestA10PassesConformance(t *testing.T) {
	srv := a10test.New("admin", "s3cret")
	defer srv.Close()

	c := a10.New(srv.URL(), "admin", []byte("s3cret"))
	ops := connector.NewHTTPOps(srv.Client())
	dep := connector.NewDeployment("conformance-client-ssl", a10Cert, a10Key)
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("conformance deploy %d: %v", i, err)
		}
	}
	if _, ok := srv.Binding("conformance-client-ssl"); !ok {
		t.Fatal("conformance deploy did not bind the client-ssl template")
	}
}
