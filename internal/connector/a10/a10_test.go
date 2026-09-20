// SPDX-License-Identifier: BUSL-1.1

package a10_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// aXAPI error bodies are untrusted and may echo the submitted password, session
// signature, certificate, or private key. They must remain byte-backed and must
// not become part of the durable error returned to the outbox worker.
func TestDeployRedactsSecretsEchoedByAppliance(t *testing.T) {
	const (
		password = "A10-PASSWORD-DO-NOT-LOG"
		token    = "A10-TOKEN-DO-NOT-LOG"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"`+token+`"}}`)
		case "/axapi/v3/file/ssl-cert":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(bytes.Join([][]byte{[]byte(password), []byte(token), a10Cert, a10Key}, []byte("|")))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := a10.New(srv.URL, "admin", []byte(password))
	t.Cleanup(c.Close)
	_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("payments-client-ssl", a10Cert, a10Key))
	if err == nil {
		t.Fatal("deploy succeeded despite appliance failure")
	}
	for _, forbidden := range []string{password, token, string(a10Cert), string(a10Key)} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error %q leaked authority-bearing response content", err)
		}
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
