package azurekv_test

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/azurekv"
	"trstctl.com/trstctl/internal/connector/azurekv/azurekvtest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	token    = "eyJ0eXAaccess-token"
	certName = "web-prod"
)

var (
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\nkv-leaf\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\nkv-key\n-----END PRIVATE KEY-----\n")
)

// Deploy imports the renewed key+cert as a PEM bundle into the named vault
// certificate, authenticated with the bearer token.
func TestDeployImportsCertificate(t *testing.T) {
	srv := azurekvtest.New(token)
	defer srv.Close()

	c := azurekv.New(srv.URL(), azurekv.StaticToken(token))
	ops := connector.NewHTTPOps(srv.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certName, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got, ok := srv.Imported(certName)
	if !ok {
		t.Fatalf("nothing imported under %q", certName)
	}
	if !bytes.Contains(got.PEM, sampleKey) || !bytes.Contains(got.PEM, sampleCert) {
		t.Errorf("imported bundle missing key or cert: %q", got.PEM)
	}
	if got.ContentType != "application/x-pem-file" {
		t.Errorf("contentType = %q, want application/x-pem-file", got.ContentType)
	}
}

// A wrong bearer token is rejected by the vault; the deploy fails and nothing is
// imported.
func TestDeployFailsOnBadToken(t *testing.T) {
	srv := azurekvtest.New(token)
	defer srv.Close()

	c := azurekv.New(srv.URL(), azurekv.StaticToken("wrong-token"))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certName, sampleCert, sampleKey)); err == nil {
		t.Fatal("expected deploy to fail on a bad token, got nil")
	}
	if _, ok := srv.Imported(certName); ok {
		t.Error("nothing should be imported when the token is rejected")
	}
}

// Reimporting the same credential to the same name converges to the same state.
func TestDeployIsIdempotent(t *testing.T) {
	srv := azurekvtest.New(token)
	defer srv.Close()

	c := azurekv.New(srv.URL(), azurekv.StaticToken(token))
	ops := connector.NewHTTPOps(srv.Client())
	dep := connector.NewDeployment(certName, sampleCert, sampleKey)
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	got, ok := srv.Imported(certName)
	if !ok || !bytes.Contains(got.PEM, sampleCert) {
		t.Errorf("after redeploy: ok=%v", ok)
	}
}

// Least privilege: net.dial to the vault host only — no fs, no exec, no other
// host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	c := azurekv.New("https://myvault.vault.azure.net", azurekv.StaticToken(token))
	grant := c.Capabilities()
	if grant.Has(pluginhost.CapFSWrite) {
		t.Error("Key Vault connector must not request fs.write")
	}
	if grant.Has(connector.CapExec) {
		t.Error("Key Vault connector must not request process.exec")
	}
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("Key Vault connector must request net.dial")
	}
	if !grant.Allows(pluginhost.CapNetDial, "myvault.vault.azure.net") {
		t.Error("net.dial must allow the vault host")
	}
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example/", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Error("net.dial must be scoped to the vault host, not any host")
	}
}

// The connector satisfies the shared connector conformance suite.
func TestAzureKVPassesConformance(t *testing.T) {
	c := azurekv.New("https://example.vault.azure.net", azurekv.StaticToken(token))
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
