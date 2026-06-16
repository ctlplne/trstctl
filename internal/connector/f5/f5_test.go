package f5_test

import (
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
	"trstctl.com/trstctl/internal/pluginhost"
)

var (
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\nf5-leaf\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\nf5-key\n-----END PRIVATE KEY-----\n")
)

const (
	user    = "admin"
	pass    = "s3cret"
	profile = "clientssl_app"
)

// Deploy uploads the certificate and key, installs them as crypto objects, and
// binds them to the named Client SSL profile.
func TestDeployInstallsAndBindsCertificate(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()

	c := f5.New(srv.URL(), profile, f5.WithBasicAuth(user, pass))
	ops := connector.NewHTTPOps(srv.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("app", sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	gotCert, ok := srv.Uploaded(profile + ".crt")
	if !ok || string(gotCert) != string(sampleCert) {
		t.Fatalf("uploaded cert = %q, ok=%v; want %q", gotCert, ok, sampleCert)
	}
	gotKey, ok := srv.Uploaded(profile + ".key")
	if !ok || string(gotKey) != string(sampleKey) {
		t.Fatalf("uploaded key = %q, ok=%v; want %q", gotKey, ok, sampleKey)
	}
	if !srv.InstalledCert(profile + ".crt") {
		t.Errorf("crypto cert %q not installed", profile+".crt")
	}
	if !srv.InstalledKey(profile + ".key") {
		t.Errorf("crypto key %q not installed", profile+".key")
	}
	chain, ok := srv.Profile(profile)
	if !ok {
		t.Fatalf("profile %q not bound", profile)
	}
	if chain.Cert != profile+".crt" || chain.Key != profile+".key" {
		t.Errorf("profile chain = %+v; want cert=%q key=%q", chain, profile+".crt", profile+".key")
	}
}

// WithName overrides the crypto object base name independently of the profile.
func TestDeployHonorsCustomName(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()

	c := f5.New(srv.URL(), profile, f5.WithBasicAuth(user, pass), f5.WithName("renewed-2026"))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("app", sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, ok := srv.Uploaded("renewed-2026.crt"); !ok {
		t.Errorf("custom-named cert not uploaded")
	}
	chain, _ := srv.Profile(profile)
	if chain.Cert != "renewed-2026.crt" {
		t.Errorf("profile chain cert = %q; want renewed-2026.crt", chain.Cert)
	}
}

// Without valid credentials the appliance rejects the call and the deploy fails
// rather than silently succeeding.
func TestDeployFailsWithoutAuth(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()

	c := f5.New(srv.URL(), profile, f5.WithBasicAuth("admin", "wrong"))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("app", sampleCert, sampleKey)); err == nil {
		t.Fatal("expected deploy to fail on bad credentials, got nil")
	}
	if _, ok := srv.Profile(profile); ok {
		t.Error("profile must not be bound when auth fails")
	}
}

// Redeploying the same credential converges to the same appliance state.
func TestDeployIsIdempotent(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()

	c := f5.New(srv.URL(), profile, f5.WithBasicAuth(user, pass))
	ops := connector.NewHTTPOps(srv.Client())
	dep := connector.NewDeployment("app", sampleCert, sampleKey)

	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	chain, ok := srv.Profile(profile)
	if !ok || chain.Cert != profile+".crt" || chain.Key != profile+".key" {
		t.Errorf("after redeploy: chain=%+v ok=%v", chain, ok)
	}
}

// Least privilege: the connector grants only net.dial to the BIG-IP host. It
// cannot write files or execute commands, and cannot reach any other host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()
	c := f5.New(srv.URL(), profile, f5.WithBasicAuth(user, pass))

	grant := c.Capabilities()
	if grant.Has(pluginhost.CapFSWrite) {
		t.Error("F5 connector must not request fs.write")
	}
	if grant.Has(connector.CapExec) {
		t.Error("F5 connector must not request process.exec")
	}
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("F5 connector must request net.dial")
	}
	// Scoped to the BIG-IP host only.
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example/mgmt/tm/sys", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Error("net.dial must be scoped to the BIG-IP host, not any host")
	}
}

// The connector satisfies the shared connector conformance suite.
func TestF5PassesConformance(t *testing.T) {
	c := f5.New("https://bigip.test", profile, f5.WithBasicAuth(user, pass))
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
