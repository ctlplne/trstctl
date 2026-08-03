// SPDX-License-Identifier: MPL-2.0

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

	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)))
	ops := connector.NewHTTPOps(srv.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("app", sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// D4: the object name carries the certificate's fingerprint, so a later
	// deployment cannot overwrite this one — that is what leaves something for
	// a rollback to bind back to.
	dep := connector.NewDeployment("app", sampleCert, sampleKey)
	base := connector.DeployedObjectName(profile, dep.Fingerprint)
	gotCert, ok := srv.Uploaded(base + ".crt")
	if !ok || string(gotCert) != string(sampleCert) {
		t.Fatalf("uploaded cert = %q, ok=%v; want %q", gotCert, ok, sampleCert)
	}
	gotKey, ok := srv.Uploaded(base + ".key")
	if !ok || string(gotKey) != string(sampleKey) {
		t.Fatalf("uploaded key = %q, ok=%v; want %q", gotKey, ok, sampleKey)
	}
	if !srv.InstalledCert(base + ".crt") {
		t.Errorf("crypto cert %q not installed", base+".crt")
	}
	if !srv.InstalledKey(base + ".key") {
		t.Errorf("crypto key %q not installed", base+".key")
	}
	chain, ok := srv.Profile(profile)
	if !ok {
		t.Fatalf("profile %q not bound", profile)
	}
	if chain.Cert != base+".crt" || chain.Key != base+".key" {
		t.Errorf("profile chain = %+v; want cert=%q key=%q", chain, base+".crt", base+".key")
	}
}

// WithName overrides the crypto object base name independently of the profile.
func TestDeployHonorsCustomName(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()

	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)), f5.WithName("renewed-2026"))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("app", sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	base := connector.DeployedObjectName("renewed-2026", connector.NewDeployment("app", sampleCert, sampleKey).Fingerprint)
	if _, ok := srv.Uploaded(base + ".crt"); !ok {
		t.Errorf("custom-named cert not uploaded as %q", base+".crt")
	}
	chain, _ := srv.Profile(profile)
	if chain.Cert != base+".crt" {
		t.Errorf("profile chain cert = %q; want %q", chain.Cert, base+".crt")
	}
}

// Without valid credentials the appliance rejects the call and the deploy fails
// rather than silently succeeding.
func TestDeployFailsWithoutAuth(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()

	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes("admin", []byte("wrong")))
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

	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)))
	ops := connector.NewHTTPOps(srv.Client())
	dep := connector.NewDeployment("app", sampleCert, sampleKey)

	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	// Idempotent because the name is the fingerprint: the same certificate
	// deployed twice installs over itself rather than accumulating objects.
	base := connector.DeployedObjectName(profile, dep.Fingerprint)
	chain, ok := srv.Profile(profile)
	if !ok || chain.Cert != base+".crt" || chain.Key != base+".key" {
		t.Errorf("after redeploy: chain=%+v ok=%v, want cert=%q", chain, ok, base+".crt")
	}
}

// Least privilege: the connector grants only net.dial to the BIG-IP host. It
// cannot write files or execute commands, and cannot reach any other host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := f5test.New(user, pass)
	defer srv.Close()
	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes(user, []byte(pass)))

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
	c := f5.New("https://bigip.test", profile, f5.WithBasicAuthBytes(user, []byte(pass)))
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
