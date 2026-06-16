package acm_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	region    = "us-east-1"
	accessKey = "AKIDEXAMPLE"
	secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	targetARN = "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
)

func leafPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("leaf-der")})
}
func interPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("intermediate-der")})
}
func keyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("key-der")})
}

func creds() acm.Credentials {
	return acm.Credentials{AccessKeyID: accessKey, SecretAccessKey: []byte(secretKey)}
}

// Deploy imports the renewed certificate and key into the target ARN over a
// correctly SigV4-signed ImportCertificate call (the double rejects a bad
// signature, so a green test means the signing is correct).
func TestDeployImportsCertificate(t *testing.T) {
	srv := acmtest.New(accessKey, secretKey)
	defer srv.Close()

	c := acm.New(region, creds(), acm.WithEndpoint(srv.URL()))
	ops := connector.NewHTTPOps(srv.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(targetARN, leafPEM(), keyPEM())); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got, ok := srv.Imported(targetARN)
	if !ok {
		t.Fatalf("nothing imported under %s", targetARN)
	}
	if string(got.Certificate) != string(leafPEM()) {
		t.Errorf("Certificate = %q, want leaf %q", got.Certificate, leafPEM())
	}
	if string(got.PrivateKey) != string(keyPEM()) {
		t.Errorf("PrivateKey mismatch")
	}
	if len(got.Chain) != 0 {
		t.Errorf("Chain = %q, want empty for a single-block cert", got.Chain)
	}
}

// A leaf+intermediate CertPEM is split: the leaf goes to Certificate, the
// remainder to CertificateChain (ACM requires them separated).
func TestDeploySplitsLeafAndChain(t *testing.T) {
	srv := acmtest.New(accessKey, secretKey)
	defer srv.Close()

	full := append(append([]byte{}, leafPEM()...), interPEM()...)
	c := acm.New(region, creds(), acm.WithEndpoint(srv.URL()))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(targetARN, full, keyPEM())); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got, _ := srv.Imported(targetARN)
	if string(got.Certificate) != string(leafPEM()) {
		t.Errorf("Certificate = %q, want only the leaf", got.Certificate)
	}
	if string(got.Chain) != string(interPEM()) {
		t.Errorf("Chain = %q, want the intermediate", got.Chain)
	}
}

// A wrong secret produces a signature the service rejects; the deploy fails and
// nothing is imported.
func TestDeployFailsOnBadCredentials(t *testing.T) {
	srv := acmtest.New(accessKey, secretKey)
	defer srv.Close()

	c := acm.New(region, acm.Credentials{AccessKeyID: accessKey, SecretAccessKey: []byte("wrong-secret")}, acm.WithEndpoint(srv.URL()))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(targetARN, leafPEM(), keyPEM())); err == nil {
		t.Fatal("expected deploy to fail on a bad signature, got nil")
	}
	if _, ok := srv.Imported(targetARN); ok {
		t.Error("nothing should be imported when the signature is rejected")
	}
}

// Reimporting the same credential to the same ARN converges to the same state.
func TestDeployIsIdempotent(t *testing.T) {
	srv := acmtest.New(accessKey, secretKey)
	defer srv.Close()

	c := acm.New(region, creds(), acm.WithEndpoint(srv.URL()))
	ops := connector.NewHTTPOps(srv.Client())
	dep := connector.NewDeployment(targetARN, leafPEM(), keyPEM())
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	got, ok := srv.Imported(targetARN)
	if !ok || string(got.Certificate) != string(leafPEM()) {
		t.Errorf("after redeploy: %+v ok=%v", got, ok)
	}
}

// Least privilege: net.dial to the ACM endpoint host only — no fs, no exec, and
// not any other host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	c := acm.New(region, creds()) // default endpoint acm.us-east-1.amazonaws.com
	grant := c.Capabilities()
	if grant.Has(pluginhost.CapFSWrite) {
		t.Error("ACM connector must not request fs.write")
	}
	if grant.Has(connector.CapExec) {
		t.Error("ACM connector must not request process.exec")
	}
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("ACM connector must request net.dial")
	}
	if !grant.Allows(pluginhost.CapNetDial, "acm.us-east-1.amazonaws.com") {
		t.Error("net.dial must allow the ACM endpoint host")
	}
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example/", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Error("net.dial must be scoped to the ACM host, not any host")
	}
}

// The connector satisfies the shared connector conformance suite.
func TestACMPassesConformance(t *testing.T) {
	c := acm.New(region, creds())
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
