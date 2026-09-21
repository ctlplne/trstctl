// SPDX-License-Identifier: BUSL-1.1

package paloalto_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/paloalto"
	"trstctl.com/trstctl/internal/connector/paloalto/paloaltotest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	certName = "web-prod"
	// defaultName mirrors the connector's fallback object name. Duplicated
	// rather than exported: the test asserts the shipped default is what an
	// operator gets, so reading it from the connector would make the assertion
	// vacuous.
	defaultName = "trstctl"
)

var (
	// #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
	testAPIKey = []byte("pan-os-api-key-do-not-log")
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\npan-leaf\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\npan-key\n-----END PRIVATE KEY-----\n")
)

// deploy runs the real connector against the double and returns the error.
func deploy(t *testing.T, srv *paloaltotest.Server, apiKey []byte, dep connector.Deployment) error {
	t.Helper()
	c := paloalto.New(srv.URL(), apiKey)
	defer c.Close()
	_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), dep)
	return err
}

// The acceptance: a renewed credential lands in the named PAN-OS certificate
// object as two imports under one certificate-name, and the double — which
// rejects a bad key, bad parameters, and a non-PEM body — has both parts
// verbatim.
func TestDeployImportsCertificateAndKey(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	if err := deploy(t, srv, testAPIKey, connector.NewDeployment(certName, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	obj, ok := srv.Object(certName)
	if !ok {
		t.Fatalf("no certificate object imported under %q", certName)
	}
	if !bytes.Equal(obj.CertPEM, sampleCert) {
		t.Errorf("imported certificate = %q, want %q", obj.CertPEM, sampleCert)
	}
	if !bytes.Equal(obj.KeyPEM, sampleKey) {
		t.Error("imported private key does not match the deployed key")
	}
	if srv.Calls() != 2 {
		t.Errorf("accepted imports = %d, want 2 (certificate + private-key)", srv.Calls())
	}
}

// PAN-OS attaches a key to a certificate object, so the certificate import must
// come first. The double refuses a key for an unknown name, but assert the order
// directly too: a reversed connector would fail with a confusing "does not
// exist" rather than a clear statement of what it got wrong.
func TestDeployImportsCertificateBeforeKey(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	if err := deploy(t, srv, testAPIKey, connector.NewDeployment(certName, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	imports := srv.Imports()
	if len(imports) != 2 {
		t.Fatalf("imports = %+v, want 2", imports)
	}
	if imports[0].Category != "certificate" || imports[1].Category != "private-key" {
		t.Errorf("import order = %q then %q; want certificate then private-key",
			imports[0].Category, imports[1].Category)
	}
	for _, imp := range imports {
		if imp.Name != certName {
			t.Errorf("import %+v used name %q, want the single object name %q", imp, imp.Name, certName)
		}
	}
}

// An empty target deploys to the documented default object name, so an operator
// who names nothing still gets a predictable object rather than a rejected call.
func TestDeployUsesDefaultObjectNameForEmptyTarget(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	if err := deploy(t, srv, testAPIKey, connector.NewDeployment("", sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, ok := srv.Object(defaultName); !ok {
		t.Errorf("no object under the default name %q; imports=%+v", defaultName, srv.Imports())
	}
}

// With no key supplied (it may already live on the appliance, e.g. in an HSM)
// only the certificate is imported. The connector must not invent an empty
// private-key import, which the double would reject as a non-PEM body.
func TestDeployImportsCertificateOnlyWhenNoKeySupplied(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	if err := deploy(t, srv, testAPIKey, connector.NewDeployment(certName, sampleCert, nil)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	obj, ok := srv.Object(certName)
	if !ok {
		t.Fatalf("no certificate object imported under %q", certName)
	}
	if len(obj.KeyPEM) != 0 {
		t.Error("a private key was imported despite none being supplied")
	}
	if srv.Calls() != 1 {
		t.Errorf("accepted imports = %d, want 1 (certificate only)", srv.Calls())
	}
}

// Redeploying the same credential converges to the same firewall state: PAN-OS
// import overwrites the named object in place, so nothing accumulates.
func TestDeployIsIdempotent(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	dep := connector.NewDeployment(certName, sampleCert, sampleKey)
	for i := 0; i < 2; i++ {
		if err := deploy(t, srv, testAPIKey, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	if n := srv.ObjectCount(); n != 1 {
		t.Errorf("certificate objects = %d after redeploy, want 1", n)
	}
	obj, _ := srv.Object(certName)
	if !bytes.Equal(obj.CertPEM, sampleCert) {
		t.Errorf("after redeploy certificate = %q, want %q", obj.CertPEM, sampleCert)
	}
}

// A wrong API key must fail closed, and nothing may be imported. This is the
// case that most needs a faithful double: a permissive one would report success
// and leave paloalto advertised as working against a firewall that would refuse
// every call.
func TestDeployFailsOnWrongAPIKey(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	err := deploy(t, srv, []byte("wrong-key"), connector.NewDeployment(certName, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("deploy with a wrong API key succeeded")
	}
	if _, ok := srv.Object(certName); ok {
		t.Error("an object was imported despite the API key being rejected")
	}
}

// A missing credential is rejected the same way. An empty key must not be
// mistaken for "no authentication required".
func TestDeployFailsOnMissingAPIKey(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	if err := deploy(t, srv, nil, connector.NewDeployment(certName, sampleCert, sampleKey)); err == nil {
		t.Fatal("deploy with no API key succeeded")
	}
	if _, ok := srv.Object(certName); ok {
		t.Error("an object was imported despite there being no API key")
	}
}

// PAN-OS reports some failures inside a 200 with <response status="error">, so a
// 2xx is necessary but not sufficient. The double produces that shape for a body
// the config engine cannot parse; the connector must still fail.
func TestDeployFailsWhenDeviceReportsErrorInsideA200(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	notPEM := []byte("this is not a certificate")
	if err := deploy(t, srv, testAPIKey, connector.NewDeployment(certName, notPEM, sampleKey)); err == nil {
		t.Fatal("a PAN-OS status=\"error\" envelope inside a 200 was treated as success")
	}
	if _, ok := srv.Object(certName); ok {
		t.Error("an object was recorded for a body the device rejected")
	}
}

// A non-2xx from the device surfaces as an error, and the device's response body
// does not survive into it.
//
// This codebase drains and redacts response bodies on purpose: an appliance
// error body is attacker-influenced and routinely echoes the request, so a
// connector that quoted it into an error would carry the API key and the private
// key into logs, transcripts, and the outbox. The injected body here contains
// both, so the assertion is exact rather than incidental.
func TestNon2xxErrorRedactsTheDeviceResponseBody(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	leak := append([]byte("<response status=\"error\">import failed for key="), testAPIKey...)
	leak = append(leak, ' ')
	leak = append(leak, sampleKey...)
	leak = append(leak, []byte("</response>")...)
	srv.InjectFailure(http.StatusInternalServerError, leak)

	err := deploy(t, srv, testAPIKey, connector.NewDeployment(certName, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("a 500 from the device was treated as success")
	}
	// Compared as bytes so the search itself does not copy credential material
	// into an immutable Go string (AN-8).
	msg := []byte(err.Error())
	if bytes.Contains(msg, testAPIKey) {
		t.Errorf("error leaked the API key: %q", msg)
	}
	if bytes.Contains(msg, sampleKey) {
		t.Errorf("error leaked private key material: %q", msg)
	}
	// The status is kept because an operator needs it to act; the body is not.
	if !bytes.Contains(msg, []byte("500")) {
		t.Errorf("error dropped the HTTP status an operator needs: %q", msg)
	}
	if !bytes.Contains(msg, []byte("redacted")) {
		t.Errorf("error does not state that the body was redacted: %q", msg)
	}
}

// The private key must not appear in ANY error the connector can produce. The
// key crosses the connector on every deploy, so this is swept across every
// failure mode rather than asserted on one path.
//
// The last case is the one that earns the word "any". Every other failure here
// lands on the certificate import, which returns before the key import is
// attempted — so without it, the error wrap around the key import (the only one
// with the private key in scope) is never executed, and a build that formatted
// dep.KeyPEM straight into it passes this test. That was a real hole; the
// device-scoped injection is what closes it.
func TestPrivateKeyNeverAppearsInAnyError(t *testing.T) {
	// A distinct key so a match cannot come from anywhere but the deployment.
	secretKey := []byte("-----BEGIN PRIVATE KEY-----\nultra-secret-pan-key-material\n-----END PRIVATE KEY-----\n")
	secretAPIKey := []byte("ultra-secret-pan-os-api-key")
	echoed := append(append([]byte("failed: "), secretKey...), secretAPIKey...)

	cases := []struct {
		name string
		// apiKey the connector authenticates with.
		apiKey []byte
		cert   []byte
		// inject, when non-nil, is a 502 body returned for every request.
		inject []byte
		// injectOn, when non-empty, fails only that import category, letting the
		// earlier one land.
		injectOn string
	}{
		{name: "rejected credential", apiKey: secretAPIKey, cert: sampleCert},
		{name: "error inside a 200", apiKey: testAPIKey, cert: []byte("not pem at all")},
		{name: "device 502 echoing the request", apiKey: testAPIKey, cert: sampleCert, inject: echoed},
		{name: "private-key import rejected after the certificate landed",
			apiKey: testAPIKey, cert: sampleCert, inject: echoed, injectOn: "private-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := paloaltotest.New(testAPIKey)
			defer srv.Close()
			switch {
			case tc.injectOn != "":
				srv.InjectFailureFor(tc.injectOn, http.StatusBadGateway, tc.inject)
			case tc.inject != nil:
				srv.InjectFailure(http.StatusBadGateway, tc.inject)
			}

			err := deploy(t, srv, tc.apiKey, connector.NewDeployment(certName, tc.cert, secretKey))
			if err == nil {
				t.Fatal("expected a failure")
			}
			// Compared as bytes: turning key material into a string to search for
			// it would itself put the secret in an immutable, unwipeable Go string
			// (AN-8).
			msg := []byte(err.Error())
			if bytes.Contains(msg, secretKey) {
				t.Errorf("error leaked the private key: %q", msg)
			}
			// Even a fragment is a leak: PEM armor is public, the base64 payload
			// between the markers is the secret.
			if bytes.Contains(msg, []byte("ultra-secret-pan-key-material")) {
				t.Errorf("error leaked private key material: %q", msg)
			}
			if bytes.Contains(msg, secretAPIKey) {
				t.Errorf("error leaked the API key: %q", msg)
			}
			// The object name is operator-facing context and is expected to
			// survive, so the redaction above is not passing by saying nothing.
			if !bytes.Contains(msg, []byte(certName)) {
				t.Errorf("error dropped the object name an operator needs: %q", msg)
			}
		})
	}
}

// A private-key import the firewall refuses must fail the deploy, and the state
// it leaves behind must be the state that actually exists.
//
// This is the half-applied deploy: the certificate object was created and the
// key was not, so the firewall is holding a certificate it cannot serve. The
// connector's job is to report that as a failure — reporting success here would
// mark the credential delivered while TLS on that firewall is broken, which is
// worse than never having deployed.
func TestKeyImportFailureFailsTheDeployAndLeavesTheCertificateKeyless(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()
	srv.InjectFailureFor("private-key", http.StatusBadGateway,
		[]byte(`<response status="error"><result><msg>key rejected</msg></result></response>`))

	err := deploy(t, srv, testAPIKey, connector.NewDeployment(certName, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("a rejected private-key import was reported as a successful deploy")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error does not say which import failed: %q", err)
	}

	// The certificate import really did happen first, so this also proves the
	// injection scoped to one category rather than failing everything.
	obj, ok := srv.Object(certName)
	if !ok {
		t.Fatal("the certificate import did not land; the failure was not scoped to the key")
	}
	if !bytes.Equal(obj.CertPEM, sampleCert) {
		t.Errorf("certificate = %q, want %q", obj.CertPEM, sampleCert)
	}
	if len(obj.KeyPEM) != 0 {
		t.Error("a key is recorded on the object the device refused the key for")
	}
}

// The API key travels in a header and must never appear in a request URL.
//
// PAN-OS accepts its key as a key= query parameter, so a connector that sent it
// that way would work — and would write the key in clear into the firewall's own
// log, into every proxy in between, and into request tracing. The device will
// not catch that, so the test does.
func TestAPIKeyNeverAppearsInARequestURL(t *testing.T) {
	srv := paloaltotest.New(testAPIKey)
	defer srv.Close()

	if err := deploy(t, srv, testAPIKey, connector.NewDeployment(certName, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	queries := srv.Queries()
	// Guards the assertion below against passing because nothing was recorded.
	if len(queries) != 2 {
		t.Fatalf("recorded queries = %d, want 2", len(queries))
	}
	for _, q := range queries {
		if bytes.Contains(q, testAPIKey) {
			t.Errorf("API key present in a request URL: %q", q)
		}
		// The parameters that must be there, so this is not asserting on an
		// empty query string.
		if !bytes.Contains(q, []byte("type=import")) {
			t.Errorf("query %q is missing type=import", q)
		}
	}
}

// Least privilege: net.dial to the appliance host only — no fs, no exec, no
// other host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	c := paloalto.New("https://fw.example", testAPIKey)
	defer c.Close()

	grant := c.Capabilities()
	if grant.Has(pluginhost.CapFSWrite) {
		t.Error("PAN-OS connector must not request fs.write")
	}
	if grant.Has(connector.CapExec) {
		t.Error("PAN-OS connector must not request process.exec")
	}
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("PAN-OS connector must request net.dial")
	}
	if !grant.Allows(pluginhost.CapNetDial, "fw.example") {
		t.Error("net.dial must allow the appliance host")
	}
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example/", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Error("net.dial must be scoped to the appliance host, not any host")
	}
}

// The connector satisfies the shared conformance suite.
func TestPaloAltoConformance(t *testing.T) {
	c := paloalto.New("https://fw.example", testAPIKey)
	defer c.Close()

	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}

// PAN-OS cannot roll back by re-binding, and the census must keep saying so.
//
// A rollback is a re-bind: point an installed object back at a predecessor
// without re-uploading it. That needs an API call addressing an INSTALLED object
// separately from the upload, and this connector's entire surface is one call —
// type=import — whose addressing unit, certificate-name, IS the object the
// deploy target names. There is no binding to move, and each deploy overwrites
// the object in place, so no predecessor survives to bind back to. Restoring the
// previous certificate would mean re-importing its PEM and key, which is a
// redeploy wearing a different name and needs key material the control plane
// does not hold after B1.
//
// This is asserted, not just written down, because the honest answer is the one
// that decays silently: someone adds a Rollback method that re-imports, the
// census gains an entry, and an operator is told a firewall was re-pointed when
// it was re-uploaded.
func TestPaloAltoCannotRollBack(t *testing.T) {
	if connector.CanRollback("paloalto") {
		t.Error("the rollback census claims paloalto can re-bind; its API has no call that " +
			"addresses an installed certificate object apart from importing one")
	}
	var c connector.Connector = paloalto.New("https://fw.example", testAPIKey)
	defer c.(*paloalto.Connector).Close()
	if _, ok := c.(connector.Rollbacker); ok {
		t.Error("paloalto declares Rollbacker; verify it re-binds rather than re-importing " +
			"before adding it to the census")
	}

	// And the SDK reports the honest outcome rather than a silent success, so an
	// operator staring at a failing firewall learns that nothing happened.
	_, err := connector.RunRollback(context.Background(), c, connector.NewHTTPOps(nil), connector.Rollback{
		Target: certName, PredecessorFingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	})
	if err != connector.ErrRollbackUnsupported {
		t.Errorf("RunRollback err = %v, want ErrRollbackUnsupported", err)
	}
}
