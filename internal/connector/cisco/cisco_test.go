// SPDX-License-Identifier: BUSL-1.1

package cisco_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/cisco"
	"trstctl.com/trstctl/internal/connector/cisco/ciscotest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	user = "ers-admin"
	pass = "s3cret-p@ss" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
	name = "web-prod"
)

var (
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\ncisco-leaf\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\ncisco-key\n-----END PRIVATE KEY-----\n")
)

func newConnector(t *testing.T, endpoint string, password []byte) *cisco.Connector {
	t.Helper()
	c := cisco.New(endpoint, user, password)
	t.Cleanup(c.Close)
	return c
}

// A deploy imports the renewed credential under the target's certificate name,
// intact. The strict double is what makes this an end-to-end claim rather than a
// claim that the connector produced some bytes: it rejects a body whose PEM
// fields are not PEM, so an intact recording is proof the wire encoding survived.
func TestDeployImportsCertificateUnderTargetName(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	c := newConnector(t, srv.URL(), []byte(pass))
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment(name, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	got, ok := srv.Imported(name)
	if !ok {
		t.Fatalf("nothing imported under %q; device has %v", name, srv.ImportedNames())
	}
	if !bytes.Equal(got.Certificate, sampleCert) {
		t.Errorf("imported certificate = %q, want %q", got.Certificate, sampleCert)
	}
	if !bytes.Equal(got.PrivateKey, sampleKey) {
		t.Error("imported private key does not match the deployed key")
	}
	// One call, no refusals: the connector must not probe endpoints it has no
	// grant to reach, and a refusal here would mean the deploy "succeeded" only
	// because some other request happened to land.
	if srv.Calls() != 1 {
		t.Errorf("device saw %d requests, want exactly 1", srv.Calls())
	}
	if refusals := srv.Refusals(); len(refusals) != 0 {
		t.Errorf("device refused %+v; the connector spoke a call the API does not offer", refusals)
	}
}

// A deployment with no target imports under the connector's default name, so an
// operator who configured no certificate name still gets a predictable object
// rather than an unnamed one the device rejects.
func TestDeployDefaultsTheCertificateName(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	c := newConnector(t, srv.URL(), []byte(pass))
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("", sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, ok := srv.Imported("trstctl"); !ok {
		t.Fatalf("default-named import missing; device has %v", srv.ImportedNames())
	}
}

// Replaying the same deployment converges on one object (AN-5). The import is
// keyed by certificate name, so a second identical deploy overwrites itself
// instead of accumulating a second trustpoint the operator has to reconcile.
func TestDeployIsIdempotent(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	c := newConnector(t, srv.URL(), []byte(pass))
	dep := connector.NewDeployment(name, sampleCert, sampleKey)
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), dep); err != nil {
			t.Fatalf("deploy %d: %v", attempt, err)
		}
	}
	if names := srv.ImportedNames(); len(names) != 1 || names[0] != name {
		t.Fatalf("device holds %v after replay, want one object named %q", names, name)
	}
}

// A wrong password is rejected by the device and the deploy fails. The assertion
// that nothing was imported is the load-bearing half: a connector that ignored
// the status would report success for a credential the appliance never took.
func TestDeployFailsOnBadCredentials(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	c := newConnector(t, srv.URL(), []byte("wrong-password"))
	_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment(name, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("deploy succeeded with the wrong password")
	}
	if _, ok := srv.Imported(name); ok {
		t.Error("the device imported a credential it had rejected the caller for")
	}
	refusals := srv.Refusals()
	if len(refusals) != 1 || refusals[0].Status != http.StatusUnauthorized {
		t.Fatalf("device refusals = %+v, want a single 401", refusals)
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Errorf("error %q does not carry the device's status; an operator cannot tell auth failure from a network fault", err)
	}
}

// A non-2xx from the device fails the deploy, and the device's response body
// does not reach the error.
//
// The body here is the worst case on purpose: an appliance that echoes the
// submitted credential back inside its error message. That is not hypothetical —
// error text on these devices is assembled from the request — and the connector
// drains the body without formatting it precisely so an echo cannot become a log
// line. Asserting only "an error occurred" would leave that property untested.
func TestDeviceRejectionSurfacesWithoutEchoingTheCredential(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	echoed := bytes.Join([][]byte{[]byte("import failed for "), []byte(pass), sampleCert, sampleKey}, []byte("|"))
	srv.FailNext(http.StatusInternalServerError, echoed)

	c := newConnector(t, srv.URL(), []byte(pass))
	_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment(name, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("deploy succeeded despite a 500 from the device")
	}
	assertNoSecrets(t, err.Error())
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error %q lost the bounded status diagnostic, leaving nothing to triage on", err)
	}
	if _, ok := srv.Imported(name); ok {
		t.Error("a rejected import was recorded as landed")
	}
}

// No error path leaks the password or the private key.
//
// One redaction test proves one branch. Deploy can fail at the transport, at
// authentication, and at the device's own rejection, and each builds its message
// differently — the key is in scope at all three. This walks every reachable
// failure and holds the same property over all of them.
func TestNoErrorPathLeaksTheKeyOrPassword(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	cases := []struct {
		name  string
		setup func() *cisco.Connector
	}{
		{"rejected credentials", func() *cisco.Connector {
			return newConnector(t, srv.URL(), []byte("wrong-password"))
		}},
		{"device rejects the import", func() *cisco.Connector {
			srv.FailNext(http.StatusConflict, bytes.Join([][]byte{[]byte(pass), sampleKey}, []byte(" ")))
			return newConnector(t, srv.URL(), []byte(pass))
		}},
		{"management host unreachable", func() *cisco.Connector {
			// A closed port: the error is built from a transport failure rather
			// than a response, which is a different formatting path.
			dead := ciscotest.New(user, []byte(pass))
			endpoint := dead.URL()
			dead.Close()
			return newConnector(t, endpoint, []byte(pass))
		}},
		{"unusable management endpoint", func() *cisco.Connector {
			// Fails while the request is still being built, before the body is
			// ever handed to a transport. That branch returns the underlying
			// error unwrapped, and the URL it names is assembled next to the
			// marshaled key — the one place a raw return could carry it along.
			return newConnector(t, "http://ise.example\x7f", []byte(pass))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.setup()
			_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment(name, sampleCert, sampleKey))
			if err == nil {
				t.Fatal("expected the deploy to fail")
			}
			assertNoSecrets(t, err.Error())
		})
	}
}

// assertNoSecrets holds the property every connector error must have: the
// message may describe what failed, never what was being deployed.
//
// Each secret is listed in every form it could plausibly escape in, because a
// leak rarely reproduces the literal fixture. The PEM entries are paired with a
// distinctive inner substring: json.Marshal escapes the newlines, so an error
// that formatted the marshaled request body would carry the key with "\n" in
// place of every line break and a search for the raw PEM would come back clean.
// The base64 entry covers the likeliest leak of all — anything that dumps the
// request (httputil.DumpRequest, %v on an *http.Request) spills the
// Authorization header, in which the password appears only as base64 of
// "user:pass" and never as the characters an operator typed.
func assertNoSecrets(t *testing.T, msg string) {
	t.Helper()
	forbidden := map[string]string{
		"the management password":        pass,
		"the Basic credential in base64": base64.StdEncoding.EncodeToString([]byte(user + ":" + pass)),
		"the private key PEM":            string(sampleKey),
		"the private key body":           "cisco-key",
		"the certificate PEM":            string(sampleCert),
		"the certificate body":           "cisco-leaf",
	}
	for what, secret := range forbidden {
		if strings.Contains(msg, secret) {
			t.Errorf("error message leaks %s: %q", what, msg)
		}
	}
}

// Least privilege: the connector reaches the management host over the network
// and nothing else. No filesystem, no exec, no other host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()
	c := newConnector(t, srv.URL(), []byte(pass))

	grant := c.Capabilities()
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("cisco connector must request net.dial")
	}
	if grant.Has(pluginhost.CapFSWrite) || grant.Has(pluginhost.CapFSRead) || grant.Has(connector.CapExec) {
		t.Error("cisco connector must not request filesystem or exec capabilities")
	}
	host := strings.TrimPrefix(srv.URL(), "http://")
	if !grant.Allows(pluginhost.CapNetDial, host) {
		t.Fatalf("net.dial must allow the management host %q", host)
	}
	if grant.Allows(pluginhost.CapNetDial, "evil.example") {
		t.Error("net.dial must be scoped to the management host, not any host")
	}
}

// An endpoint with no derivable authority must grant nothing, and the deploy
// must be denied rather than run.
//
// This is the inverted failure the least-privilege test above cannot see,
// because it only ever builds a connector from a well-formed httptest URL. A
// pluginhost grant with an EMPTY net.dial constraint is unrestricted, not
// closed, so a connector that derived no host would widen to every reachable
// address — the exact opposite of what a misconfiguration should do. The
// schemeless case is the one that matters in practice: "ise.example" is what an
// operator types, url.Parse accepts it, and the authority lands in Path.
func TestUnparseableEndpointGrantsNothingRatherThanEverything(t *testing.T) {
	for _, endpoint := range []string{
		"ise.example",            // no scheme: url.Parse reads the authority as a path
		"ise.example:8443",       // no scheme, with a port
		"",                       // absent config
		"http://ise.example\x7f", // a control character url.Parse rejects outright
	} {
		t.Run(endpoint, func(t *testing.T) {
			c := newConnector(t, endpoint, []byte(pass))
			grant := c.Capabilities()
			if grant.Allows(pluginhost.CapNetDial, "evil.example") {
				t.Error("an endpoint with no derivable host granted net.dial to an arbitrary host")
			}
			// Deliberately NOT asserting the capability is absent from the
			// grant. The guarantee lives in pluginhost — an explicit constraint
			// that resolved to nothing denies — so the capability is present
			// with a constraint that permits no host. Asserting its absence
			// would pin the mechanism rather than the property, and would fail
			// the moment the guard moved, which is exactly when the property
			// still held.
			if grant.Allows(pluginhost.CapNetDial, "") {
				t.Error("an endpoint with no derivable host allowed a dial to an empty authority")
			}

			// The sandbox must be what stops it, so the deploy fails closed even
			// if a future connector change stopped checking the endpoint itself.
			srv := ciscotest.New(user, []byte(pass))
			defer srv.Close()
			if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment(name, sampleCert, sampleKey)); err == nil {
				t.Fatal("deploy succeeded from an endpoint with no derivable management host")
			}
			if names := srv.ImportedNames(); len(names) != 0 {
				t.Errorf("a denied deploy still reached a device and imported %v", names)
			}
		})
	}
}

// The connector satisfies the shared connector conformance suite.
func TestCiscoConformance(t *testing.T) {
	c := newConnector(t, "https://ise.example", []byte(pass))
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}

// The cisco family is absent from the rollback census, and that must stay a
// deliberate statement rather than an oversight.
//
// The connector's only management call is the certificate import, which carries
// the private key in its body. There is no call that addresses an
// already-installed certificate — no bind, no trustpoint re-point — so the only
// way to "roll back" would be to upload the predecessor again, and after B1 the
// control plane does not hold that key. A Rollback method here would either fail
// every time or lie; the census saying "no" is the honest answer, and this test
// fails if someone flips it without adding the API surface that would make it
// true.
func TestCiscoIsNotAdvertisedAsRollbackCapable(t *testing.T) {
	if connector.CanRollback("cisco") {
		t.Fatal("the census claims cisco can roll back; its management API exposes only a " +
			"key-bearing import, so a re-bind is not expressible and the claim would " +
			"strand an operator mid-incident")
	}
	var c connector.Connector = newConnector(t, "https://ise.example", []byte(pass))
	if _, ok := c.(connector.Rollbacker); ok {
		t.Fatal("cisco implements Rollbacker without an API that can re-bind an installed certificate")
	}
	if _, err := connector.RunRollback(context.Background(), c, connector.NewHTTPOps(http.DefaultClient), connector.Rollback{Target: name}); err == nil {
		t.Fatal("RunRollback returned nil for cisco; an operator would read that as a listener restored")
	}
}
