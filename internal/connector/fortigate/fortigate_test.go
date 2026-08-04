// SPDX-License-Identifier: MPL-2.0

package fortigate_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/fortigate"
	"trstctl.com/trstctl/internal/connector/fortigate/fortigatetest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
)

// apiToken is the FortiOS REST API token the fake appliance requires. It is
// []byte, not a string, because that is how the connector custodies it (AN-8) and
// a test that pinned it as a string would be modelling a shape the product does
// not use.
var apiToken = []byte("fortios-rest-api-token-supersecret")

// rejectedToken is a credential the appliance does not accept — the shape of a
// token that has been rotated or revoked out from under a target. It is a
// distinct value from apiToken so a leak assertion on the 401 path has something
// real to catch: a connector prints the credential it holds, and on this path
// that is not the one the appliance would have accepted.
var rejectedToken = []byte("fortios-rest-api-token-rotated-away")

// material generates a real certificate and key through the internal/crypto
// boundary (AN-3: this test imports no crypto/*). Real PEM matters here: the
// emulator refuses material a FortiGate could not load, so a fixture that merely
// looked PEM-shaped would prove the deploy path against a device that never
// accepts it.
func material(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	t.Cleanup(signer.Destroy)
	der, err := crypto.SelfSignedCACert(signer, "fortigate.test", time.Hour)
	if err != nil {
		t.Fatalf("self-sign certificate: %v", err)
	}
	keyPEM, err = signer.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("export private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM
}

// A deploy imports the renewed credential into the vpn.certificate/local object
// named by the target, and touches nothing else on the appliance.
func TestDeployImportsCertificateUnderTargetName(t *testing.T) {
	certPEM, keyPEM := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()

	c := fortigate.New(srv.URL(), apiToken)
	t.Cleanup(c.Close)

	const target = "edge-tls"
	stats, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment(target, certPEM, keyPEM))
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if stats.Denied != 0 {
		t.Errorf("Denied = %d, want 0", stats.Denied)
	}

	got, ok := srv.Stored(target)
	if !ok {
		t.Fatalf("the appliance holds no local certificate named %q", target)
	}
	if !bytes.Equal(got.Certificate, certPEM) {
		t.Errorf("imported certificate does not match the deployed one")
	}
	if !bytes.Equal(got.PrivateKey, keyPEM) {
		t.Errorf("imported private key does not match the deployed one")
	}
	if n := srv.Puts(); n != 1 {
		t.Errorf("accepted imports = %d, want 1", n)
	}
	// The connector's grant is net.dial to this host and nothing more, so a call
	// the appliance refuses as off-contract means it reached for FortiOS surface
	// outside the one endpoint this connector is documented to use.
	if refused := srv.Refused(); len(refused) != 0 {
		t.Errorf("the connector made off-contract calls: %+v", refused)
	}
}

// An empty target deploys under the connector's documented default object name,
// so a target configured without one still lands somewhere an operator can find.
func TestDeployUsesDefaultObjectNameWhenTargetEmpty(t *testing.T) {
	certPEM, keyPEM := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()

	c := fortigate.New(srv.URL(), apiToken)
	t.Cleanup(c.Close)

	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("", certPEM, keyPEM)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, ok := srv.Stored("trstctl"); !ok {
		t.Fatalf("nothing was imported under the default object name %q", "trstctl")
	}
}

// The FortiOS PUT is an upsert keyed by object name, so a replayed deploy — which
// the outbox will do (AN-5) — converges instead of accumulating objects.
func TestDeployIsIdempotent(t *testing.T) {
	certPEM, keyPEM := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()

	c := fortigate.New(srv.URL(), apiToken)
	t.Cleanup(c.Close)

	dep := connector.NewDeployment("edge-tls", certPEM, keyPEM)
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), dep); err != nil {
			t.Fatalf("deploy %d: %v", attempt, err)
		}
	}
	if n := srv.Count(); n != 1 {
		t.Errorf("local-certificate objects after replay = %d, want 1", n)
	}
}

// A rejected token fails the deploy. The failure that matters is not the error
// text but that nothing was imported: a connector that reported success here
// would leave an operator believing a listener was renewed when the appliance
// never accepted the call.
func TestDeployFailsWhenTokenRejected(t *testing.T) {
	certPEM, keyPEM := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()

	c := fortigate.New(srv.URL(), rejectedToken)
	t.Cleanup(c.Close)

	_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("edge-tls", certPEM, keyPEM))
	if err == nil {
		t.Fatal("deploy with a rejected token succeeded; want an error")
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Errorf("error %q does not carry the appliance's 401", err)
	}
	// A 401 is the most common production failure — a token rotated or revoked out
	// from under a target — so it is the error most likely to reach a ticket. The
	// obvious "help the operator" fix is to name the credential that was refused,
	// which would publish it; the check is against the token this connector holds,
	// not the one the appliance accepts, because those differ precisely here.
	assertNoSecrets(t, err.Error(), rejectedToken, certPEM, keyPEM)
	if _, ok := srv.Stored("edge-tls"); ok {
		t.Error("a certificate was imported despite the rejected token")
	}
}

// A non-2xx from the appliance surfaces as an error carrying the status and
// nothing else.
//
// FortiOS assembles error bodies from the request that failed and can echo
// submitted fields back, so the response to a failed import is one of the few
// places on the wire where the API token and the subject private key can arrive
// together. The connector drains that body and reports the status alone; this
// test pins that, because the natural "improvement" — including the device's
// message to help operators debug — would put the key into every ticket, log
// line and notification the failure touches.
func TestDeployErrorRedactsWhatTheApplianceEchoesBack(t *testing.T) {
	certPEM, keyPEM := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()

	echoed := bytes.Join([][]byte{apiToken, certPEM, keyPEM}, []byte("|"))
	srv.SetFailure(http.StatusInternalServerError, echoed)

	c := fortigate.New(srv.URL(), apiToken)
	t.Cleanup(c.Close)

	_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("edge-tls", certPEM, keyPEM))
	if err == nil {
		t.Fatal("deploy succeeded despite the appliance failing it")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error %q lost the status diagnostic an operator needs", err)
	}
	assertNoSecrets(t, err.Error(), apiToken, certPEM, keyPEM)
	if _, ok := srv.Stored("edge-tls"); ok {
		t.Error("a certificate was imported despite the appliance failing the call")
	}
}

// The private key and the API token never appear in an error, on any failure
// path, and never leave the connector anywhere but where they belong: the key in
// the request body, the token in the Authorization header.
func TestSecretsNeverReachErrorsOrTheWrongPlaceOnTheWire(t *testing.T) {
	certPEM, keyPEM := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()

	c := fortigate.New(srv.URL(), apiToken)
	t.Cleanup(c.Close)
	dep := connector.NewDeployment("edge-tls", certPEM, keyPEM)
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), dep); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	// The token is a bearer credential: it belongs in the header and nowhere else.
	// A copy inside the JSON payload would be durably recorded by the appliance in
	// a certificate object an operator can read back.
	for i, body := range srv.Bodies() {
		if bytes.Contains(body, apiToken) {
			t.Errorf("request body %d carried the API token in its payload", i)
		}
	}
	sawBearer := false
	for _, header := range srv.AuthHeaders() {
		if header == "Bearer "+string(apiToken) {
			sawBearer = true
		}
	}
	if !sawBearer {
		t.Error("the appliance never received the token as a bearer Authorization header")
	}
	// FortiOS also accepts the token as an `access_token` query parameter, and a
	// connector belt-and-bracing both forms would still authenticate and still pass
	// every state assertion above while writing the credential into every proxy
	// access log on the path. Assert the request-target directly rather than relying
	// on a transport error to happen to quote the URL back.
	for i, target := range srv.RequestTargets() {
		if strings.Contains(target, string(apiToken)) {
			t.Errorf("request %d carried the API token in the URL: %q", i, target)
		}
	}

	// Every failure mode the connector can surface, checked for leakage: the
	// appliance refusing the credential, and the appliance being unreachable (the
	// path where the URL — and anything a careless implementation appended to it —
	// ends up inside a transport error).
	rejected := fortigate.New(srv.URL(), rejectedToken)
	t.Cleanup(rejected.Close)
	_, err := connector.Run(context.Background(), rejected, connector.NewHTTPOps(srv.Client()), dep)
	if err == nil {
		t.Fatal("expected an error from the rotated token")
	}
	assertNoSecrets(t, err.Error(), rejectedToken, certPEM, keyPEM)

	dead := fortigatetest.New(apiToken)
	deadURL, deadClient := dead.URL(), dead.Client()
	dead.Close()
	unreachable := fortigate.New(deadURL, apiToken)
	t.Cleanup(unreachable.Close)
	_, err = connector.Run(context.Background(), unreachable, connector.NewHTTPOps(deadClient), dep)
	if err == nil {
		t.Fatal("expected an error from the unreachable appliance")
	}
	assertNoSecrets(t, err.Error(), apiToken, certPEM, keyPEM)
}

// The emulator is only evidence if it refuses what the real appliance refuses.
// These are the refusals the connector's contract rests on, asserted directly:
// unauthenticated calls, other endpoints, other methods, and material a FortiGate
// could not load. Without this, a later change that loosened the double would
// silently turn every test above into a test of nothing.
func TestEmulatorRefusesWhatTheApplianceRefuses(t *testing.T) {
	certPEM, keyPEM := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()

	object := srv.URL() + "/api/v2/cmdb/vpn.certificate/local/edge-tls"
	good := `{"name":"edge-tls","certificate":` + quote(certPEM) + `,"private-key":` + quote(keyPEM) + `}`

	cases := []struct {
		name   string
		method string
		url    string
		auth   string
		body   string
		want   int
	}{
		{"no credential", http.MethodPut, object, "", good, http.StatusUnauthorized},
		{"wrong credential", http.MethodPut, object, "Bearer nope", good, http.StatusUnauthorized},
		{"token in a query parameter is not a credential", http.MethodPut, object + "?access_token=" + string(apiToken), "", good, http.StatusUnauthorized},
		{"another endpoint", http.MethodPut, srv.URL() + "/api/v2/cmdb/system/admin/admin", "Bearer " + string(apiToken), good, http.StatusNotFound},
		{"another method", http.MethodGet, object, "Bearer " + string(apiToken), "", http.StatusMethodNotAllowed},
		{"the collection, with no object named", http.MethodPut, srv.URL() + "/api/v2/cmdb/vpn.certificate/local/", "Bearer " + string(apiToken), good, http.StatusMethodNotAllowed},
		{"malformed body", http.MethodPut, object, "Bearer " + string(apiToken), "{", http.StatusBadRequest},
		{"body naming a different object", http.MethodPut, object, "Bearer " + string(apiToken), `{"name":"other","certificate":` + quote(certPEM) + `,"private-key":` + quote(keyPEM) + `}`, http.StatusBadRequest},
		{"no private key", http.MethodPut, object, "Bearer " + string(apiToken), `{"name":"edge-tls","certificate":` + quote(certPEM) + `,"private-key":""}`, http.StatusBadRequest},
		{"material that is not PEM", http.MethodPut, object, "Bearer " + string(apiToken), `{"name":"edge-tls","certificate":"not a certificate","private-key":"not a key"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
	if _, ok := srv.Stored("edge-tls"); ok {
		t.Error("a refused request still imported a certificate")
	}
}

// Least privilege: net.dial to the appliance host, nothing else, and not to any
// other host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	srv := fortigatetest.New(apiToken)
	defer srv.Close()
	c := fortigate.New(srv.URL(), apiToken)
	t.Cleanup(c.Close)

	grant := c.Capabilities()
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("the FortiGate connector must request net.dial")
	}
	if grant.Has(pluginhost.CapFSWrite) || grant.Has(connector.CapExec) {
		t.Error("the FortiGate connector must not request filesystem write or process exec")
	}
	other, _ := http.NewRequest(http.MethodPut, "https://evil.example/api/v2/cmdb/vpn.certificate/local/x", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Error("net.dial must be scoped to the FortiOS management host, not any host")
	}
}

// FortiGate cannot roll back, and must not claim to (epic D4, C1a discipline).
//
// A rollback is a re-BIND: point an installed object back at a predecessor
// without re-uploading it. This connector's entire API surface is one CMDB
// object, `vpn.certificate/local/{name}`, which HOLDS the material — there is no
// second call that binds an already-installed certificate to a listener, and the
// deploy replaces the object's contents in place, so no predecessor survives it
// to bind back to. The honest outcome is no Rollback method and no census entry;
// this test keeps that honest in both directions, so adding a Rollback that
// re-uploaded (which is a redeploy, and needs a key the control plane does not
// hold after B1) would fail here rather than quietly making the census lie.
func TestFortiGateDoesNotClaimRollback(t *testing.T) {
	certPEM, keyPEM := material(t)
	srv := fortigatetest.New(apiToken)
	defer srv.Close()

	if connector.CanRollback("fortigate") {
		t.Error("the rollback census claims fortigate can re-bind; its API has no bind call separate from the upload")
	}

	c := fortigate.New(srv.URL(), apiToken)
	t.Cleanup(c.Close)
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment("edge-tls", certPEM, keyPEM)); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	_, err := connector.RunRollback(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.Rollback{
		Target:                 "edge-tls",
		PredecessorFingerprint: connector.NewDeployment("edge-tls", certPEM, keyPEM).Fingerprint,
		Reason:                 "operator asked for a rollback this family cannot execute",
	})
	if err == nil {
		t.Fatal("a rollback reported success on a connector that cannot re-bind")
	}
	if err.Error() != connector.ErrRollbackUnsupported.Error() {
		t.Errorf("rollback error = %v, want %v", err, connector.ErrRollbackUnsupported)
	}
	// And nothing moved on the appliance: an unsupported rollback must be inert,
	// not a partial attempt that leaves the object half-changed.
	if n := srv.Puts(); n != 1 {
		t.Errorf("imports after the refused rollback = %d, want the deploy's 1", n)
	}
}

// The connector satisfies the shared connector conformance suite.
func TestFortiGatePassesConformance(t *testing.T) {
	c := fortigate.New("https://fgt.example", apiToken)
	t.Cleanup(c.Close)
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, check := range rep.Checks {
			if !check.Passed {
				t.Errorf("conformance %q failed: %s", check.Name, check.Detail)
			}
		}
	}
}

// assertNoSecrets fails if text carries the private key, the certificate, the
// token the connector under test is holding, or any substantial fragment of one.
// The fragment check matters: a truncated body echo leaks just as much as a whole
// one, and an assertion on the full value would pass for it.
//
// token is a parameter rather than the package-level apiToken because a connector
// leaks the credential IT holds, not the one the appliance happens to accept. The
// failure paths that matter most — a rotated or revoked token — are exactly the
// ones where those two differ, so checking apiToken there would assert against a
// value the connector never had and could never have printed.
func assertNoSecrets(t *testing.T, text string, token, certPEM, keyPEM []byte) {
	t.Helper()
	for label, secretBytes := range map[string][]byte{
		"API token":   token,
		"private key": keyPEM,
		"certificate": certPEM,
	} {
		if len(secretBytes) == 0 {
			continue
		}
		if strings.Contains(text, string(secretBytes)) {
			t.Errorf("error text leaked the %s: %q", label, text)
			continue
		}
		if frag := fragment(secretBytes); frag != "" && strings.Contains(text, frag) {
			t.Errorf("error text leaked a fragment of the %s: %q", label, text)
		}
	}
}

// fragment returns a distinctive middle slice of material, long enough that an
// accidental match is not credible.
//
// The width adapts to short material because a FortiOS API token is only ~32
// bytes: a fixed 24-byte window would silently return nothing for it, leaving the
// token covered by the whole-value check alone and a partial echo undetected.
func fragment(material []byte) string {
	width := 24
	if len(material) < 2*width {
		width = len(material) / 2
	}
	if width < 12 {
		return ""
	}
	start := len(material)/2 - width/2
	return string(material[start : start+width])
}

// quote renders PEM as a JSON string for the emulator-fidelity cases, which build
// request bodies by hand rather than through the connector.
func quote(material []byte) string {
	return `"` + strings.ReplaceAll(string(material), "\n", `\n`) + `"`
}
