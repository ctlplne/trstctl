package paloalto_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/paloalto"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	testAPIKey = "pan-os-api-key-do-not-log"
	certName   = "web-prod"
)

var (
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\npan-leaf\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\npan-key\n-----END PRIVATE KEY-----\n")
)

// imported is a credential part the fake PAN-OS received, keyed by
// "certificate-name/category".
type imported struct {
	category string
	name     string
	body     []byte
}

// fakePANOS is an in-process double of the PAN-OS XML API import endpoint,
// faithful to the parts the connector exercises. It authenticates the X-PAN-KEY
// header the way real PAN-OS does — a missing or wrong key is rejected with a
// PAN-OS XML <response status="error"> (the API answers 200 with an error
// envelope, which is exactly the failure mode the connector must not treat as
// success). On a good key it records the imported part (by name and category) and
// returns <response status="success"/>. It speaks no other operation.
type fakePANOS struct {
	srv    *httptest.Server
	apiKey string

	mu      sync.Mutex
	objects map[string]imported // "name/category" -> imported part
	calls   int
}

func newFakePANOS(apiKey string) *fakePANOS {
	f := &fakePANOS{apiKey: apiKey, objects: map[string]imported{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakePANOS) URL() string          { return f.srv.URL }
func (f *fakePANOS) Client() *http.Client { return f.srv.Client() }
func (f *fakePANOS) Close()               { f.srv.Close() }

// Calls is the number of authenticated import requests served.
func (f *fakePANOS) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// imported returns the part stored under name+category.
func (f *fakePANOS) imported(name, category string) (imported, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.objects[name+"/"+category]
	return v, ok
}

func (f *fakePANOS) handle(w http.ResponseWriter, r *http.Request) {
	// Authenticate exactly like real PAN-OS: a missing or wrong key yields a
	// 200 with an XML error envelope, never a silent success. PAN-OS does not
	// echo the key back.
	if r.Header.Get("X-PAN-KEY") != f.apiKey {
		writeXML(w, `<response status="error" code="403"><msg><line>Invalid Credential</line></msg></response>`)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/api/" {
		writeXML(w, `<response status="error"><msg>unknown operation</msg></response>`)
		return
	}

	q := r.URL.Query()
	if q.Get("type") != "import" || q.Get("format") != "pem" {
		writeXML(w, `<response status="error"><msg>unexpected import parameters</msg></response>`)
		return
	}
	name := q.Get("certificate-name")
	category := q.Get("category")
	if name == "" || (category != "certificate" && category != "private-key") {
		writeXML(w, `<response status="error"><msg>missing certificate-name or bad category</msg></response>`)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(body) == 0 {
		writeXML(w, `<response status="error"><msg>empty import body</msg></response>`)
		return
	}

	f.mu.Lock()
	f.calls++
	f.objects[name+"/"+category] = imported{category: category, name: name, body: body}
	f.mu.Unlock()

	writeXML(w, `<response status="success"><result>import succeeded</result></response>`)
}

func writeXML(w http.ResponseWriter, doc string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, doc)
}

func newConnector(t *testing.T, f *fakePANOS, apiKey string) *paloalto.Connector {
	t.Helper()
	return paloalto.New(f.URL(), apiKey)
}

// TestPaloAltoConformance: the connector satisfies the shared connector
// conformance suite (names itself, least-privilege grant, deploys idempotently
// through the sandbox, denies ungranted operations). The conformance suite drives
// the connector against the SDK's in-memory Ops, so it does not touch the double.
func TestPaloAltoConformance(t *testing.T) {
	c := paloalto.New("https://fw.example", testAPIKey)
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}

// TestDeploysCert is the acceptance: a renewed credential is imported into the
// named PAN-OS certificate object — the certificate as category=certificate and
// the key as category=private-key under the same name — over an authenticated XML
// API call, and the double (which rejects a bad key and a non-success envelope)
// has stored both parts verbatim.
func TestDeploysCert(t *testing.T) {
	f := newFakePANOS(testAPIKey)
	defer f.Close()

	c := newConnector(t, f, testAPIKey)
	ops := connector.NewHTTPOps(f.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certName, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	gotCert, ok := f.imported(certName, "certificate")
	if !ok {
		t.Fatalf("no certificate imported under %q", certName)
	}
	if !bytes.Equal(gotCert.body, sampleCert) {
		t.Errorf("imported certificate = %q, want %q", gotCert.body, sampleCert)
	}

	gotKey, ok := f.imported(certName, "private-key")
	if !ok {
		t.Fatalf("no private key imported under %q", certName)
	}
	if !bytes.Equal(gotKey.body, sampleKey) {
		t.Errorf("imported private key mismatch")
	}

	if f.Calls() != 2 {
		t.Errorf("authenticated imports = %d, want 2 (certificate + private-key)", f.Calls())
	}
}

// TestDeployImportsCertOnly: with no key supplied, only the certificate is
// imported (the key may already live on the appliance, e.g. in an HSM). The
// connector must not invent an empty private-key import.
func TestDeployImportsCertOnly(t *testing.T) {
	f := newFakePANOS(testAPIKey)
	defer f.Close()

	c := newConnector(t, f, testAPIKey)
	ops := connector.NewHTTPOps(f.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certName, sampleCert, nil)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, ok := f.imported(certName, "certificate"); !ok {
		t.Fatalf("no certificate imported under %q", certName)
	}
	if _, ok := f.imported(certName, "private-key"); ok {
		t.Error("a private key was imported despite none being supplied")
	}
}

// TestDeployIsIdempotent: re-importing the same credential to the same name
// converges to the same appliance state (PAN-OS import overwrites in place).
func TestDeployIsIdempotent(t *testing.T) {
	f := newFakePANOS(testAPIKey)
	defer f.Close()

	c := newConnector(t, f, testAPIKey)
	ops := connector.NewHTTPOps(f.Client())
	dep := connector.NewDeployment(certName, sampleCert, sampleKey)
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	got, ok := f.imported(certName, "certificate")
	if !ok || !bytes.Equal(got.body, sampleCert) {
		t.Errorf("after redeploy: cert=%q ok=%v", got.body, ok)
	}
}

// TestBadKeyRejected: a wrong API key must fail closed. PAN-OS answers 200 with
// <response status="error">, so the connector cannot rely on the status code
// alone — it must inspect the XML envelope and report a failure, and nothing must
// be imported.
func TestBadKeyRejected(t *testing.T) {
	f := newFakePANOS(testAPIKey)
	defer f.Close()

	c := newConnector(t, f, "wrong-key")
	ops := connector.NewHTTPOps(f.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certName, sampleCert, sampleKey)); err == nil {
		t.Fatal("deploy with a wrong API key succeeded; the PAN-OS error envelope was not honored")
	}
	if _, ok := f.imported(certName, "certificate"); ok {
		t.Error("nothing should be imported when the API key is rejected")
	}
}

// TestKeyNeverLogged (AN-8): on the failure path, the returned error must never
// leak the API key or the private-key material, even though both cross the
// connector on every call.
func TestKeyNeverLogged(t *testing.T) {
	f := newFakePANOS(testAPIKey)
	defer f.Close()

	const secretAPIKey = "ultra-secret-pan-os-api-key"
	// Wrong key (relative to the double) so we exercise the error path while the
	// connector still holds — and must not leak — secretAPIKey.
	c := newConnector(t, f, secretAPIKey)
	ops := connector.NewHTTPOps(f.Client())

	_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certName, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("expected an error from the rejected API key")
	}
	if strings.Contains(err.Error(), secretAPIKey) {
		t.Fatalf("error leaked the API key: %v", err)
	}
	if strings.Contains(err.Error(), string(sampleKey)) {
		t.Fatalf("error leaked the private key material: %v", err)
	}
}

// TestCapabilitiesAreLeastPrivilege: net.dial to the appliance host only — no
// fs, no exec, no other host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	c := paloalto.New("https://fw.example", testAPIKey)
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
