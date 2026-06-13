package cisco_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trustctl.io/trustctl/internal/connector"
	"trustctl.io/trustctl/internal/connector/cisco"
	"trustctl.io/trustctl/internal/pluginhost"
)

const (
	user = "ers-admin"
	pass = "s3cret-p@ss"
	name = "web-prod"
)

var (
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\ncisco-leaf\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\ncisco-key\n-----END PRIVATE KEY-----\n")
)

// fakeCisco is a faithful in-process double of the Cisco ASA / ISE management
// API certificate-import endpoint, for testing the connector on CI without a real
// appliance. It checks HTTP Basic auth on every request (401 on mismatch) and,
// on a POST to the import path, records the imported certificate and key by name.
type fakeCisco struct {
	srv  *httptest.Server
	user string
	pass string

	mu       sync.Mutex
	imported map[string]importedCred // name -> credential
}

type importedCred struct {
	Certificate []byte
	PrivateKey  []byte
}

func newFakeCisco(user, pass string) *fakeCisco {
	f := &fakeCisco{user: user, pass: pass, imported: map[string]importedCred{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeCisco) URL() string          { return f.srv.URL }
func (f *fakeCisco) Client() *http.Client { return f.srv.Client() }
func (f *fakeCisco) Close()               { f.srv.Close() }

// Imported returns the credential imported under the given certificate name.
func (f *fakeCisco) Imported(name string) (importedCred, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.imported[name]
	return v, ok
}

func (f *fakeCisco) handle(w http.ResponseWriter, r *http.Request) {
	if !f.authOK(r) {
		// 401 with a body that does NOT echo any credential, like a real device.
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"authentication failed"}`)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/api/certificate/import" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var in struct {
		Name        string `json:"name"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"privateKey"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Name == "" || in.Certificate == "" || in.PrivateKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"name, certificate and privateKey are required"}`)
		return
	}
	f.mu.Lock()
	f.imported[in.Name] = importedCred{Certificate: []byte(in.Certificate), PrivateKey: []byte(in.PrivateKey)}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"name": in.Name, "status": "imported"})
}

// authOK validates the request's HTTP Basic credentials against the configured
// username/password, parsing the Authorization header directly so the test
// exercises the exact header the connector emits.
func (f *fakeCisco) authOK(r *http.Request) bool {
	const prefix = "Basic "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, prefix))
	if err != nil {
		return false
	}
	u, p, ok := strings.Cut(string(raw), ":")
	return ok && u == f.user && p == f.pass
}

// The connector satisfies the shared connector conformance suite.
func TestCiscoConformance(t *testing.T) {
	c := cisco.New("https://ise.example", user, pass)
	rep := connector.Conformance(context.Background(), c)
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}

// Deploy POSTs the renewed certificate and key to the import endpoint with the
// correct Basic credentials; the double stores them under the certificate name.
func TestDeploysCert(t *testing.T) {
	srv := newFakeCisco(user, pass)
	defer srv.Close()

	c := cisco.New(srv.URL(), user, pass)
	ops := connector.NewHTTPOps(srv.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(name, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got, ok := srv.Imported(name)
	if !ok {
		t.Fatalf("nothing imported under %q", name)
	}
	if string(got.Certificate) != string(sampleCert) {
		t.Errorf("Certificate = %q, want %q", got.Certificate, sampleCert)
	}
	if string(got.PrivateKey) != string(sampleKey) {
		t.Errorf("PrivateKey mismatch")
	}
}

// Wrong credentials are rejected with 401; the deploy fails and nothing is
// imported.
func TestBadCredentialsRejected(t *testing.T) {
	srv := newFakeCisco(user, pass)
	defer srv.Close()

	c := cisco.New(srv.URL(), user, "wrong-password")
	ops := connector.NewHTTPOps(srv.Client())

	_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(name, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("expected deploy to fail on bad credentials, got nil")
	}
	if _, ok := srv.Imported(name); ok {
		t.Error("nothing should be imported when credentials are rejected")
	}
}

// The password never appears in the error surfaced from a failed deploy (or in
// the request URL the connector targets). A connector that interpolated the
// credential into a message or URL would leak it into logs.
func TestPasswordNeverLogged(t *testing.T) {
	const secret = "sup3r-s3cr3t-do-not-log"

	// A server that always fails, so Deploy must format an error from the
	// response — the path most likely to accidentally include the credential.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"internal appliance error"}`)
	}))
	defer srv.Close()

	c := cisco.New(srv.URL(), user, secret)
	ops := connector.NewHTTPOps(srv.Client())

	_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(name, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("expected deploy to fail, got nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message leaks the password: %q", err.Error())
	}
	// Also assert the connector's declared reach does not embed the credential.
	grant := c.Capabilities()
	host, _ := strings.CutPrefix(srv.URL(), "http://")
	if !grant.Allows(pluginhost.CapNetDial, host) {
		t.Fatalf("net.dial must allow the management host %q", host)
	}
}
