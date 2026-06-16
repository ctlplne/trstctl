package fortigate_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/fortigate"
)

const testToken = "fortios-rest-api-token-supersecret"

// stored is a local certificate the fake FortiOS received.
type stored struct {
	Certificate string
	PrivateKey  string
}

// fakeFortiOS is an in-process double of the FortiOS REST API local-certificate
// endpoint, faithful in the way that matters for this connector's contract: it
// authenticates every request against the expected bearer token (rejecting a
// missing/wrong token with 401, the way the appliance does), and on a PUT to
// vpn.certificate/local/{name} it upserts the certificate by name so a test can
// assert it landed. So an auth-header bug in the connector is caught here, not
// papered over. It records the highest-privilege secret it must never see — the
// bearer token — and exposes the raw request bodies so a test can prove the
// token is carried only in the header, never in a payload.
type fakeFortiOS struct {
	srv   *httptest.Server
	token string

	mu       sync.Mutex
	certs    map[string]stored // object name -> material
	puts     int
	bodies   []string // every request body received, for leak assertions
	authSeen []string // every Authorization header received, for leak assertions
}

func newFakeFortiOS(token string) *fakeFortiOS {
	f := &fakeFortiOS{token: token, certs: map[string]stored{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeFortiOS) URL() string          { return f.srv.URL }
func (f *fakeFortiOS) Client() *http.Client { return f.srv.Client() }
func (f *fakeFortiOS) Close()               { f.srv.Close() }

// Stored returns the certificate upserted under name.
func (f *fakeFortiOS) Stored(name string) (stored, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.certs[name]
	return v, ok
}

// Puts is the number of authenticated PUTs served.
func (f *fakeFortiOS) Puts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts
}

// Bodies returns a copy of every request body received.
func (f *fakeFortiOS) Bodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bodies...)
}

// Count is the number of distinct local-certificate objects stored.
func (f *fakeFortiOS) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.certs)
}

func (f *fakeFortiOS) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	f.mu.Lock()
	f.bodies = append(f.bodies, string(body))
	f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
	f.mu.Unlock()

	// Authenticate: FortiOS rejects a missing or wrong bearer token with 401.
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"status":"error","http_status":401}`)
		return
	}

	const prefix = "/api/v2/cmdb/vpn.certificate/local/"
	if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, prefix) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"status":"error","http_status":404}`)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)

	var in struct {
		Name        string `json:"name"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private-key"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Certificate == "" || in.PrivateKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"status":"error","http_status":400}`)
		return
	}

	f.mu.Lock()
	f.puts++
	f.certs[name] = stored{Certificate: in.Certificate, PrivateKey: in.PrivateKey}
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"success","http_status":200,"name":"`+name+`"}`)
}

var (
	certPEM = []byte("-----BEGIN CERTIFICATE-----\nfortigate-test-cert\n-----END CERTIFICATE-----\n")
	keyPEM  = []byte("-----BEGIN PRIVATE KEY-----\nfortigate-test-key\n-----END PRIVATE KEY-----\n")
)

func TestFortiGateConformance(t *testing.T) {
	f := newFakeFortiOS(testToken)
	defer f.Close()

	c := fortigate.New(f.URL(), []byte(testToken))
	// Conformance drives the connector through the SDK's in-memory ops, exercising
	// name, least-privilege grant, deploy, idempotency, and denial-of-ungranted.
	if rep := connector.Conformance(context.Background(), c); !rep.OK() {
		for _, chk := range rep.Checks {
			t.Logf("check %q passed=%v detail=%s", chk.Name, chk.Passed, chk.Detail)
		}
		t.Fatal("conformance report not OK")
	}
}

func TestDeploysCert(t *testing.T) {
	f := newFakeFortiOS(testToken)
	defer f.Close()

	c := fortigate.New(f.URL(), []byte(testToken))
	const target = "edge-tls"
	dep := connector.NewDeployment(target, certPEM, keyPEM)

	stats, err := connector.Run(context.Background(), c, connector.NewHTTPOps(f.Client()), dep)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Denied != 0 {
		t.Fatalf("Denied = %d, want 0", stats.Denied)
	}

	got, ok := f.Stored(target)
	if !ok {
		t.Fatalf("certificate %q was not stored on the appliance", target)
	}
	if got.Certificate != string(certPEM) {
		t.Errorf("stored certificate = %q, want %q", got.Certificate, certPEM)
	}
	if got.PrivateKey != string(keyPEM) {
		t.Errorf("stored private key = %q, want %q", got.PrivateKey, keyPEM)
	}
	if f.Puts() != 1 {
		t.Errorf("authenticated PUTs = %d, want 1", f.Puts())
	}

	// Redeploy: PUT is an upsert, so it must succeed and leave one object.
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(f.Client()), dep); err != nil {
		t.Fatalf("redeploy Run: %v", err)
	}
	if n := f.Count(); n != 1 {
		t.Errorf("stored object count after redeploy = %d, want 1", n)
	}
}

func TestDeploysDefaultName(t *testing.T) {
	f := newFakeFortiOS(testToken)
	defer f.Close()

	c := fortigate.New(f.URL(), []byte(testToken))
	// Empty target => the connector's default object name "trstctl".
	dep := connector.NewDeployment("", certPEM, keyPEM)
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(f.Client()), dep); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := f.Stored("trstctl"); !ok {
		t.Fatalf("certificate was not stored under the default name %q", "trstctl")
	}
}

func TestBadTokenRejected(t *testing.T) {
	f := newFakeFortiOS(testToken)
	defer f.Close()

	// Connector configured with the wrong token: the appliance answers 401 and
	// Deploy must surface that as an error, not a silent success.
	c := fortigate.New(f.URL(), []byte("wrong-token"))
	dep := connector.NewDeployment("edge-tls", certPEM, keyPEM)

	_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(f.Client()), dep)
	if err == nil {
		t.Fatal("Run with a bad token succeeded; want an error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q does not mention the 401 status", err.Error())
	}
	if _, ok := f.Stored("edge-tls"); ok {
		t.Fatal("certificate was stored despite a rejected token")
	}
}

func TestTokenNeverLogged(t *testing.T) {
	f := newFakeFortiOS(testToken)
	defer f.Close()

	c := fortigate.New(f.URL(), []byte(testToken))
	dep := connector.NewDeployment("edge-tls", certPEM, keyPEM)
	if _, err := connector.Run(context.Background(), c, connector.NewHTTPOps(f.Client()), dep); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The token must travel only in the Authorization header as a bearer
	// credential — never inside a request body / JSON payload.
	for i, b := range f.Bodies() {
		if strings.Contains(b, testToken) {
			t.Fatalf("request body %d leaked the API token into the payload: %q", i, b)
		}
	}

	// And it must reach the appliance exactly as a bearer header (proving it is
	// transported deliberately, not smuggled elsewhere).
	f.mu.Lock()
	auth := append([]string(nil), f.authSeen...)
	f.mu.Unlock()
	sawBearer := false
	for _, a := range auth {
		if a == "Bearer "+testToken {
			sawBearer = true
		}
	}
	if !sawBearer {
		t.Fatal("the appliance never received the token as a bearer Authorization header")
	}

	// On the error path the token must not appear in the surfaced error. Drive a
	// failure (wrong token -> 401) and assert the error text is token-free.
	bad := fortigate.New(f.URL(), []byte(testToken+"-but-rotated"))
	_, err := connector.Run(context.Background(), bad, connector.NewHTTPOps(f.Client()), dep)
	if err == nil {
		t.Fatal("expected an error from the rotated/invalid token")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaked the API token: %q", err.Error())
	}
}
