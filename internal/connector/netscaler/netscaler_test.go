package netscaler_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/netscaler"
	"trstctl.com/trstctl/internal/connector/netscaler/netscalertest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const (
	user    = "nsroot"
	pass    = "s3cret"
	certkey = "web-prod"
)

var (
	sampleCert = []byte("-----BEGIN CERTIFICATE-----\nns-leaf\n-----END CERTIFICATE-----\n")
	sampleKey  = []byte("-----BEGIN PRIVATE KEY-----\nns-key\n-----END PRIVATE KEY-----\n")
)

// Deploy uploads the renewed cert and key as system files, then rebinds the
// existing SSL certkey to them — the full NetScaler renewal.
func TestDeployUploadsAndRebinds(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()

	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())

	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certkey, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	gotCert, ok := srv.File(certkey + ".crt")
	if !ok || !bytes.Equal(gotCert, sampleCert) {
		t.Errorf("uploaded cert = %q ok=%v; want %q", gotCert, ok, sampleCert)
	}
	gotKey, ok := srv.File(certkey + ".key")
	if !ok || !bytes.Equal(gotKey, sampleKey) {
		t.Errorf("uploaded key = %q ok=%v; want %q", gotKey, ok, sampleKey)
	}
	b, ok := srv.Binding(certkey)
	if !ok || b.Cert != certkey+".crt" || b.Key != certkey+".key" {
		t.Errorf("binding = %+v ok=%v; want cert=%q key=%q", b, ok, certkey+".crt", certkey+".key")
	}
}

// The session is opened and then closed: the connector logs in and logs out,
// leaving no dangling session on the appliance.
func TestDeployLogsInAndOut(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()

	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certkey, sampleCert, sampleKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if srv.Logins() != 1 {
		t.Errorf("logins = %d, want 1", srv.Logins())
	}
	if srv.Logouts() != 1 {
		t.Errorf("logouts = %d, want 1 (session must be closed)", srv.Logouts())
	}
	if srv.OpenSessions() != 0 {
		t.Errorf("open sessions = %d, want 0", srv.OpenSessions())
	}
}

// Wrong credentials are rejected at login; the deploy fails and nothing is
// uploaded or rebound.
func TestDeployFailsOnBadCredentials(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()

	c := netscaler.New(srv.URL(), user, []byte("wrong-password"))
	ops := connector.NewHTTPOps(srv.Client())
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certkey, sampleCert, sampleKey)); err == nil {
		t.Fatal("expected deploy to fail on bad credentials, got nil")
	}
	if _, ok := srv.Binding(certkey); ok {
		t.Error("certkey must not be rebound when login fails")
	}
	if srv.OpenSessions() != 0 {
		t.Error("a failed login must not leave a session open")
	}
}

func TestDeployRejectsMalformedLoginResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "malformed-json", body: "{", want: "decode response"},
		{name: "empty-json", body: `{}`, want: "missing sessionid"},
		{name: "nitro-error", body: `{"errorcode":354,"message":"Invalid username or password"}`, want: "NITRO error 354"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/nitro/v1/config/login" {
					t.Fatalf("unexpected request after failed login: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			c := netscaler.New(srv.URL, user, []byte(pass))
			_, err := connector.Run(context.Background(), c, connector.NewHTTPOps(srv.Client()), connector.NewDeployment(certkey, sampleCert, sampleKey))
			if err == nil {
				t.Fatal("deploy succeeded on a malformed login response")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err, tc.want)
			}
		})
	}
}

func TestDeployRejectsLoginReadError(t *testing.T) {
	c := netscaler.New("https://ns.example", user, []byte(pass))
	ops := readErrorOps{err: errors.New("login body truncated")}
	_, err := connector.Run(context.Background(), c, ops, connector.NewDeployment(certkey, sampleCert, sampleKey))
	if err == nil {
		t.Fatal("deploy succeeded when login response body failed to read")
	}
	if !strings.Contains(err.Error(), "read response") || !strings.Contains(err.Error(), "login body truncated") {
		t.Fatalf("error %q did not surface the response read failure", err)
	}
}

// Re-applying the same credential converges to the same appliance state.
func TestDeployIsIdempotent(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()

	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	dep := connector.NewDeployment(certkey, sampleCert, sampleKey)
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
	}
	gotCert, _ := srv.File(certkey + ".crt")
	b, ok := srv.Binding(certkey)
	if !bytes.Equal(gotCert, sampleCert) || !ok || b.Cert != certkey+".crt" {
		t.Errorf("after redeploy: cert=%q binding=%+v ok=%v", gotCert, b, ok)
	}
}

// Least privilege: net.dial to the NSIP host only — no fs, no exec, no other
// host.
func TestCapabilitiesAreLeastPrivilege(t *testing.T) {
	c := netscaler.New("https://ns.example", user, []byte(pass))
	grant := c.Capabilities()
	if grant.Has(pluginhost.CapFSWrite) {
		t.Error("NetScaler connector must not request fs.write")
	}
	if grant.Has(connector.CapExec) {
		t.Error("NetScaler connector must not request process.exec")
	}
	if !grant.Has(pluginhost.CapNetDial) {
		t.Fatal("NetScaler connector must request net.dial")
	}
	if !grant.Allows(pluginhost.CapNetDial, "ns.example") {
		t.Error("net.dial must allow the NSIP host")
	}
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example/", nil)
	if grant.Allows(pluginhost.CapNetDial, other.URL.Host) {
		t.Error("net.dial must be scoped to the NSIP host, not any host")
	}
}

// The connector satisfies the shared connector contract against a faithful NITRO
// double. A generic empty-body HTTP double is not enough here: accepting that
// would reintroduce the malformed-2xx login bug this connector must reject.
func TestNetScalerPassesConformance(t *testing.T) {
	srv := netscalertest.New(user, pass)
	defer srv.Close()

	c := netscaler.New(srv.URL(), user, []byte(pass))
	ops := connector.NewHTTPOps(srv.Client())
	dep := connector.NewDeployment("conformance-target", sampleCert, sampleKey)
	for i := 0; i < 2; i++ {
		if _, err := connector.Run(context.Background(), c, ops, dep); err != nil {
			t.Fatalf("conformance deploy %d: %v", i, err)
		}
	}
	if _, ok := srv.Binding("conformance-target"); !ok {
		t.Fatal("conformance deploy did not bind the certkey")
	}
}

type readErrorOps struct {
	err error
}

func (readErrorOps) Send(string, []byte) error      { return nil }
func (readErrorOps) WriteFile(string, []byte) error { return nil }
func (readErrorOps) Exec(string, []string) error    { return nil }
func (o readErrorOps) Request(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       readErrorCloser{err: o.err},
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

type readErrorCloser struct {
	err error
}

func (r readErrorCloser) Read([]byte) (int, error) { return 0, r.err }
func (r readErrorCloser) Close() error             { return nil }
