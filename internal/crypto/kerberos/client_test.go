// SPDX-License-Identifier: BUSL-1.1

package kerberos

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// clientKeytab is a keytab for a client principal, the way an operator would
// export one for the relay's domain account.
func clientKeytab(t *testing.T, principal, realm, password string) []byte {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(principal, realm, password, time.Now().Add(-time.Hour), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A158: the client authenticator accepts only an exact, injection-free
// configuration and a keytab that holds the configured account.
func TestClientAuthenticatorValidatesItsConfiguration(t *testing.T) {
	good := clientKeytab(t, "svc-trstctl", "CORP.EXAMPLE", "keytab-derivation-input")
	for name, cfg := range map[string]ClientConfig{
		"lower-case realm":      {Realm: "corp.example", Principal: "svc-trstctl", KDCs: []string{"dc1.corp.example:88"}, Keytab: good},
		"realm injection":       {Realm: "CORP.EXAMPLE\n[realms]", Principal: "svc-trstctl", KDCs: []string{"dc1.corp.example:88"}, Keytab: good},
		"principal with realm":  {Realm: "CORP.EXAMPLE", Principal: "svc-trstctl@CORP.EXAMPLE", KDCs: []string{"dc1.corp.example:88"}, Keytab: good},
		"no KDC":                {Realm: "CORP.EXAMPLE", Principal: "svc-trstctl", Keytab: good},
		"KDC without a port":    {Realm: "CORP.EXAMPLE", Principal: "svc-trstctl", KDCs: []string{"dc1.corp.example"}, Keytab: good},
		"KDC config injection":  {Realm: "CORP.EXAMPLE", Principal: "svc-trstctl", KDCs: []string{"dc1}\n kdc = evil:88"}, Keytab: good},
		"malformed SPN":         {Realm: "CORP.EXAMPLE", Principal: "svc-trstctl", KDCs: []string{"dc1.corp.example:88"}, Keytab: good, SPN: "certsrv"},
		"not a keytab":          {Realm: "CORP.EXAMPLE", Principal: "svc-trstctl", KDCs: []string{"dc1.corp.example:88"}, Keytab: []byte("password")},
		"keytab for another id": {Realm: "CORP.EXAMPLE", Principal: "svc-other", KDCs: []string{"dc1.corp.example:88"}, Keytab: good},
	} {
		if _, err := NewClientAuthenticator(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, err := NewClientAuthenticator(ClientConfig{Realm: "CORP.EXAMPLE", Principal: "svc-trstctl", KDCs: []string{"dc1.corp.example:88", "[2001:db8::1]:88"}, Keytab: good})
	if err != nil {
		t.Fatalf("valid configuration refused: %v", err)
	}
	a.Destroy()
	if a.Scheme() != "Negotiate" {
		t.Fatalf("scheme = %q", a.Scheme())
	}
}

// Without a reachable KDC the authenticator fails the request and sets no
// header: there is no password to fall back to.
func TestClientAuthenticatorFailsClosedWithoutAKDC(t *testing.T) {
	a, err := NewClientAuthenticator(ClientConfig{Realm: "CORP.EXAMPLE", Principal: "svc-trstctl",
		KDCs: []string{"127.0.0.1:1"}, Keytab: clientKeytab(t, "svc-trstctl", "CORP.EXAMPLE", "keytab-derivation-input")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Destroy)
	req := httptest.NewRequest(http.MethodPost, "https://adcs.corp.example/certsrv/certfnsh.asp", nil)
	if err := a.Authorize(req, ""); err == nil || req.Header.Get("Authorization") != "" {
		t.Fatalf("authorize without a KDC = %v, header %q; want a refusal and no header", err, req.Header.Get("Authorization"))
	}
}

// TestLabKDCClientAuthenticatorAnswersNegotiate is the A158 proof against a
// real KDC: the authenticator logs in with a keytab (no password at runtime),
// obtains a service ticket, and a Negotiate-protected endpoint verifying with
// the service keytab admits the account. It runs only with the lab KDC
// variables set (TestLabKDC's), realm LAB.TEST, service HTTP/localhost.
func TestLabKDCClientAuthenticatorAnswersNegotiate(t *testing.T) {
	addr, keytabPath := os.Getenv("TRSTCTL_LAB_KDC_ADDR"), os.Getenv("TRSTCTL_LAB_KDC_KEYTAB")
	user, passwordFile := os.Getenv("TRSTCTL_LAB_KDC_USER"), os.Getenv("TRSTCTL_LAB_KDC_PASSWORD_FILE")
	if addr == "" || keytabPath == "" || user == "" || passwordFile == "" {
		t.Skip("lab KDC not configured")
	}
	password, err := os.ReadFile(passwordFile) // #nosec G304 G703 -- lab password file named by the test environment, never by a request (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	// The operator's export of the account's key; the test derives it from the
	// lab account's password once, as ktutil would.
	accountKeytab := clientKeytab(t, user, "LAB.TEST", strings.TrimSpace(string(password)))
	serviceKeytab, err := keytab.Load(keytabPath)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewFromKeytab(serviceKeytab, Config{Realm: "LAB.TEST"})
	if err != nil {
		t.Fatal(err)
	}
	var admitted Identity
	endpoint := httptest.NewServer(svc.Handler(func(w http.ResponseWriter, _ *http.Request, id Identity) {
		admitted = id
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(endpoint.Close)

	a, err := NewClientAuthenticator(ClientConfig{Realm: "LAB.TEST", Principal: user, KDCs: []string{addr}, Keytab: accountKeytab, SPN: "HTTP/localhost"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Destroy)
	for i := 0; i < 2; i++ { // the second request reuses the TGT and gets a fresh service ticket
		req, err := http.NewRequest(http.MethodGet, endpoint.URL+"/certsrv/", nil) // #nosec G704 -- the test's own loopback httptest server (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Authorize(req, ""); err != nil {
			t.Fatalf("authorize against the lab KDC: %v", err)
		}
		if !strings.HasPrefix(req.Header.Get("Authorization"), "Negotiate ") {
			t.Fatalf("Authorization = %q; want a Negotiate token", req.Header.Get("Authorization"))
		}
		resp, err := endpoint.Client().Do(req) // #nosec G704 -- the test's own loopback httptest server (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || admitted.Principal != user+"@LAB.TEST" {
			t.Fatalf("Negotiate endpoint = %d admitted %+v; want %s@LAB.TEST", resp.StatusCode, admitted, user)
		}
	}
}
