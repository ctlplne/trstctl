// SPDX-License-Identifier: BUSL-1.1

package kerberos

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// TestLabKDC verifies a ticket issued by a real KDC (A79 proof). It runs only
// with TRSTCTL_LAB_KDC_ADDR, TRSTCTL_LAB_KDC_KEYTAB, TRSTCTL_LAB_KDC_USER and
// TRSTCTL_LAB_KDC_PASSWORD_FILE set (the lab's MIT KDC; realm LAB.TEST,
// service HTTP/localhost), and prints the library's own verdict so a refusal
// names its cause.
func TestLabKDC(t *testing.T) {
	addr, keytabPath := os.Getenv("TRSTCTL_LAB_KDC_ADDR"), os.Getenv("TRSTCTL_LAB_KDC_KEYTAB")
	user, passwordFile := os.Getenv("TRSTCTL_LAB_KDC_USER"), os.Getenv("TRSTCTL_LAB_KDC_PASSWORD_FILE")
	if addr == "" || keytabPath == "" || user == "" || passwordFile == "" {
		t.Skip("lab KDC not configured")
	}
	password, err := os.ReadFile(passwordFile) // #nosec G304 G703 -- lab password file named by the test environment, never by a request (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := krbconfig.NewFromString("[libdefaults]\n default_realm = LAB.TEST\n dns_lookup_kdc = false\n udp_preference_limit = 1\n[realms]\n LAB.TEST = {\n  kdc = " + addr + "\n }\n")
	if err != nil {
		t.Fatal(err)
	}
	cl := client.NewWithPassword(user, "LAB.TEST", strings.TrimSpace(string(password)), conf, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		t.Fatalf("KDC login: %v", err)
	}
	tkt, key, err := cl.GetServiceTicket("HTTP/localhost")
	if err != nil {
		t.Fatalf("service ticket: %v", err)
	}
	t.Logf("service ticket: sname=%v realm=%s etype=%d kvno=%d", tkt.SName.PrincipalNameString(), tkt.Realm, tkt.EncPart.EType, tkt.EncPart.KVNO)
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range kt.Entries {
		t.Logf("keytab entry: %s kvno=%d etype=%d", e.Principal.String(), e.KVNO, e.Key.KeyType)
	}
	nt, err := spnego.NewNegTokenInitKRB5(cl, tkt, key)
	if err != nil {
		t.Fatal(err)
	}
	token := spnego.SPNEGOToken{Init: true, NegTokenInit: nt}
	raw, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewFromKeytab(kt, Config{ServicePrincipal: "HTTP/localhost", Realm: "LAB.TEST"})
	if err != nil {
		t.Fatal(err)
	}
	var seen Identity
	req := httptest.NewRequest(http.MethodGet, "/auth/kerberos/login", nil)
	req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(raw))
	rec := httptest.NewRecorder()
	svc.Handler(func(w http.ResponseWriter, _ *http.Request, id Identity) {
		seen = id
		w.WriteHeader(http.StatusNoContent)
	}).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || seen.Principal != user+"@LAB.TEST" {
		// The library's own verdict on a fresh token (an authenticator verifies
		// once; the replay cache refuses a second look at the same one).
		tkt2, key2, err := cl.GetServiceTicket("HTTP/localhost")
		if err != nil {
			t.Fatal(err)
		}
		nt2, _ := spnego.NewNegTokenInitKRB5(cl, tkt2, key2)
		token2 := spnego.SPNEGOToken{Init: true, NegTokenInit: nt2}
		raw2, _ := token2.Marshal()
		var parsed spnego.SPNEGOToken
		_ = parsed.Unmarshal(raw2)
		ok, _, status := spnego.SPNEGOService(kt).AcceptSecContext(&parsed)
		t.Fatalf("real KDC ticket = %d identity %+v (library with default settings: ok=%v %q)", rec.Code, seen, ok, status.Message)
	}
}
