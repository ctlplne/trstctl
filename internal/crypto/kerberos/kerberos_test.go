// SPDX-License-Identifier: BUSL-1.1

package kerberos

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	testRealm = "LAB.TEST"
	testSPN   = "HTTP/trstctl.lab.test"
)

// serviceKeytab is an in-memory keytab for the service principal, the way a
// KDC export would be loaded from disk.
func serviceKeytab(t *testing.T, password string) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry(testSPN, testRealm, password, time.Now().Add(-time.Hour), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	return kt
}

// negotiateHeader mints a service ticket for user under the service key (what
// the KDC would issue) and wraps it in the SPNEGO token a browser sends.
func negotiateHeader(t *testing.T, kt *keytab.Keytab, user string, start time.Time) string {
	t.Helper()
	cname := types.NewPrincipalName(1, user)
	sname := types.NewPrincipalName(3, testSPN)
	ticketFlags := types.NewKrbFlags()
	types.SetFlag(&ticketFlags, flags.Forwardable)
	tkt, sessionKey, err := messages.NewTicket(cname, testRealm, sname, testRealm, ticketFlags, kt, etypeID.AES256_CTS_HMAC_SHA1_96, 1,
		start, start, start.Add(time.Hour), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	conf, err := krbconfig.NewFromString("[libdefaults]\n default_realm = " + testRealm + "\n")
	if err != nil {
		t.Fatal(err)
	}
	cl := client.NewWithPassword(user, testRealm, "unused", conf)
	nt, err := spnego.NewNegTokenInitKRB5(cl, tkt, sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	token := spnego.SPNEGOToken{Init: true, NegTokenInit: nt}
	raw, err := token.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return "Negotiate " + base64.StdEncoding.EncodeToString(raw)
}

// A79: without a token the handler challenges with Negotiate; a ticket under
// the service key authenticates the principal; a ticket under another key, a
// stale one, a wrong realm and a missing keytab principal are refused.
func TestServiceVerifiesSPNEGOTicketsAgainstTheKeytab(t *testing.T) {
	kt := serviceKeytab(t, "service-password")
	svc, err := NewFromKeytab(kt, Config{ServicePrincipal: testSPN, Realm: testRealm})
	if err != nil {
		t.Fatal(err)
	}
	var seen Identity
	handler := svc.Handler(func(w http.ResponseWriter, _ *http.Request, id Identity) {
		seen = id
		w.WriteHeader(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/kerberos/login", nil))
	if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Negotiate") {
		t.Fatalf("no token = %d %q, want a Negotiate challenge", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/kerberos/login", nil)
	req.Header.Set("Authorization", negotiateHeader(t, kt, "alice", time.Now()))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || seen.Principal != "alice@"+testRealm || seen.Username != "alice" || seen.Realm != testRealm {
		t.Fatalf("valid ticket = %d identity %+v", rec.Code, seen)
	}

	for name, header := range map[string]string{
		"other service key": negotiateHeader(t, serviceKeytab(t, "another-password"), "alice", time.Now()),
		"expired":           negotiateHeader(t, kt, "alice", time.Now().Add(-3*time.Hour)),
		"garbage":           "Negotiate " + base64.StdEncoding.EncodeToString([]byte("not a token")),
	} {
		req := httptest.NewRequest(http.MethodGet, "/auth/kerberos/login", nil)
		req.Header.Set("Authorization", header)
		rec := httptest.NewRecorder()
		seen = Identity{}
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || seen.Principal != "" {
			t.Fatalf("%s = %d identity %+v, want 401 and no identity", name, rec.Code, seen)
		}
	}

	if _, err := NewFromKeytab(kt, Config{ServicePrincipal: "HTTP/other.lab.test"}); err == nil {
		t.Fatal("a service principal absent from the keytab was accepted")
	}
	if _, err := NewFromKeytab(keytab.New(), Config{}); err == nil {
		t.Fatal("an empty keytab was accepted")
	}
	other, err := NewFromKeytab(kt, Config{Realm: "OTHER.TEST"})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/auth/kerberos/login", nil)
	req.Header.Set("Authorization", negotiateHeader(t, kt, "alice", time.Now()))
	rec = httptest.NewRecorder()
	other.Handler(func(w http.ResponseWriter, _ *http.Request, _ Identity) { w.WriteHeader(http.StatusNoContent) }).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ticket from another realm = %d, want 401", rec.Code)
	}
}
