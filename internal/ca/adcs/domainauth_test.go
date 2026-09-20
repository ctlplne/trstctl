// SPDX-License-Identifier: BUSL-1.1

package adcs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F4: "no plaintext Basic".
//
// Basic sends base64, which is an encoding and not a protection. On a plaintext
// hop anyone on the path reads a domain credential that can issue from the
// enterprise CA directly — the compromise is not "an eavesdropper saw a
// request", it is "an attacker can now mint certificates your whole estate
// trusts".

func TestAPasswordIsNeverSentOverPlaintext(t *testing.T) {
	t.Parallel()
	_, err := NewWebEnrollmentTransport(WebEnrollmentConfig{
		BaseURL:  "http://adcs.corp.example/certsrv",
		Username: "svc-trstctl",
		Password: []byte("hunter2"),
	})
	if err == nil {
		t.Fatal("a password was accepted for a plaintext http:// endpoint.\n\n" +
			"Basic is base64, not encryption. Anyone on the path reads a credential that can " +
			"issue from the enterprise CA, and every certificate they mint is trusted by the " +
			"whole domain.")
	}
	if !strings.Contains(err.Error(), "not encryption") {
		t.Errorf("error does not explain why: %v", err)
	}
}

// The same endpoint with no password is fine — an operator may front certsrv
// with a proxy that authenticates for them.
func TestPlaintextWithoutAPasswordIsStillAllowed(t *testing.T) {
	t.Parallel()
	if _, err := NewWebEnrollmentTransport(WebEnrollmentConfig{
		BaseURL:    "http://adcs.corp.example/certsrv",
		HTTPClient: &http.Client{},
	}); err != nil {
		t.Fatalf("a passwordless plaintext endpoint was refused: %v.\n\n"+
			"The rule is about not LEAKING a credential, not about forbidding http; a "+
			"reverse proxy that supplies Kerberos is a legitimate deployment", err)
	}
}

type fakeAuth struct {
	scheme string
	calls  int
	err    error
}

func (f *fakeAuth) Authorize(req *http.Request, _ string) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	req.Header.Set("Authorization", f.scheme+" fake-token")
	return nil
}
func (f *fakeAuth) Scheme() string { return f.scheme }

// A domain-integrated authenticator must REPLACE Basic, never sit alongside it.
func TestDomainAuthReplacesBasicRatherThanSupplementingIt(t *testing.T) {
	t.Parallel()
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("certificate issued"))
	}))
	defer srv.Close()

	auth := &fakeAuth{scheme: "Negotiate"}
	tr, err := NewWebEnrollmentTransport(WebEnrollmentConfig{
		BaseURL: srv.URL, Username: "svc",
		Authenticator: auth, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/certsrv", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tr.roundTrip(req)

	if auth.calls != 1 {
		t.Fatalf("the authenticator was called %d times, want 1", auth.calls)
	}
	if strings.HasPrefix(seen, "Basic ") {
		t.Fatalf("Basic was sent even though a domain authenticator was configured (%q).\n\n"+
			"Falling back to Basic quietly downgrades to the scheme the operator deliberately "+
			"moved away from, and the password they thought was unused goes on the wire.", seen)
	}
	if !strings.HasPrefix(seen, "Negotiate ") {
		t.Fatalf("Authorization = %q, want the domain authenticator's header", seen)
	}
}

// Configuring both is refused: a live domain credential sitting in config that
// nothing reads is what somebody later "fixes" by making it take effect.
func TestAPasswordAndADomainAuthenticatorCannotBothBeConfigured(t *testing.T) {
	t.Parallel()
	_, err := NewWebEnrollmentTransport(WebEnrollmentConfig{
		BaseURL: "https://adcs.corp.example/certsrv", Username: "svc",
		Password: []byte("hunter2"), Authenticator: &fakeAuth{scheme: "Negotiate"},
	})
	if err == nil {
		t.Fatal("both a password and a domain authenticator were accepted. The password is dead " +
			"config, and dead config in a credential field is what somebody later makes live")
	}
}

// A failing authenticator must fail the request, not fall through to Basic.
func TestAFailingDomainAuthDoesNotFallBackToBasic(t *testing.T) {
	t.Parallel()
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	tr, err := NewWebEnrollmentTransport(WebEnrollmentConfig{
		BaseURL: srv.URL, Username: "svc",
		Authenticator: &fakeAuth{scheme: "Negotiate", err: http.ErrNoCookie},
		HTTPClient:    srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/certsrv", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.roundTrip(req); err == nil {
		t.Fatal("a failed domain authentication succeeded anyway")
	}
	if strings.HasPrefix(seen, "Basic ") {
		t.Fatal("the request fell back to Basic after domain auth failed. A transient Kerberos " +
			"problem would silently put the domain password on the wire")
	}
}
