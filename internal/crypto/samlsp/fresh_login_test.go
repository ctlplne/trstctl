// SPDX-License-Identifier: BUSL-1.1

package samlsp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func authnRequestXML(t *testing.T, redirect string) string {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	deflated, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestFreshLoginAsksForForceAuthnA277O1: a fresh sign-in's AuthnRequest asks
// the IdP to authenticate the subject again (ForceAuthn="true"); an ordinary
// one does not. The verified assertion carries when the IdP authenticated the
// subject: the latest AuthnStatement's instant, with its session index.
func TestFreshLoginAsksForForceAuthnA277O1(t *testing.T) {
	sp := aud58SAMLServiceProvider(t, false)
	fresh, err := sp.LoginRedirectFresh("relay-fresh")
	if err != nil {
		t.Fatal(err)
	}
	if req := authnRequestXML(t, fresh.URL); !strings.Contains(req, `ForceAuthn="true"`) || !strings.Contains(req, fresh.RequestID) {
		t.Fatalf("a fresh sign-in's AuthnRequest: %s", req)
	}
	ordinary, err := sp.LoginRedirect("relay")
	if err != nil {
		t.Fatal(err)
	}
	if req := authnRequestXML(t, ordinary.URL); strings.Contains(req, "ForceAuthn") {
		t.Fatalf("an ordinary sign-in asked for ForceAuthn: %s", req)
	}
	earlier, later := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC), time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
	got := normalizeAssertion(&saml.Assertion{AuthnStatements: []saml.AuthnStatement{
		{AuthnInstant: earlier, SessionIndex: "idp-session-1"}, {AuthnInstant: later},
	}})
	if !got.AuthnInstant.Equal(later) || got.SessionIndex != "idp-session-1" {
		t.Fatalf("normalized assertion: instant %s, session %q", got.AuthnInstant, got.SessionIndex)
	}
}
