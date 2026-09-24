// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func loginReturnIssuer() *SessionIssuer {
	s := NewSessionIssuer([]byte(strings.Repeat("k", 32)), time.Hour)
	s.Now = func() time.Time { return time.Unix(2000000000, 0) }
	return s
}

func TestLoginReturnBoundAcrossInstances(t *testing.T) {
	for _, destination := range []string{"/", "/certificates?owner=a%20b#inventory", "/" + strings.Repeat("<", 4095), "/" + strings.Repeat("é", 2047)} {
		s := loginReturnIssuer()
		token, err := s.SealLoginReturn("saml", strings.Repeat("s", 128), strings.Repeat("r", 512), destination)
		if err != nil || len(token) > maxLoginReturnToken {
			t.Fatalf("seal failed or exceeded wire bound: %v", err)
		}
		other := loginReturnIssuer()
		got, err := other.OpenLoginReturn("saml", strings.Repeat("s", 128), strings.Repeat("r", 512), token)
		if err != nil || got != destination {
			t.Fatalf("separate instance did not preserve destination: %v", err)
		}
		if _, err := other.Verify(token); err == nil {
			t.Fatal("return context accepted as an authenticated session")
		}
	}
}

func TestLoginReturnRejectsUntrustedContext(t *testing.T) {
	s := loginReturnIssuer()
	token, err := s.SealLoginReturn("saml", "state", "request", "/certificates")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, purpose, state, request, token string
		clock                                int64
		otherKey                             bool
	}{
		{"purpose", "oidc", "state", "request", token, 2000000000, false},
		{"state", "saml", "other", "request", token, 2000000000, false},
		{"request", "saml", "state", "other", token, 2000000000, false},
		{"key", "saml", "state", "request", token, 2000000000, true},
		{"payload", "saml", "state", "request", "A" + token[1:], 2000000000, false},
		{"signature", "saml", "state", "request", token[:len(token)-3] + "AAA", 2000000000, false},
		{"expired", "saml", "state", "request", token, 2000000600, false},
		{"future", "saml", "state", "request", token, 1999999999, false},
		{"empty", "saml", "state", "request", "", 2000000000, false},
		{"oversized", "saml", "state", "request", strings.Repeat("a", 7001), 2000000000, false},
		{"extra segment", "saml", "state", "request", token + ".extra", 2000000000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier := loginReturnIssuer()
			verifier.Now = func() time.Time { return time.Unix(tc.clock, 0) }
			if tc.otherKey {
				verifier.secret = []byte(strings.Repeat("x", 32))
			}
			if _, err := verifier.OpenLoginReturn(tc.purpose, tc.state, tc.request, tc.token); err != ErrLoginReturn {
				t.Fatal("untrusted context was not rejected")
			}
		})
	}
	s.Now = func() time.Time { return time.Unix(2000000599, 0) }
	if _, err := s.OpenLoginReturn("saml", "state", "request", token); err != nil {
		t.Fatal("context expired before the ten-minute boundary")
	}
}

func TestLoginReturnRejectsMalformedSignedEnvelope(t *testing.T) {
	s := loginReturnIssuer()
	for _, payload := range []string{
		"2\x002000000000\x00state\x00request\x00/",
		"1\x00+2000000000\x00state\x00request\x00/",
		"1\x002000000000\x00state\x00request",
		"1\x002000000000\x00state\x00request\x00",
		"1\x002000000000\x00state\x00request\x00/\x00extra",
		"1\x002000000000\x00state\x00request\x00/" + strings.Repeat("a", 4096),
	} {
		key := s.loginReturnKey("saml")
		mac := crypto.HMACSHA256(key, []byte(payload))
		token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac)
		secret.Wipe(key)
		secret.Wipe(mac)
		if _, err := s.OpenLoginReturn("saml", "state", "request", token); err != ErrLoginReturn {
			t.Fatal("malformed signed envelope accepted")
		}
	}
}

func TestLoginReturnSealRejectsInvalidFields(t *testing.T) {
	s := loginReturnIssuer()
	for _, fields := range [][4]string{
		{"", "state", "request", "/"}, {"saml", "", "request", "/"},
		{"saml", "state", "", "/"}, {"saml", "state", "request", ""},
		{strings.Repeat("p", 65), "state", "request", "/"},
		{"saml", strings.Repeat("s", 129), "request", "/"},
		{"saml", "state", strings.Repeat("r", 513), "/"},
		{"saml", "state", "request", strings.Repeat("a", 4097)},
		{"saml", "state", "request", "/\x00"},
	} {
		if _, err := s.SealLoginReturn(fields[0], fields[1], fields[2], fields[3]); err != ErrLoginReturn {
			t.Fatal("invalid fields accepted")
		}
	}
	s.secret = nil
	if _, err := s.SealLoginReturn("saml", "state", "request", "/"); err != ErrLoginReturn {
		t.Fatal("missing key accepted")
	}
}

func FuzzLoginReturnOpen(f *testing.F) {
	s := loginReturnIssuer()
	token, err := s.SealLoginReturn("saml", "state", "request", "/certificates")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token)
	f.Add("")
	f.Add("bad.bad")
	f.Fuzz(func(t *testing.T, input string) {
		destination, err := s.OpenLoginReturn("saml", "state", "request", input)
		if err == nil && destination != "/certificates" {
			t.Fatal("untrusted bytes produced a different authenticated destination")
		}
	})
}
