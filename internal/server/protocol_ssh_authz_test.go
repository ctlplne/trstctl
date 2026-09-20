// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/est"
	"trstctl.com/trstctl/internal/protocols/ssh"
)

// newTestSSHCA builds a real signer-backed SSH CA so the served handlers run
// their genuine code paths rather than tripping over a nil dependency.
func newTestSSHCA(t *testing.T) *ssh.CA {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	ca, err := ssh.New(ssh.Config{TenantID: "tenant-a", Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// denyAllSSHAuth stands in for the real bearer authenticator: it refuses every
// request, which is what an anonymous caller sees.
type denyAllSSHAuth struct{ calls int }

func (d *denyAllSSHAuth) Authenticate(*http.Request) est.AuthenticationResult {
	d.calls++
	return est.AuthenticationResult{StatusCode: http.StatusUnauthorized, Challenge: `Bearer realm="ssh"`}
}

// allowAllSSHAuth stands in for a bearer token that carries certs:issue.
type allowAllSSHAuth struct{ calls int }

func (a *allowAllSSHAuth) Authenticate(*http.Request) est.AuthenticationResult {
	a.calls++
	return est.AuthenticationResult{Allowed: true}
}

// TestServedSSHMutatingRoutesRequireAuthentication is the regression guard for
// the served SSH CA's anonymous-issuance defect. POST /ssh/issue/user,
// /ssh/issue/host and /ssh/revoke were mounted with no authenticator at all, so
// any client that could reach the listener could mint an SSH user certificate
// naming `root` — ssh.Profile carries no principal allowlist, and issue() checks
// only that principals are non-empty and the TTL is within MaxTTL. Any host
// configured with this CA in TrustedUserCAKeys was fully compromised.
//
// The test drives the real mux, so it fails if a route is ever registered
// without the wrapper.
func TestServedSSHMutatingRoutesRequireAuthentication(t *testing.T) {
	deny := &denyAllSSHAuth{}
	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", deny)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","key_id":"x","principals":["root"],"ttl_seconds":3600}`
	for _, route := range []struct{ method, path, payload string }{
		{http.MethodPost, "/ssh/issue/user", body},
		{http.MethodPost, "/ssh/issue/host", body},
		{http.MethodPost, "/ssh/revoke", `{"serial":1}`},
	} {
		t.Run(route.path, func(t *testing.T) {
			before := deny.calls
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest(route.method, route.path, strings.NewReader(route.payload)))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous %s %s = %d, want 401 — the SSH CA mints to unauthenticated callers",
					route.method, route.path, rec.Code)
			}
			if deny.calls == before {
				t.Fatalf("%s %s never consulted the authenticator; the route is not gated", route.method, route.path)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got == "" {
				t.Error("denial must carry an authentication challenge")
			}
		})
	}
}

// TestServedSSHTrustMaterialStaysPublic pins the other half of the contract: the
// two GET routes serve the material a host needs BEFORE it can authenticate
// anything (the CA public key for TrustedUserCAKeys, and the binary KRL for
// RevokedKeys), exactly like a CRL distribution point. Gating those would break
// every host bootstrap, so the fix must not over-reach.
func TestServedSSHTrustMaterialStaysPublic(t *testing.T) {
	deny := &denyAllSSHAuth{}
	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", deny)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/ssh/ca", "/ssh/krl"} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("GET %s must stay public: a host fetches it before it can authenticate", path)
		}
	}
	if deny.calls != 0 {
		t.Errorf("public trust routes consulted the authenticator %d times", deny.calls)
	}
}

// TestServedSSHRefusesConstructionWithoutAuthenticator makes the fail-closed
// construction explicit: a nil authenticator must not silently produce an open
// CA, which is how the original defect would return.
func TestServedSSHRefusesConstructionWithoutAuthenticator(t *testing.T) {
	if _, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", nil); err == nil {
		t.Fatal("newSSHProtocol accepted a nil authenticator; the served SSH CA would be anonymous again")
	}
}

// TestServedSSHAuthenticatedRequestReachesHandler proves the gate is not a
// blanket denial: an authorized caller passes the wrapper and reaches the
// handler. (Issuance itself then fails on the nil CA, which is fine — what is
// asserted here is that the request was let through.)
func TestServedSSHAuthenticatedRequestReachesHandler(t *testing.T) {
	allow := &allowAllSSHAuth{}
	p, err := newSSHProtocol(newTestSSHCA(t), "tenant-a", allow)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ssh/revoke", strings.NewReader(`{"serial":1}`)))
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("an authorized caller was refused; the gate rejects everything")
	}
	if allow.calls != 1 {
		t.Fatalf("authenticator consulted %d times, want 1", allow.calls)
	}
}
