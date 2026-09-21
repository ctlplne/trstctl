// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The provider plane must refuse anyone it has not authenticated.
//
// It used to authenticate nobody. operatorFromRequest parsed
// "Bearer provider:<id>:<email>" for SHAPE and returned
// Operator{Role: OperatorAdmin, MFA: true} — no verification of any kind, and
// MFA asserted on the caller's behalf. /provider/ is mounted on the root mux
// behind only a bulkhead whenever the provider plane is licensed, so tenant
// create, suspend, offboard and break-glass were a curl away for anyone who
// knew the token format. The format was in the source.
//
// These tests drive the real handler, because the bug lived in the handler's
// idea of who a caller is and a service-level test would have proved nothing.

// stubAuth accepts exactly one credential, so a test can tell "authenticated"
// from "the door is open".
type stubAuth struct{ accept string }

func (s stubAuth) AuthenticateOperator(r *http.Request) (Operator, bool) {
	if s.accept != "" && r.Header.Get("Authorization") == s.accept {
		return Operator{ID: "op-1", Email: "op@example.test", Role: OperatorAdmin, MFA: true}, true
	}
	return Operator{}, false
}

func providerHandler(t *testing.T, auth OperatorAuthenticator) http.Handler {
	t.Helper()
	return NewHandler(Config{
		License:       providerLicense(t, 5),
		Authenticator: auth,
		// This file is about AUTHENTICATION failing closed. Delegation is the
		// separate axis, granted here so an authentication result is what these
		// tests actually observe.
		Delegations: fullyDelegated("op-1", CustomerID("acme"), CustomerID("bg-tenant")),
	})
}

func TestTheOldShapeOnlyTokenNoLongerAuthenticatesAnyone(t *testing.T) {
	t.Parallel()
	h := providerHandler(t, stubAuth{accept: "Bearer real-credential"})

	// The exact credential that used to mint a provider administrator.
	for _, token := range []string{
		"Bearer provider:anyone:anyone@example.test",
		"Bearer provider:attacker:a@b.c",
		"Bearer provider:x:y",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants",
			bytes.NewBufferString(`{"slug":"acme","name":"Acme"}`))
		req.Header.Set("Authorization", token)
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
			t.Fatalf("token %q provisioned a tenant (status %d). This is the original defect: the "+
				"token was parsed for shape and never verified, so anyone who knew the format was "+
				"a provider administrator with MFA asserted.", token, rec.Code)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q status = %d, want 401", token, rec.Code)
		}
	}
}

// A nil authenticator must close the plane, not open it.
//
// Every other dependency in Config falls back to a working stand-in. This one
// must not: the safe stand-in for "who is this caller" does not exist, and a
// placeholder is exactly how the original behavior came to be.
func TestANilAuthenticatorRefusesEveryRequest(t *testing.T) {
	t.Parallel()
	h := providerHandler(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants",
		bytes.NewBufferString(`{"slug":"acme","name":"Acme"}`))
	req.Header.Set("Authorization", "Bearer provider:anyone:anyone@example.test")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d with no authenticator configured, want 401. An unconfigured "+
			"provider plane must be closed; opening it is how this defect shipped.", rec.Code)
	}
}

// A configured, matching credential still works — the fix must not simply
// break the surface.
func TestAVerifiedOperatorIsStillAdmitted(t *testing.T) {
	t.Parallel()
	h := providerHandler(t, stubAuth{accept: "Bearer real-credential"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants",
		bytes.NewBufferString(`{"slug":"acme","name":"Acme"}`))
	req.Header.Set("Authorization", "Bearer real-credential")
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("a verified operator was refused (status %d); the fix has closed the plane to "+
			"everyone rather than to the unauthenticated", rec.Code)
	}
}

// Break-glass consent must come from the authenticated caller.
//
// This handler did not authenticate at all, and took the consenting subject
// from the request body — so the operator who requested break-glass named
// whatever approver they liked and consented to their own grant with a second
// call. Two-person control defeated by a JSON string.
func TestBreakGlassConsentCannotBeSelfSupplied(t *testing.T) {
	t.Parallel()
	h := providerHandler(t, stubAuth{accept: "Bearer real-credential"})

	// Unauthenticated consent must be refused outright.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/provider/v1/breakglass/g-1/consent",
		bytes.NewBufferString(`{"tenant_id":"t1","subject":"second-approver"}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated consent status = %d, want 401. Consent used to require no "+
			"credential at all.", rec.Code)
	}

	// A tenant to hold the grant.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/provider/v1/tenants",
		bytes.NewBufferString(`{"slug":"bg-tenant","name":"BG Tenant"}`))
	req.Header.Set("Authorization", "Bearer real-credential")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("could not provision a tenant: status %d body %s", rec.Code, rec.Body.String())
	}
	var tenant struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tenant); err != nil {
		t.Fatalf("decode tenant: %v body %s", err, rec.Body.String())
	}
	tenantID := tenant.ID
	if tenantID == "" {
		tenantID = tenant.Slug
	}

	// Now against a REAL grant.
	//
	// A first version of this used a made-up grant id, and the mutation check
	// showed it caught the regression only because a nonexistent grant 404s —
	// the primary "was it accepted" assertion never fired. A test that passes
	// because its fixture is missing proves nothing about the guard, so the
	// grant is created first and the self-consent path is genuinely reachable.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/provider/v1/breakglass",
		bytes.NewBufferString(`{"tenant_id":"`+tenantID+`","reason":"incident 42"}`))
	req.Header.Set("Authorization", "Bearer real-credential")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("could not create a break-glass grant to test against: status %d body %s",
			rec.Code, rec.Body.String())
	}
	var grant struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &grant); err != nil || grant.ID == "" {
		t.Fatalf("grant id missing from response: %v body %s", err, rec.Body.String())
	}

	// The requester now tries to consent to its OWN grant while naming a
	// different approver — the exact two-person-control bypass.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/provider/v1/breakglass/"+grant.ID+"/consent",
		bytes.NewBufferString(`{"tenant_id":"`+tenantID+`","subject":"someone-else"}`))
	req.Header.Set("Authorization", "Bearer real-credential")
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("a caller supplied its own consenting subject against a real grant and was " +
			"accepted; the approver must be the authenticated operator or two-person control is " +
			"a formality defeated by a JSON string")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("supplied-subject consent status = %d, want 400", rec.Code)
	}
}
