// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
)

type acmeAuthModeLog struct {
	events []events.Event
}

func (l *acmeAuthModeLog) Append(_ context.Context, ev events.Event) (events.Event, error) {
	l.events = append(l.events, ev)
	return ev, nil
}

func (l *acmeAuthModeLog) Replay(_ context.Context, _ uint64, _ func(events.Event) error) error {
	return nil
}

func TestACMETrustAuthenticatedProfileMakesOrderReadyWithoutDVChallenge(t *testing.T) {
	srv, err := New(nil, failingValidator{}).WithCertificateProfile(profile.CertificateProfile{
		Name:         "internal-pki",
		ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
	})
	if err != nil {
		t.Fatalf("configure trust-authenticated profile: %v", err)
	}
	log := &acmeAuthModeLog{}
	if _, err := srv.WithStateLog(context.Background(), "tenant-acme", log); err != nil {
		t.Fatalf("bind ACME state log: %v", err)
	}

	srv.meta.ExternalAccountRequired = true
	srv.eabCredentials = map[string]*eabCredential{"internal": {keyID: "internal"}}
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid, eabKeyID: "internal"}
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"svc.internal.test"}]}`)}
	rec := httptest.NewRecorder()
	srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	if rec.Code != http.StatusCreated {
		t.Fatalf("new order status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode new-order response: %v", err)
	}
	if body.Status != statusReady {
		t.Fatalf("trust-authenticated order status = %q, want ready", body.Status)
	}
	if len(srv.orders) != 1 {
		t.Fatalf("orders retained = %d, want 1", len(srv.orders))
	}
	for _, az := range srv.authzs {
		if az.status != statusValid {
			t.Fatalf("trust-authenticated authz status = %q, want valid", az.status)
		}
		for _, ch := range az.challenges {
			if ch.status != statusValid {
				t.Fatalf("trust-authenticated placeholder challenge status = %q, want valid", ch.status)
			}
		}
	}
	if len(log.events) != 1 || log.events[0].Type != acmeEventOrderCreated {
		t.Fatalf("state events = %+v, want one order-created event", log.events)
	}
	if !strings.Contains(string(log.events[0].Data), `"auth_mode":"trust_authenticated"`) {
		t.Fatalf("order-created event does not record trust-authenticated skip: %s", string(log.events[0].Data))
	}
}

func TestACMEPublicTrustProfileStillRequiresDVChallenge(t *testing.T) {
	srv, err := New(nil, AcceptAll{}).WithCertificateProfile(profile.CertificateProfile{
		Name:         "public-web",
		ACMEAuthMode: profile.ACMEAuthModePublicTrust,
	})
	if err != nil {
		t.Fatalf("configure public-trust profile: %v", err)
	}
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"www.example.test"}]}`)}
	rec := httptest.NewRecorder()
	srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	if rec.Code != http.StatusCreated {
		t.Fatalf("new order status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode new-order response: %v", err)
	}
	if body.Status != statusPending {
		t.Fatalf("public-trust order status = %q, want pending", body.Status)
	}
	for _, az := range srv.authzs {
		if az.status != statusPending {
			t.Fatalf("public-trust authz status = %q, want pending", az.status)
		}
		if len(az.challenges) != 3 {
			t.Fatalf("public-trust challenge count = %d, want 3 DV challenges", len(az.challenges))
		}
		for _, ch := range az.challenges {
			if ch.status != statusPending {
				t.Fatalf("public-trust challenge status = %q, want pending", ch.status)
			}
		}
	}
}

func TestACMETrustAuthenticatedProfileStillRejectsUnauthenticatedOrder(t *testing.T) {
	srv, err := New(nil, AcceptAll{}).WithCertificateProfile(profile.CertificateProfile{
		Name:         "internal-pki",
		ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
	})
	if err != nil {
		t.Fatalf("configure trust-authenticated profile: %v", err)
	}
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"svc.internal.test"}]}`)}
	rec := httptest.NewRecorder()
	srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated trust-authenticated order status = %d, want 401: %s", rec.Code, rec.Body.String())
	}
	if len(srv.orders) != 0 {
		t.Fatalf("unauthenticated order created %d orders, want 0", len(srv.orders))
	}
}

func TestACMETrustAuthenticatedProfileRequiresEABBoundAccount(t *testing.T) {
	srv, err := New(nil, AcceptAll{}).WithCertificateProfile(profile.CertificateProfile{
		ACMEAuthMode: profile.ACMEAuthModeTrustAuthenticated,
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"svc.internal.test"}]}`)}
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
	for _, required := range []bool{false, true} {
		srv.meta.ExternalAccountRequired = required
		rec := httptest.NewRecorder()
		srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
		if rec.Code != http.StatusForbidden || len(srv.orders) != 0 {
			t.Fatalf("required=%v: unbound account got %d, orders=%d: %s", required, rec.Code, len(srv.orders), rec.Body.String())
		}
	}
	acct.eabKeyID = "internal"
	srv.eabCredentials = map[string]*eabCredential{"internal": {keyID: "internal"}}
	srv.meta.ExternalAccountRequired = false
	rec := httptest.NewRecorder()
	srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	if rec.Code != http.StatusForbidden || len(srv.orders) != 0 {
		t.Fatalf("trust mode without required EAB got %d, orders=%d: %s", rec.Code, len(srv.orders), rec.Body.String())
	}
}

func TestACMEActiveProfileModeIsResolvedForEachOrder(t *testing.T) {
	srv := New(nil, AcceptAll{})
	srv.meta.ExternalAccountRequired = true
	srv.eabCredentials = map[string]*eabCredential{"internal": {keyID: "internal"}}
	mode := profile.ACMEAuthModePublicTrust
	srv.WithCertificateProfileResolver(func(context.Context) (profile.CertificateProfile, error) {
		return profile.CertificateProfile{ACMEAuthMode: mode}, nil
	})
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid, eabKeyID: "internal"}
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"svc.internal.test"}]}`)}
	for _, tc := range []struct {
		mode profile.ACMEAuthMode
		want string
	}{{profile.ACMEAuthModePublicTrust, statusPending}, {profile.ACMEAuthModeTrustAuthenticated, statusReady}} {
		mode = tc.mode
		rec := httptest.NewRecorder()
		srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
		if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"status":"`+tc.want+`"`) {
			t.Fatalf("mode %q got %d %s, want %s", tc.mode, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

func TestACMEActiveProfileReadFailureRefusesOrderWithoutFallback(t *testing.T) {
	srv := New(nil, AcceptAll{})
	srv.WithCertificateProfileResolver(func(context.Context) (profile.CertificateProfile, error) {
		return profile.CertificateProfile{}, errors.New("profile store unavailable")
	})
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
	msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"svc.internal.test"}]}`)}
	rec := httptest.NewRecorder()
	srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
	if rec.Code != http.StatusServiceUnavailable || len(srv.orders) != 0 {
		t.Fatalf("failed profile read got %d, orders=%d: %s", rec.Code, len(srv.orders), rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "profile store unavailable") {
		t.Fatal("profile store error leaked into public ACME response")
	}
}

func TestACMEInternalTrustReadyOrderCannotFinalizeAfterProfileOrEABRevocation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    profile.ACMEAuthMode
		disable bool
	}{{"profile switches to public trust", profile.ACMEAuthModePublicTrust, false},
		{"EAB credential is disabled", profile.ACMEAuthModeTrustAuthenticated, true}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(nil, AcceptAll{})
			srv.meta.ExternalAccountRequired = true
			srv.eabCredentials = map[string]*eabCredential{"internal": {keyID: "internal", disabledByOperator: tc.disable}}
			srv.WithCertificateProfileResolver(func(context.Context) (profile.CertificateProfile, error) {
				return profile.CertificateProfile{ACMEAuthMode: tc.mode}, nil
			})
			acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid, eabKeyID: "internal"}
			srv.orders["order"] = &order{id: "order", accountURL: acct.url, status: statusReady,
				authMode: profile.ACMEAuthModeTrustAuthenticated}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "http://ca.test/acme/order/order/finalize", nil)
			req.SetPathValue("id", "order")
			srv.finalize(rec, req, &jose.ACMEMessage{}, acct)
			if rec.Code != http.StatusForbidden || srv.orders["order"].status != statusReady {
				t.Fatalf("finalize after grant change got %d, status=%q: %s", rec.Code, srv.orders["order"].status, rec.Body.String())
			}
		})
	}
}

type failingValidator struct{}

func (failingValidator) Validate(context.Context, string, string, string, string) error {
	return context.Canceled
}
