// SPDX-License-Identifier: BUSL-1.1

package est_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/est"
)

type recordingEnroller struct {
	ca       caFixture
	profiles []string
}

func (e *recordingEnroller) Enroll(_ context.Context, csrDER []byte, profileName, _, _ string) ([]byte, error) {
	e.profiles = append(e.profiles, profileName)
	return crypto.SignLeafFromCSR(e.ca.certDER, e.ca.signer, csrDER, time.Hour)
}

func TestPerProfilePathIDDispatchesDistinctProfiles(t *testing.T) {
	wifiSrv, wifiRec := newProfileRouteServer(t, "wifi-profile", allowAuth{})
	iotSrv, iotRec := newProfileRouteServer(t, "iot-profile", allowAuth{})
	dispatcher, err := est.NewDispatcher([]est.ProfileRoute{
		{PathID: "wifi", Server: wifiSrv},
		{PathID: "iot", Server: iotSrv},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}

	postESTCSR(t, dispatcher, "/.well-known/est/wifi/simpleenroll", nil, http.StatusOK)
	postESTCSR(t, dispatcher, "/.well-known/est/iot/simpleenroll", nil, http.StatusOK)

	if got := wifiRec.profiles; len(got) != 1 || got[0] != "wifi-profile" {
		t.Fatalf("wifi route profiles = %v, want [wifi-profile]", got)
	}
	if got := iotRec.profiles; len(got) != 1 || got[0] != "iot-profile" {
		t.Fatalf("iot route profiles = %v, want [iot-profile]", got)
	}
}

func TestBasicAuthPerIPLimiterRejectsBruteForce(t *testing.T) {
	s, _ := newProfileRouteServer(t, "wifi-profile", est.NewBasicAuthenticator(est.BasicAuthConfig{
		Password:         []byte("correct-password"),
		MaxFailuresPerIP: 2,
		Window:           time.Minute,
	}))

	for i, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", b64Body(deviceCSR(t)))
		req.RemoteAddr = "198.51.100.10:4444"
		req.SetBasicAuth("device", "wrong-password")
		s.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("basic auth attempt %d status %d (%s), want %d", i+1, rec.Code, rec.Body.String(), want)
		}
	}
}

func TestPerPrincipalLimiterRejectsEnrollmentFlood(t *testing.T) {
	ca := newCA(t)
	rec := &recordingEnroller{ca: ca}
	s := est.New(est.Config{
		Enroller:                   rec,
		Auth:                       allowAuth{},
		CAChainDER:                 [][]byte{ca.certDER},
		ProfileName:                "wifi-profile",
		MaxEnrollmentsPerPrincipal: 1,
		PrincipalRateLimitWindow:   time.Minute,
	})
	csr := deviceCSR(t)

	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", b64Body(csr))
		req.RemoteAddr = "198.51.100.20:4444"
		s.ServeHTTP(resp, req)
		if resp.Code != want {
			t.Fatalf("principal enrollment attempt %d status %d (%s), want %d", i+1, resp.Code, resp.Body.String(), want)
		}
	}
	if len(rec.profiles) != 1 {
		t.Fatalf("enroller calls after rate limit = %d, want 1", len(rec.profiles))
	}
}

// CR-059: the mutual-TLS route renews only. Initial enrollment and server-side
// keygen are refused there before the body is read (the bootstrap credential on
// the main listener is for those), and a renewal needs the mount's client
// certificate check to accept the presented leaf: a nil check refuses.
func TestMTLSSiblingRouteRenewsOnlyWithAnActiveClientCertificate(t *testing.T) {
	clientCertDER, clientCADER := issuedClientCert(t)
	dispatcherFor := func(check func(context.Context, []byte) error) http.Handler {
		s, _ := newProfileRouteServerWithMTLSCheck(t, "wifi-profile", denyAuth{}, check)
		s.SetMTLSClientCAs([][]byte{clientCADER})
		dispatcher, err := est.NewDispatcher([]est.ProfileRoute{
			{PathID: "wifi", Server: s, EnableMTLS: true},
		})
		if err != nil {
			t.Fatalf("NewDispatcher: %v", err)
		}
		return dispatcher
	}
	tlsState, err := crypto.TLSStateWithPeerCertificates([][]byte{clientCertDER})
	if err != nil {
		t.Fatalf("TLSStateWithPeerCertificates: %v", err)
	}
	var checked [][]byte
	active := dispatcherFor(func(_ context.Context, leafDER []byte) error {
		checked = append(checked, leafDER)
		return nil
	})

	// Initial enrollment is refused on the mutual-TLS route, whatever the CSR.
	postESTCSR(t, active, "/.well-known/est-mtls/wifi/simpleenroll", tlsState, http.StatusForbidden)
	if len(checked) != 0 {
		t.Fatal("the refused enrollment reached the client certificate check")
	}
	// Re-enrollment (RFC 7030 §4.2.2) must reproduce the authenticated identity: a
	// CSR for the client cert's own name succeeds, a cross-identity CSR is refused
	// so a stolen credential cannot re-key an arbitrary name (AUD-201 follow-up).
	postESTCSRBody(t, active, "/.well-known/est-mtls/wifi/simplereenroll", tlsState, clientMatchingCSR(t), http.StatusOK)
	if len(checked) == 0 || !bytes.Equal(checked[0], clientCertDER) {
		t.Fatal("the renewal did not hand the verified leaf to the client certificate check")
	}
	postESTCSRBody(t, active, "/.well-known/est-mtls/wifi/simplereenroll", tlsState, deviceCSR(t), http.StatusForbidden)
	postESTCSR(t, active, "/.well-known/est-mtls/wifi/simpleenroll", nil, http.StatusForbidden)
	postESTCSRBody(t, active, "/.well-known/est-mtls/wifi/simplereenroll", nil, clientMatchingCSR(t), http.StatusUnauthorized)

	// A leaf the check refuses (another tenant's, revoked, not an EST leaf), or a
	// mount with no check at all, renews nothing.
	refused := dispatcherFor(func(context.Context, []byte) error { return errors.New("not an active certificate of this tenant") })
	postESTCSRBody(t, refused, "/.well-known/est-mtls/wifi/simplereenroll", tlsState, clientMatchingCSR(t), http.StatusForbidden)
	unchecked := dispatcherFor(nil)
	postESTCSRBody(t, unchecked, "/.well-known/est-mtls/wifi/simplereenroll", tlsState, clientMatchingCSR(t), http.StatusForbidden)
}

// readRecorder notes whether a handler read the request body.
type readRecorder struct {
	r    io.Reader
	read bool
}

func (r *readRecorder) Read(p []byte) (int, error) {
	r.read = true
	return r.r.Read(p)
}

// CR-058: issuance requires current authorization even when the client
// certificate was active when the request arrived.
func TestMTLSRenewalChecksClientCertificateAtIssuanceAdmission(t *testing.T) {
	leafDER, anchorDER := issuedClientCert(t)
	tlsState, err := crypto.TLSStateWithPeerCertificates([][]byte{leafDER})
	if err != nil {
		t.Fatal(err)
	}
	body := &readRecorder{r: b64Body(clientMatchingCSR(t))}
	checks := 0
	s, enroller := newProfileRouteServerWithMTLSCheck(t, "device", denyAuth{}, func(_ context.Context, der []byte) error {
		checks++
		if !bytes.Equal(der, leafDER) {
			t.Error("the certificate check received a different leaf")
		}
		if body.read {
			return errors.New("client certificate is no longer active")
		}
		return nil
	})
	s.SetMTLSClientCAs([][]byte{anchorDER})
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simplereenroll", body)
	req.TLS = tlsState.ConnectionState()
	resp := httptest.NewRecorder()
	est.MTLSRouteHandler(s).ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden || strings.TrimSpace(resp.Body.String()) != "client certificate is not an active certificate of this mount's tenant" {
		t.Errorf("renewal response status = %d, want 403 with the fixed refusal", resp.Code)
	}
	if checks != 2 || len(enroller.profiles) != 0 {
		t.Errorf("certificate checks = %d, issuance calls = %d, want 2 and 0", checks, len(enroller.profiles))
	}
}

// CR-058: a renewal still waiting for the issuance worker needs current
// certificate standing when the worker takes it.
func TestQueuedMTLSRenewalRequiresCurrentCertificateStanding(t *testing.T) {
	leafDER, anchorDER := issuedClientCert(t)
	tlsState, err := crypto.TLSStateWithPeerCertificates([][]byte{leafDER})
	if err != nil {
		t.Fatal(err)
	}
	pool := bulkhead.New(bulkhead.Config{Name: "est", Workers: 1, Queue: 1})
	defer pool.Close()
	release := make(chan struct{})
	releaseWorker := sync.OnceFunc(func() { close(release) })
	defer releaseWorker()
	if err := pool.Submit(func() { <-release }); err != nil {
		t.Fatal(err)
	}

	var active atomic.Bool
	active.Store(true)
	ca := newCA(t)
	enroller := &recordingEnroller{ca: ca}
	s := est.New(est.Config{
		Enroller: enroller, Pool: pool, MTLSClientCAsDER: [][]byte{anchorDER},
		MTLSClientCertificate: func(context.Context, []byte) error {
			if active.Load() {
				return nil
			}
			return errors.New("client certificate is no longer active")
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simplereenroll", b64Body(clientMatchingCSR(t)))
	req.TLS = tlsState.ConnectionState()
	status := make(chan int, 1)
	go func() {
		resp := httptest.NewRecorder()
		est.MTLSRouteHandler(s).ServeHTTP(resp, req)
		status <- resp.Code
	}()
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for pool.Stats().Queued == 0 {
		select {
		case code := <-status:
			t.Fatalf("renewal returned %d before reaching the issuance queue", code)
		case <-deadline:
			t.Fatal("renewal did not reach the issuance queue")
		case <-tick.C:
		}
	}
	active.Store(false)
	releaseWorker()
	select {
	case code := <-status:
		if code != http.StatusForbidden || len(enroller.profiles) != 0 {
			t.Fatalf("queued renewal returned %d and made %d issuance calls, want 403 and zero calls", code, len(enroller.profiles))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("renewal did not finish after the worker was released")
	}
}

// CR-059: on the served mutual-TLS listener, which answers the standard paths,
// initial enrollment and server-side keygen are refused before the request body
// or the client certificate check is touched, whether or not server-side keygen
// is enabled. A refused renewal names nothing of the check's reason.
func TestMTLSListenerRefusesEnrollmentAndServerKeygenBeforeTheBody(t *testing.T) {
	clientCertDER, clientCADER := issuedClientCert(t)
	tlsState, err := crypto.TLSStateWithPeerCertificates([][]byte{clientCertDER})
	if err != nil {
		t.Fatalf("TLSStateWithPeerCertificates: %v", err)
	}
	serve := func(h http.Handler, op string, body io.Reader) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/"+op, body)
		req.TLS = tlsState.ConnectionState()
		h.ServeHTTP(rec, req)
		return rec
	}
	const reenrollOnly = "the mutual-TLS listener serves re-enrollment only; enroll on the main listener"
	for _, keygenEnabled := range []bool{false, true} {
		ca := newCA(t)
		keygen := &recordingServerKeygen{}
		checks := 0
		s := est.New(est.Config{
			Enroller: &recordingEnroller{ca: ca}, ServerKeygen: keygen, ServerKeygenEnabled: keygenEnabled,
			Auth: allowAuth{}, CAChainDER: [][]byte{ca.certDER},
			MTLSClientCertificate: func(context.Context, []byte) error { checks++; return nil },
		})
		s.SetMTLSClientCAs([][]byte{clientCADER})
		listener := est.MTLSRouteHandler(s)
		for _, op := range []string{"simpleenroll", "serverkeygen"} {
			body := &readRecorder{r: b64Body(clientMatchingCSR(t))}
			rec := serve(listener, op, body)
			if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != reenrollOnly {
				t.Fatalf("keygen enabled=%t: /%s = %d %q; want 403 %q", keygenEnabled, op, rec.Code, rec.Body.String(), reenrollOnly)
			}
			if body.read {
				t.Fatalf("keygen enabled=%t: /%s read the request body before refusing", keygenEnabled, op)
			}
		}
		if checks != 0 || keygen.calls != 0 {
			t.Fatalf("keygen enabled=%t: refused requests reached the certificate check %d times and keygen %d times", keygenEnabled, checks, keygen.calls)
		}
		// The same mount still renews on the listener.
		if rec := serve(listener, "simplereenroll", b64Body(clientMatchingCSR(t))); rec.Code != http.StatusOK || checks != 2 {
			t.Fatalf("keygen enabled=%t: renewal = %d (%s), certificate checks %d; want 200 after two checks", keygenEnabled, rec.Code, rec.Body.String(), checks)
		}
	}

	ca := newCA(t)
	const reason = "serial 0badc0de is tenant other-tenant's"
	s := est.New(est.Config{
		Enroller: &recordingEnroller{ca: ca}, Auth: allowAuth{}, CAChainDER: [][]byte{ca.certDER},
		MTLSClientCertificate: func(context.Context, []byte) error { return errors.New(reason) },
	})
	s.SetMTLSClientCAs([][]byte{clientCADER})
	rec := serve(est.MTLSRouteHandler(s), "simplereenroll", b64Body(clientMatchingCSR(t)))
	if got := strings.TrimSpace(rec.Body.String()); rec.Code != http.StatusForbidden ||
		got != "client certificate is not an active certificate of this mount's tenant" || strings.Contains(got, "0badc0de") {
		t.Fatalf("refused renewal = %d %q; want 403 with the fixed refusal only", rec.Code, got)
	}
}

func newProfileRouteServerWithMTLSCheck(t *testing.T, profileName string, auth est.Authenticator, check func(context.Context, []byte) error) (*est.Server, *recordingEnroller) {
	t.Helper()
	ca := newCA(t)
	rec := &recordingEnroller{ca: ca}
	s := est.New(est.Config{
		Enroller:              rec,
		Auth:                  auth,
		CAChainDER:            [][]byte{ca.certDER},
		ProfileName:           profileName,
		MTLSClientCertificate: check,
	})
	return s, rec
}

func newProfileRouteServer(t *testing.T, profileName string, auth est.Authenticator) (*est.Server, *recordingEnroller) {
	t.Helper()
	ca := newCA(t)
	rec := &recordingEnroller{ca: ca}
	s := est.New(est.Config{
		Enroller:    rec,
		Auth:        auth,
		CAChainDER:  [][]byte{ca.certDER},
		ProfileName: profileName,
	})
	return s, rec
}

func postESTCSR(t *testing.T, h http.Handler, path string, tlsState any, want int) {
	t.Helper()
	postESTCSRBody(t, h, path, tlsState, deviceCSR(t), want)
}

func postESTCSRBody(t *testing.T, h http.Handler, path string, tlsState any, csrDER []byte, want int) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, b64Body(csrDER))
	if state, ok := tlsState.(*crypto.TLSConnectionState); ok {
		req.TLS = state.ConnectionState()
	}
	h.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s status %d (%s), want %d", path, rec.Code, rec.Body.String(), want)
	}
}

// clientMatchingCSR builds a CSR whose subject is the identity issuedClientCert
// asserts ("est-client"), so the re-enrollment identity binding accepts it.
func clientMatchingCSR(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "est-client"}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// issuedClientCert issues a clientAuth leaf for "est-client" under a fresh CA
// and returns the leaf and the CA certificate.
func issuedClientCert(t *testing.T) ([]byte, []byte) {
	t.Helper()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "est-client-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := crypto.SignLeafFromCSR(caDER, caKey, clientMatchingCSR(t), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return leafDER, caDER
}
