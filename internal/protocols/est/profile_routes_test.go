package est_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestMTLSSiblingRouteEnrollsWithTrustedClientCert(t *testing.T) {
	clientCertDER := selfSignedClientCert(t)
	s, _ := newProfileRouteServer(t, "wifi-profile", denyAuth{})
	s.SetMTLSClientCAs([][]byte{clientCertDER})
	dispatcher, err := est.NewDispatcher([]est.ProfileRoute{
		{PathID: "wifi", Server: s, EnableMTLS: true},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	tlsState, err := crypto.TLSStateWithPeerCertificates([][]byte{clientCertDER})
	if err != nil {
		t.Fatalf("TLSStateWithPeerCertificates: %v", err)
	}

	postESTCSR(t, dispatcher, "/.well-known/est-mtls/wifi/simpleenroll", tlsState, http.StatusOK)
	postESTCSR(t, dispatcher, "/.well-known/est-mtls/wifi/simplereenroll", tlsState, http.StatusOK)
	postESTCSR(t, dispatcher, "/.well-known/est-mtls/wifi/simpleenroll", nil, http.StatusUnauthorized)
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
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, b64Body(deviceCSR(t)))
	if state, ok := tlsState.(*crypto.TLSConnectionState); ok {
		req.TLS = state.ConnectionState()
	}
	h.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("%s status %d (%s), want %d", path, rec.Code, rec.Body.String(), want)
	}
}

func selfSignedClientCert(t *testing.T) []byte {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(signer.Destroy)
	certDER, err := crypto.SelfSignedCACert(signer, "est-client", time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}
	return certDER
}
