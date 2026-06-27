package est_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/est"
)

func TestChannelBindingRequiredAllowsMatchingCSR(t *testing.T) {
	s, serverCertDER := newChannelBindingServer(t)
	binding, err := crypto.TLSServerEndPoint(serverCertDER)
	if err != nil {
		t.Fatalf("tls-server-end-point: %v", err)
	}

	for _, path := range []string{"/.well-known/est/simpleenroll", "/.well-known/est/simplereenroll"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, b64Body(deviceCSRWithESTBinding(t, binding)))
		req.Header.Set("Content-Type", "application/pkcs10")
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s with matching channel binding status %d (%s), want 200", path, rec.Code, rec.Body.String())
		}
	}
}

func TestChannelBindingRequiredRejectsMissingOrMismatchedCSR(t *testing.T) {
	s, serverCertDER := newChannelBindingServer(t)
	binding, err := crypto.TLSServerEndPoint(serverCertDER)
	if err != nil {
		t.Fatalf("tls-server-end-point: %v", err)
	}
	mismatch := append([]byte(nil), binding...)
	mismatch[0] ^= 0xff

	for _, tc := range []struct {
		name string
		csr  []byte
		want int
	}{
		{name: "missing", csr: deviceCSR(t), want: http.StatusBadRequest},
		{name: "mismatch", csr: deviceCSRWithESTBinding(t, mismatch), want: http.StatusConflict},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simplereenroll", b64Body(tc.csr))
		req.Header.Set("Content-Type", "application/pkcs10")
		s.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s channel binding status %d (%s), want %d", tc.name, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

func TestOptionalChannelBindingStillRejectsMismatchedAssertion(t *testing.T) {
	ca := newCA(t)
	binding, err := crypto.TLSServerEndPoint(ca.certDER)
	if err != nil {
		t.Fatalf("tls-server-end-point: %v", err)
	}
	binding[0] ^= 0xff
	s := est.New(est.Config{
		Enroller:                     realEnroller{ca: ca},
		Auth:                         allowAuth{},
		CAChainDER:                   [][]byte{ca.certDER},
		ProfileName:                  "iot",
		ChannelBindingCertificateDER: ca.certDER,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", b64Body(deviceCSRWithESTBinding(t, binding)))
	req.Header.Set("Content-Type", "application/pkcs10")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("optional mismatched channel binding status %d (%s), want 409", rec.Code, rec.Body.String())
	}
}

func newChannelBindingServer(t *testing.T) (*est.Server, []byte) {
	t.Helper()
	ca := newCA(t)
	s := est.New(est.Config{
		Enroller:                     realEnroller{ca: ca},
		Auth:                         allowAuth{},
		CAChainDER:                   [][]byte{ca.certDER},
		ProfileName:                  "iot",
		ChannelBindingRequired:       true,
		ChannelBindingCertificateDER: ca.certDER,
	})
	return s, ca.certDER
}

func deviceCSRWithESTBinding(t *testing.T, binding []byte) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:        "device-1",
		DNSNames:          []string{"device-1.iot.test"},
		ESTChannelBinding: binding,
	}, key)
	if err != nil {
		t.Fatalf("create channel-bound CSR: %v", err)
	}
	return csr
}
