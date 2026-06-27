package scep_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/scep"
)

func TestSCEPProfileRoutesPresentDistinctRACerts(t *testing.T) {
	issuer := newRSACA(t)
	corpRA := newRSACA(t)
	iotRA := newRSACA(t)

	corp := scep.New(scep.Config{
		CAChainDER: [][]byte{corpRA.certDER, issuer.certDER},
		RACertDER:  corpRA.certDER, RAKeyPKCS8: corpRA.keyPKCS8,
		ProfileName: "corp",
	})
	iot := scep.New(scep.Config{
		CAChainDER: [][]byte{iotRA.certDER, issuer.certDER},
		RACertDER:  iotRA.certDER, RAKeyPKCS8: iotRA.keyPKCS8,
		ProfileName: "iot",
	})
	dispatcher, err := scep.NewDispatcher([]scep.ProfileRoute{
		{PathID: "corp", Server: corp},
		{PathID: "iot", Server: iot},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	ts := httptest.NewServer(dispatcher)
	defer ts.Close()

	corpCert := firstCACert(t, ts.URL+"/scep/corp?operation=GetCACert")
	iotCert := firstCACert(t, ts.URL+"/scep/iot?operation=GetCACert")

	if !bytes.Equal(corpCert, corpRA.certDER) {
		t.Fatal("corp SCEP profile did not present the corp RA certificate first")
	}
	if !bytes.Equal(iotCert, iotRA.certDER) {
		t.Fatal("iot SCEP profile did not present the iot RA certificate first")
	}
	if bytes.Equal(corpCert, iotCert) {
		t.Fatal("two SCEP profiles presented the same RA certificate")
	}
}

func TestSCEPPerDeviceRateLimitRejectsExcessEnrollments(t *testing.T) {
	ca := newRSACA(t)
	enroller := &countingEnroller{ca: ca}
	srv := scep.New(scep.Config{
		Enroller: enroller, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		MaxEnrollmentsPerDevice: 1, DeviceRateLimitWindow: time.Hour,
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.ServeHTTP(w, r.WithContext(scep.WithTenant(r.Context(), "tenant-a")))
	}))
	defer ts.Close()

	clientCert, clientKey, csrDER := newClientWithTemplate(t, crypto.CertificateRequestTemplate{CommonName: "device-rate-limited"})
	req1, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-rate-1")
	if err != nil {
		t.Fatalf("build first request: %v", err)
	}
	resp1, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(req1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp1.Body.Close() }()
	if resp1.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp1.Body)
		t.Fatalf("first enrollment status %d, want 200: %s", resp1.StatusCode, body)
	}

	req2, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-rate-2")
	if err != nil {
		t.Fatalf("build second request: %v", err)
	}
	resp2, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(req2))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("second enrollment status %d, want 429: %s", resp2.StatusCode, body)
	}
	if got := enroller.Count(); got != 1 {
		t.Fatalf("enroller calls = %d, want 1; rate-limited enrollment must not mint", got)
	}
}

func firstCACert(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetCACert status %d: %s", resp.StatusCode, body)
	}
	certs, err := crypto.CertsFromPKCS7(body)
	if err != nil {
		return body
	}
	return certs[0]
}

type countingEnroller struct {
	ca caFixture
	mu sync.Mutex
	n  int
}

func (e *countingEnroller) Enroll(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
	e.mu.Lock()
	e.n++
	e.mu.Unlock()
	return crypto.SignLeafFromCSR(e.ca.certDER, e.ca.signer, csrDER, time.Hour)
}

func (e *countingEnroller) Count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n
}
