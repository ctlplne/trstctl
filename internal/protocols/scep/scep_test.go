package scep_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/scep"
)

// caFixture is an RSA CA used as both the issuer and the SCEP RA (CMS) key.
type caFixture struct {
	certDER  []byte
	keyPKCS8 []byte
	signer   *crypto.LockedSigner
}

func newRSACA(t *testing.T) caFixture {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	der, err := crypto.SelfSignedCACert(signer, "SCEP Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	return caFixture{certDER: der, keyPKCS8: key, signer: signer}
}

type realEnroller struct{ ca caFixture }

func (e realEnroller) Enroll(_ context.Context, csrDER []byte, _, _, _ string) ([]byte, error) {
	return crypto.SignLeafFromCSR(e.ca.certDER, e.ca.signer, csrDER, time.Hour)
}

// scepClient builds a self-signed cert + CSR for a fresh RSA key (the device side).
func newClient(t *testing.T) (certDER, keyPKCS8, csrDER []byte) {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	certDER, err = crypto.SelfSignedCACert(signer, "device-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPKCS8, err = signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err = crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "device-1"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, keyPKCS8, csrDER
}

// TestSCEPEnrollRoundTrip drives a full RFC 8894 PKIOperation: the client envelopes and
// signs a PKCSReq, the server decrypts it, issues under the profile, and returns a CertRep
// the client decrypts back to its certificate.
func TestSCEPEnrollRoundTrip(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientCert, clientKey, csrDER := newClient(t)
	reqDER, err := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-1")
	if err != nil {
		t.Fatalf("build SCEP request: %v", err)
	}

	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PKIOperation status %d", resp.StatusCode)
	}
	replyDER, _ := io.ReadAll(resp.Body)

	issued, err := crypto.ParseSCEPResponse(replyDER, clientCert, clientKey)
	if err != nil {
		t.Fatalf("parse SCEP CertRep: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(issued, ca.certDER); err != nil {
		t.Errorf("issued certificate is not signed by the CA: %v", err)
	}
}

func TestGetCACertReturnsCA(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{CAChainDER: [][]byte{ca.certDER}, RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/scep?operation=GetCACert")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	der, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(der, ca.certDER) {
		t.Fatalf("GetCACert did not return the CA cert (status %d, %d bytes)", resp.StatusCode, len(der))
	}
}

func TestGetCACapsAdvertisesPOST(t *testing.T) {
	srv := scep.New(scep.Config{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/scep?operation=GetCACaps")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	caps, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(caps, []byte("POSTPKIOperation")) || !bytes.Contains(caps, []byte("SHA-256")) {
		t.Errorf("GetCACaps missing expected capabilities: %q", caps)
	}
}

// TestSCEPChallengeRejected: with an MDM challenge validator that rejects, enrollment
// fails closed (403) before any issuance — the Intune/JAMF gate (S8.5).
func TestSCEPChallengeRejected(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		ChallengeValidator: func(string) error { return errors.New("challenge required") },
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	clientCert, clientKey, csrDER := newClient(t)
	reqDER, _ := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-c1")
	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rejected-challenge enroll status %d, want 403", resp.StatusCode)
	}
}

// TestSCEPChallengeAccepted: with a validator that accepts, enrollment proceeds.
func TestSCEPChallengeAccepted(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
		ChallengeValidator: func(string) error { return nil },
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	clientCert, clientKey, csrDER := newClient(t)
	reqDER, _ := crypto.BuildSCEPRequest(csrDER, clientCert, clientKey, ca.certDER, "txn-c2")
	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accepted-challenge enroll status %d, want 200", resp.StatusCode)
	}
}

func TestMalformedPKIOperationFailsClosed(t *testing.T) {
	ca := newRSACA(t)
	srv := scep.New(scep.Config{
		Enroller: realEnroller{ca: ca}, CAChainDER: [][]byte{ca.certDER},
		RACertDER: ca.certDER, RAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/scep?operation=PKIOperation", "application/x-pki-message", bytes.NewReader([]byte("not a pkiMessage")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed PKIOperation status %d, want 400", resp.StatusCode)
	}
}
