package cmp_test

import (
	"bytes"
	"context"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	cmpsrv "trstctl.com/trstctl/internal/protocols/cmp"
)

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
	der, err := crypto.SelfSignedCACert(signer, "CMP Test CA", time.Hour)
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

func buildRequest(t *testing.T, clientCert, clientKey, csrDER []byte) []byte {
	t.Helper()
	txid, _ := crypto.RandomBytes(16)
	nonce, _ := crypto.RandomBytes(16)
	reqDER, err := crypto.BuildCMPRequest(csrDER, clientCert, clientKey, txid, nonce)
	if err != nil {
		t.Fatalf("build CMP request: %v", err)
	}
	return reqDER
}

// TestCMPEnrollRoundTrip drives a full p10cr enrollment: the client builds a
// signature-protected PKIMessage carrying its CSR, the server verifies the protection,
// issues under the profile, and returns a signed cp the client parses to its cert.
func TestCMPEnrollRoundTrip(t *testing.T) {
	ca := newRSACA(t)
	srv := cmpsrv.New(cmpsrv.Config{
		Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device",
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientCert, clientKey, csrDER := newClient(t)
	reqDER := buildRequest(t, clientCert, clientKey, csrDER)

	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CMP status %d", resp.StatusCode)
	}
	replyDER, _ := io.ReadAll(resp.Body)
	issued, err := crypto.ParseCMPResponse(replyDER)
	if err != nil {
		t.Fatalf("parse CMP response: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(issued, ca.certDER); err != nil {
		t.Errorf("issued certificate is not signed by the CA: %v", err)
	}
}

func TestCMPResponseEchoesRequestPvno(t *testing.T) {
	ca := newRSACA(t)
	_, _, csrDER := newClient(t)
	req := &crypto.CMPRequest{
		Pvno:          2,
		CSRDER:        csrDER,
		TransactionID: []byte("txid"),
		SenderNonce:   []byte("nonce"),
	}
	leaf, err := crypto.SignLeafFromCSR(ca.certDER, ca.signer, csrDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	replyDER, err := crypto.BuildCMPResponse(leaf, ca.certDER, ca.keyPKCS8, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := cmpMessagePvno(t, replyDER); got != 2 {
		t.Fatalf("CMP response pvno = %d, want request pvno 2 for stock OpenSSL compatibility", got)
	}
}

func TestCMPMalformedFailsClosed(t *testing.T) {
	ca := newRSACA(t)
	srv := cmpsrv.New(cmpsrv.Config{Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device"})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader([]byte("not a PKIMessage")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed CMP status %d, want 400", resp.StatusCode)
	}
}

func cmpMessagePvno(t *testing.T, der []byte) int {
	t.Helper()
	var msg struct {
		Header struct {
			Pvno int
		}
	}
	if _, err := asn1.Unmarshal(der, &msg); err != nil {
		t.Fatalf("parse CMP response header: %v", err)
	}
	return msg.Header.Pvno
}

func TestCMPRejectsOverLimitBody(t *testing.T) {
	srv := cmpsrv.New(cmpsrv.Config{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/cmp", bytes.NewReader(bytes.Repeat([]byte("x"), (1<<18)+1)))
	req.Header.Set("Content-Type", "application/pkixcmp")
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit CMP status %d, want 413", rec.Code)
	}
}

// TestCMPTamperedProtectionRejected: corrupting the protected message must fail closed —
// either the DER no longer parses or the protection signature no longer verifies.
func TestCMPTamperedProtectionRejected(t *testing.T) {
	ca := newRSACA(t)
	srv := cmpsrv.New(cmpsrv.Config{Enroller: realEnroller{ca: ca}, CACertDER: ca.certDER, CAKeyPKCS8: ca.keyPKCS8, ProfileName: "device"})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	clientCert, clientKey, csrDER := newClient(t)
	reqDER := buildRequest(t, clientCert, clientKey, csrDER)
	reqDER[len(reqDER)/3] ^= 0xff // corrupt a byte in the protected region

	resp, err := http.Post(ts.URL+"/cmp", "application/pkixcmp", bytes.NewReader(reqDER))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a tampered CMP message was accepted; protection not enforced")
	}
}
