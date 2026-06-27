package crypto_test

import (
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func TestESTChannelBindingRoundTripAndFailures(t *testing.T) {
	serverCertDER := makeCert(t, "est-channel-binding-server")
	binding, err := crypto.TLSServerEndPoint(serverCertDER)
	if err != nil {
		t.Fatalf("TLSServerEndPoint: %v", err)
	}
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(signer.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:        "device-1",
		ESTChannelBinding: binding,
	}, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if err := crypto.VerifyESTChannelBinding(csrDER, serverCertDER, true); err != nil {
		t.Fatalf("VerifyESTChannelBinding matching: %v", err)
	}

	wrongCertDER := makeCert(t, "other-est-server")
	if err := crypto.VerifyESTChannelBinding(csrDER, wrongCertDER, true); !errors.Is(err, crypto.ErrESTChannelBindingMismatch) {
		t.Fatalf("VerifyESTChannelBinding mismatch = %v, want ErrESTChannelBindingMismatch", err)
	}
	plainCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "device-1"}, signer)
	if err != nil {
		t.Fatalf("plain CreateCertificateRequest: %v", err)
	}
	if err := crypto.VerifyESTChannelBinding(plainCSR, serverCertDER, true); !errors.Is(err, crypto.ErrESTChannelBindingMissing) {
		t.Fatalf("VerifyESTChannelBinding missing = %v, want ErrESTChannelBindingMissing", err)
	}
	if err := crypto.VerifyESTChannelBinding(plainCSR, serverCertDER, false); err != nil {
		t.Fatalf("optional absent channel binding should pass: %v", err)
	}
}

func TestTLSServerEndPointRejectsInvalidCertificate(t *testing.T) {
	if _, err := crypto.TLSServerEndPoint([]byte{0x30, 0x00}); err == nil {
		t.Fatal("TLSServerEndPoint accepted an invalid certificate")
	}
}

func TestESTChannelBindingRejectsWrongLength(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(signer.Destroy)
	_, err = crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:        "device-1",
		ESTChannelBinding: []byte{0x01, 0x02, 0x03},
	}, signer)
	if err == nil {
		t.Fatal("CreateCertificateRequest accepted a wrong-length EST channel binding")
	}
}

func TestTLSServerEndPointIsStableForSameCertificate(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(signer.Destroy)
	certDER, err := crypto.SelfSignedCACert(signer, "stable-est-binding", time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}
	first, err := crypto.TLSServerEndPoint(certDER)
	if err != nil {
		t.Fatalf("first TLSServerEndPoint: %v", err)
	}
	second, err := crypto.TLSServerEndPoint(certDER)
	if err != nil {
		t.Fatalf("second TLSServerEndPoint: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("tls-server-end-point binding changed for the same certificate")
	}
}
