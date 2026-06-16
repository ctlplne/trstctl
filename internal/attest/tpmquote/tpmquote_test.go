package tpmquote

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
)

// akCertChainedTo issues an AK certificate signed by the given manufacturer CA.
func akCertChainedTo(t *testing.T, caCertDER []byte, caKey crypto.DigestSigner, ak crypto.DigestSigner) []byte {
	t.Helper()
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "AK"}, ak)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := crypto.SignLeafFromCSR(caCertDER, caKey, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestTPMQuoteConforms(t *testing.T) {
	manu, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer manu.Destroy()
	manuCert, _ := crypto.SelfSignedCACert(manu, "TPM Manufacturer CA", time.Hour)
	ak, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer ak.Destroy()
	akCert := akCertChainedTo(t, manuCert, manu, ak)

	nonce := []byte("challenge-nonce-123")
	message := append([]byte("PCR0:abcd|nonce:"), nonce...)
	sig, err := crypto.SignMessage(ak, message)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := json.Marshal(Quote{AKCertDER: akCert, Message: message, Signature: sig, Nonce: nonce})

	badSig := append([]byte{}, sig...)
	badSig[len(badSig)-1] ^= 0xff
	forged, _ := json.Marshal(Quote{AKCertDER: akCert, Message: message, Signature: badSig, Nonce: nonce})

	a := &Attestor{ManufacturerRoots: [][]byte{manuCert}, ExpectedNonce: nonce}
	if err := attest.Conform(a, good, forged); err != nil {
		t.Fatalf("Conform: %v", err)
	}
}

func TestTPMQuoteRejectsUntrustedAKAndReplay(t *testing.T) {
	trusted, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer trusted.Destroy()
	trustedCert, _ := crypto.SelfSignedCACert(trusted, "Trusted CA", time.Hour)
	rogue, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer rogue.Destroy()
	rogueCert, _ := crypto.SelfSignedCACert(rogue, "Rogue CA", time.Hour)

	ak, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer ak.Destroy()
	nonce := []byte("n1")
	msg := append([]byte("q|"), nonce...)
	sig, _ := crypto.SignMessage(ak, msg)

	a := &Attestor{ManufacturerRoots: [][]byte{trustedCert}, ExpectedNonce: nonce}

	// AK endorsed only by the rogue CA -> untrusted.
	rogueAK := akCertChainedTo(t, rogueCert, rogue, ak)
	untrusted, _ := json.Marshal(Quote{AKCertDER: rogueAK, Message: msg, Signature: sig, Nonce: nonce})
	if _, err := a.Attest(context.Background(), untrusted); err == nil {
		t.Error("attested an AK from an untrusted manufacturer")
	}

	// Properly endorsed AK but a replayed quote with the wrong nonce.
	trustedAK := akCertChainedTo(t, trustedCert, trusted, ak)
	wrongNonce := []byte("different")
	msg2 := append([]byte("q|"), wrongNonce...)
	sig2, _ := crypto.SignMessage(ak, msg2)
	replay, _ := json.Marshal(Quote{AKCertDER: trustedAK, Message: msg2, Signature: sig2, Nonce: wrongNonce})
	if _, err := a.Attest(context.Background(), replay); err == nil {
		t.Error("accepted a quote whose nonce does not match the challenge (replay)")
	}
}
