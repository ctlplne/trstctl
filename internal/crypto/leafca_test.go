package crypto_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// TestSignerBackedCAIssuesVerifiableLeaf is the AN-4 issuance primitive: a CA key
// that lives behind a DigestSigner (in production, the out-of-process signer)
// self-signs a CA certificate and then signs a leaf from a CSR, and the leaf
// verifies against that CA. No raw private key is handled here — only the
// DigestSigner boundary.
func TestSignerBackedCAIssuesVerifiableLeaf(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	defer caKey.Destroy()

	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}
	caInfo, err := certinfo.Inspect(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	if !caInfo.IsCA {
		t.Error("self-signed CA cert is not marked IsCA")
	}

	// A subscriber generates its own key and CSR.
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "svc.example.com",
		DNSNames:   []string{"svc.example.com"},
	}, leafKey)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}

	leafDER, err := crypto.SignLeafFromCSR(caDER, caKey, csrDER, time.Hour)
	if err != nil {
		t.Fatalf("SignLeafFromCSR: %v", err)
	}
	// The leaf must verify against the CA (it was signed by the CA's key).
	if err := crypto.VerifyLeafSignedByCA(leafDER, caDER); err != nil {
		t.Errorf("leaf does not verify against the CA: %v", err)
	}
	leafInfo, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if leafInfo.Subject == "" || leafInfo.Subject == caInfo.Subject {
		t.Errorf("leaf subject %q should be the subscriber, not the CA", leafInfo.Subject)
	}
}

// corruptSigner is a DigestSigner that advertises a real public key but returns a
// tampered signature — standing in for a compromised or malfunctioning signer.
type corruptSigner struct{ inner crypto.DigestSigner }

func (c corruptSigner) Public() crypto.PublicKey    { return c.inner.Public() }
func (c corruptSigner) Algorithm() crypto.Algorithm { return c.inner.Algorithm() }
func (c corruptSigner) SignDigest(d []byte, o crypto.SignOptions) ([]byte, error) {
	sig, err := c.inner.SignDigest(d, o)
	if err != nil {
		return nil, err
	}
	sig[len(sig)-1] ^= 0xff // corrupt the last byte
	return sig, nil
}

// TestSignLeafFailsClosedOnGarbageSignature: when the signing key returns a
// signature that does not verify, issuance must FAIL rather than emit an
// unverifiable certificate — the fail-closed guarantee the control plane relies
// on when the signer misbehaves.
func TestSignLeafFailsClosedOnGarbageSignature(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	// A genuine CA cert (real public key, valid self-signature).
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl Test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "svc"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	// Sign the leaf with a corrupt CA signer: the resulting signature will not
	// verify against the (real) CA public key in caDER.
	_, err = crypto.SignLeafFromCSR(caDER, corruptSigner{caKey}, csrDER, time.Hour)
	if err == nil {
		t.Fatal("SignLeafFromCSR returned a certificate despite a garbage signature; must fail closed")
	}
}
