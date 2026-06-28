package crypto_test

import (
	"net"
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

func TestSignLeafWithProfileEmitsOnlyConfiguredEKUs(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl EKU Test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "svc.eku.test"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		AllowedExtKeyUsage: []string{"serverAuth"},
	})
	if err != nil {
		t.Fatalf("SignLeafFromCSRWithProfile: %v", err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.ExtKeyUsages) != 1 || info.ExtKeyUsages[0] != "serverAuth" {
		t.Fatalf("ExtKeyUsages = %v, want exactly [serverAuth]", info.ExtKeyUsages)
	}
}

func TestSignLeafWithClientAuthProfileOmitsKeyEncipherment(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl ClientAuth Test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:    "client.eku.test",
		DNSNames:      []string{"client.eku.test"},
		RequestedEKUs: []string{"clientAuth"},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		AllowedExtKeyUsage: []string{"clientAuth"},
	})
	if err != nil {
		t.Fatalf("SignLeafFromCSRWithProfile: %v", err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if !info.KeyUsageDigitalSig {
		t.Fatalf("clientAuth leaf must include digitalSignature")
	}
	if info.KeyUsageEncipher {
		t.Fatalf("clientAuth leaf must not include keyEncipherment")
	}
	if len(info.ExtKeyUsages) != 1 || info.ExtKeyUsages[0] != "clientAuth" {
		t.Fatalf("ExtKeyUsages = %v, want exactly [clientAuth]", info.ExtKeyUsages)
	}
}

func TestSignLeafWithProfileRejectsUnknownEKU(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl EKU Test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "svc.eku.test"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		AllowedExtKeyUsage: []string{"notAnEKU"},
	})
	if err == nil || !crypto.IsLeafProfileViolation(err) {
		t.Fatalf("SignLeafFromCSRWithProfile error = %v, want leaf profile violation", err)
	}
}

func TestSignLeafWithProfileRejectsSANTypeWithoutExplicitPolicy(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl SAN Test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:  "svc.example.com",
		DNSNames:    []string{"svc.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.10")},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		PermittedDNSSuffixes: []string{"example.com"},
	})
	if err == nil || !crypto.IsLeafProfileViolation(err) {
		t.Fatalf("SignLeafFromCSRWithProfile error = %v, want DNS-only profile to reject IP SAN", err)
	}
}

func TestSignLeafWithProfileAllowsExplicitSANPolicies(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "trstctl SAN Test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName:     "svc.example.com",
		DNSNames:       []string{"svc.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.10")},
		EmailAddresses: []string{"ops@example.com"},
		URIs:           []string{"spiffe://example.com/ns/prod/svc"},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csrDER, time.Hour, crypto.LeafProfile{
		PermittedDNSSuffixes:  []string{"example.com"},
		PermittedIPCIDRs:      []string{"10.0.0.0/24"},
		PermittedEmailDomains: []string{"example.com"},
		PermittedURIPrefixes:  []string{"spiffe://example.com/ns/prod/"},
	})
	if err != nil {
		t.Fatalf("SignLeafFromCSRWithProfile: %v", err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.IPAddresses) != 1 || info.IPAddresses[0] != "10.0.0.10" {
		t.Fatalf("IPAddresses = %v, want [10.0.0.10]", info.IPAddresses)
	}
	if len(info.EmailAddresses) != 1 || info.EmailAddresses[0] != "ops@example.com" {
		t.Fatalf("EmailAddresses = %v, want [ops@example.com]", info.EmailAddresses)
	}
	if len(info.URIs) != 1 || info.URIs[0] != "spiffe://example.com/ns/prod/svc" {
		t.Fatalf("URIs = %v, want [spiffe://example.com/ns/prod/svc]", info.URIs)
	}
}
