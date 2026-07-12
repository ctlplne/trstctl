// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestCrossSignHierarchyCARetainsNarrowedPublicContract(t *testing.T) {
	issuerSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuerSigner.Destroy)
	targetSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(targetSigner.Destroy)
	issuer, err := SelfSignedHierarchyCA(issuerSigner, HierarchyCAProfile{
		CommonName: "Cross Issuer", PermittedDNSDomains: []string{"example.test"},
		MaxPathLen: 1, EKUs: []string{"serverAuth", "clientAuth"}, TTL: 48 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := PublicKeyDERFromCert(issuer.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(publicDER, issuerSigner.Public().DER) {
		t.Fatal("certificate public-key bootstrap did not recover the signer public key")
	}
	if err := VerifyCertificateSigner(issuer.CertificateDER, targetSigner.Public()); err == nil {
		t.Fatal("certificate was accepted with an unrelated persisted signer public key")
	}
	target, err := SelfSignedHierarchyCA(targetSigner, HierarchyCAProfile{
		CommonName: "Cross Target", PermittedDNSDomains: []string{"svc.example.test"},
		MaxPathLen: 0, EKUs: []string{"serverAuth"}, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cross, err := CrossSignHierarchyCA(issuer.CertificateDER, issuerSigner, target.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCrossSignedCA(issuer.CertificateDER, target.CertificateDER, cross.CertificateDER); err != nil {
		t.Fatalf("valid cross-certificate: %v", err)
	}

	issuerCert, _ := x509.ParseCertificate(issuer.CertificateDER)
	targetCert, _ := x509.ParseCertificate(target.CertificateDER)
	good, _ := x509.ParseCertificate(cross.CertificateDER)
	tests := map[string]func(*x509.Certificate){
		"outlives issuer":  func(cert *x509.Certificate) { cert.NotAfter = issuerCert.NotAfter.Add(time.Hour) },
		"predates target":  func(cert *x509.Certificate) { cert.NotBefore = targetCert.NotBefore.Add(-time.Hour) },
		"widens key usage": func(cert *x509.Certificate) { cert.KeyUsage |= x509.KeyUsageDigitalSignature },
		"widens EKU": func(cert *x509.Certificate) {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		},
		"widens DNS":         func(cert *x509.Certificate) { cert.PermittedDNSDomains = []string{"example.test"} },
		"widens path length": func(cert *x509.Certificate) { cert.MaxPathLen, cert.MaxPathLenZero = 1, false },
		"wrong SKI":          func(cert *x509.Certificate) { cert.SubjectKeyId = []byte{0xde, 0xad, 0xbe, 0xef} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := *good
			candidate.SerialNumber = new(big.Int).Add(good.SerialNumber, big.NewInt(100))
			candidate.PermittedDNSDomains = append([]string(nil), good.PermittedDNSDomains...)
			candidate.ExtKeyUsage = append([]x509.ExtKeyUsage(nil), good.ExtKeyUsage...)
			candidate.SubjectKeyId = append([]byte(nil), good.SubjectKeyId...)
			candidate.AuthorityKeyId = append([]byte(nil), good.AuthorityKeyId...)
			mutate(&candidate)
			adapter, err := newX509Signer(issuerSigner)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.CreateCertificate(rand.Reader, &candidate, issuerCert, targetCert.PublicKey, adapter)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyCrossSignedCA(issuer.CertificateDER, target.CertificateDER, der); err == nil {
				t.Fatal("adversarial cross-certificate passed verification")
			}
		})
	}
	t.Run("wrong AKI", func(t *testing.T) {
		candidate := *good
		candidate.SerialNumber = new(big.Int).Add(good.SerialNumber, big.NewInt(200))
		fakeParent := *issuerCert
		fakeParent.SubjectKeyId = []byte{0xca, 0xfe, 0xba, 0xbe}
		adapter, err := newX509Signer(issuerSigner)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificate(rand.Reader, &candidate, &fakeParent, targetCert.PublicKey, adapter)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCrossSignedCA(issuer.CertificateDER, target.CertificateDER, der); err == nil {
			t.Fatal("cross-certificate with wrong authority key identifier passed verification")
		}
	})
}

func TestCrossSignHierarchyCAPreservesExternalRawSubjectEncoding(t *testing.T) {
	issuerSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuerSigner.Destroy)
	targetSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(targetSigner.Destroy)
	issuer, err := SelfSignedHierarchyCA(issuerSigner, HierarchyCAProfile{CommonName: "Issuer", MaxPathLen: 1, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	rawSubject, err := asn1.Marshal(pkix.RDNSequence{{{
		Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
		Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("External Interop Target")},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	public, err := parsePKIXPublicKey(targetSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	ski, err := subjectKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := newX509Signer(targetSigner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(9001), Subject: pkix.Name{CommonName: "External Interop Target"}, RawSubject: rawSubject,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
		MaxPathLen: 0, MaxPathLenZero: true, SubjectKeyId: ski,
	}
	targetDER, err := x509.CreateCertificate(rand.Reader, template, template, public, adapter)
	if err != nil {
		t.Fatal(err)
	}
	target, err := x509.ParseCertificate(targetDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(target.RawSubject, rawSubject) {
		t.Fatal("fixture did not preserve its explicit external subject encoding")
	}
	cross, err := CrossSignHierarchyCA(issuer.CertificateDER, issuerSigner, targetDER)
	if err != nil {
		t.Fatal(err)
	}
	crossCert, err := x509.ParseCertificate(cross.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(crossCert.RawSubject, target.RawSubject) {
		t.Fatal("cross-certificate re-encoded the externally supplied subject")
	}
}

func TestCrossSignHierarchyCARejectsUnusableIssuerLanes(t *testing.T) {
	issuerSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuerSigner.Destroy)
	targetSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(targetSigner.Destroy)
	target, err := SelfSignedHierarchyCA(targetSigner, HierarchyCAProfile{
		CommonName: "Target", PermittedDNSDomains: []string{"target.example"}, MaxPathLen: 0, TTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("exhausted issuer path length", func(t *testing.T) {
		issuer, err := SelfSignedHierarchyCA(issuerSigner, HierarchyCAProfile{
			CommonName: "Exhausted Issuer", MaxPathLen: 0, TTL: 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CrossSignHierarchyCA(issuer.CertificateDER, issuerSigner, target.CertificateDER); err == nil {
			t.Fatal("pathLen=0 issuer cross-signed another CA")
		}
	})
	t.Run("disjoint DNS constraints", func(t *testing.T) {
		issuer, err := SelfSignedHierarchyCA(issuerSigner, HierarchyCAProfile{
			CommonName: "Disjoint Issuer", PermittedDNSDomains: []string{"issuer.example"}, MaxPathLen: 1, TTL: 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CrossSignHierarchyCA(issuer.CertificateDER, issuerSigner, target.CertificateDER); err == nil {
			t.Fatal("disjoint DNS lanes produced an unconstrained cross-certificate")
		}
	})
}
