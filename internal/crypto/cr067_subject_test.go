// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestCR067LeafProfileCannotSignUnboundCSRSubject(t *testing.T) {
	rootKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer rootKey.Destroy()
	root, err := SelfSignedHierarchyCA(rootKey, HierarchyCAProfile{CommonName: "CR067 root", MaxPathLen: 0, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	requestKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer requestKey.Destroy()
	adapter, err := newX509Signer(requestKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "postgres", Organization: []string{"system:masters"},
			OrganizationalUnit: []string{"dba"}},
		DNSNames: []string{"svc.corp.example"},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	der, err := SignLeafFromCSRWithProfile(root.CertificateDER, rootKey, csr, time.Hour, LeafProfile{
		PermittedDNSSuffixes: []string{"corp.example"}, AllowedExtKeyUsage: []string{"clientAuth"},
	})
	if err != nil {
		if !IsLeafProfileViolation(err) {
			t.Fatalf("unbound subject was refused for another reason: %v", err)
		}
		return
	}
	leaf := mustParseCertificate(t, der)
	if leaf.Subject.CommonName == "postgres" || len(leaf.Subject.Organization) > 0 || len(leaf.Subject.OrganizationalUnit) > 0 {
		t.Fatalf("profile allowed svc.corp.example but signed requester subject %q", leaf.Subject.String())
	}
}

func TestCR067UnprofiledLeafNeverCopiesExtraSubjectRDNs(t *testing.T) {
	rootKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer rootKey.Destroy()
	root, err := SelfSignedCACert(rootKey, "CR067 library CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requestKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer requestKey.Destroy()
	adapter, err := newX509Signer(requestKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "svc.example.test", Organization: []string{"system:masters"}},
		DNSNames: []string{"svc.example.test"},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	der, err := SignLeafFromCSR(root, rootKey, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCertificate(t, der)
	if leaf.Subject.CommonName != "svc.example.test" || len(leaf.Subject.Organization) != 0 {
		t.Fatalf("unprofiled signer copied unreviewed subject: %q", leaf.Subject.String())
	}
}

func TestCR067SubjectCheckUsesSignedCNNotCallerMetadata(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "postgres", DNSNames: []string{"svc.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := InspectCSR(csr)
	if err != nil {
		t.Fatal(err)
	}
	info.CommonName = "svc.example.test"
	if err := info.CheckExternalProfileSubject(info.DNSNames); err == nil {
		t.Fatal("caller metadata hid a different signed common name")
	}
	emptyCSR, err := CreateCertificateRequest(CertificateRequestTemplate{DNSNames: []string{"svc.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := InspectCSR(emptyCSR)
	if err != nil {
		t.Fatal(err)
	}
	empty.CommonName = "svc.example.test"
	if err := empty.CheckExternalProfileSubject(empty.DNSNames); err == nil {
		t.Fatal("caller metadata turned an empty signed subject into a common name")
	}
}

func TestCR067OpaqueLeafChecksSignedSubjectBeforeSigning(t *testing.T) {
	rootKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer rootKey.Destroy()
	root, err := SelfSignedCACert(rootKey, "CR067 opaque CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requestKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer requestKey.Destroy()
	csrDER, err := CreateCertificateRequest(CertificateRequestTemplate{
		CommonName: "postgres", DNSNames: []string{"svc.example.test"}, Organization: []string{"system:masters"},
	}, requestKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	info, err := InspectCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingDigestSigner{DigestSigner: rootKey}
	_, err = SignOpaqueLeafFromVerifiedRequestWithProfile(root, counted, OpaqueLeafRequest{
		Info: info, RawSubject: csr.RawSubject, SubjectPublicKeyInfoDER: csr.RawSubjectPublicKeyInfo,
	}, time.Hour, LeafProfile{PermittedDNSSuffixes: []string{"example.test"}, AllowedExtKeyUsage: []string{"clientAuth"}})
	if !IsLeafProfileViolation(err) || counted.calls != 0 {
		t.Fatalf("opaque subject = %v, signer calls %d; want refusal before signing", err, counted.calls)
	}
	_, err = SignOpaqueLeafFromVerifiedRequestWithProfile(root, counted, OpaqueLeafRequest{
		Info:                    CSRInfo{CommonName: "svc.example.test", DNSNames: []string{"svc.example.test"}},
		SubjectPublicKeyInfoDER: csr.RawSubjectPublicKeyInfo,
	}, time.Hour, LeafProfile{PermittedDNSSuffixes: []string{"example.test"}})
	if !IsLeafProfileViolation(err) || counted.calls != 0 {
		t.Fatalf("metadata-only opaque subject = %v, signer calls %d; want refusal before signing", err, counted.calls)
	}
}

func TestCR067StrippedEmptySubjectMakesSANsCritical(t *testing.T) {
	rootKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer rootKey.Destroy()
	root, err := SelfSignedCACert(rootKey, "CR067 SAN CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requestKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer requestKey.Destroy()
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{
		Organization: []string{"system:masters"}, DNSNames: []string{"svc.example.test"},
		SmtpUTF8Mailboxes: []string{"renée@example.test"},
	}, requestKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := SignLeafFromCSR(root, rootKey, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCertificate(t, der)
	if len(leaf.RawSubject) != 2 || leaf.RawSubject[0] != 0x30 || leaf.RawSubject[1] != 0 {
		t.Fatalf("stripped subject is not empty: %q", leaf.Subject.String())
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.String() == "2.5.29.17" {
			if !ext.Critical {
				t.Fatal("empty-subject leaf has a noncritical SAN")
			}
			return
		}
	}
	t.Fatal("empty-subject leaf has no SAN")
}
