// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"encoding/pem"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const x509PropertySeed int64 = 81005

type x509PropertyInput struct {
	CommonName string
	DNSNames   []string
	EKU        string
}

func (x509PropertyInput) Generate(r *rand.Rand, size int) reflect.Value {
	count := 1 + r.Intn(1+minX509Property(size, 4))
	dnsNames := make([]string, count)
	for i := range dnsNames {
		dnsNames[i] = "svc-" + x509PropertyToken(r, 1+r.Intn(12)) + ".example.test"
	}
	eku := "serverAuth"
	if r.Intn(2) == 1 {
		eku = "clientAuth"
	}
	return reflect.ValueOf(x509PropertyInput{
		CommonName: "subject-" + x509PropertyToken(r, 1+minX509Property(size, 24)),
		DNSNames:   dnsNames,
		EKU:        eku,
	})
}

// TestPropertyX509CSRAndCertificateCanonicalization generates signed PKCS#10
// requests and profiled X.509 leaves. The signed request fields must be exact,
// and DER versus PEM encodings must normalize to identical public metadata and
// canonical leaf DER.
func TestPropertyX509CSRAndCertificateCanonicalization(t *testing.T) {
	caSigner, err := trstcrypto.GenerateLockedKey(trstcrypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate X.509 property CA key: %v", err)
	}
	t.Cleanup(caSigner.Destroy)
	leafSigner, err := trstcrypto.GenerateLockedKey(trstcrypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate X.509 property leaf key: %v", err)
	}
	t.Cleanup(leafSigner.Destroy)
	caDER, err := trstcrypto.SelfSignedCACert(caSigner, "X.509 property CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("create X.509 property CA: %v", err)
	}

	prop := func(g x509PropertyInput) bool {
		csrDER, err := trstcrypto.CreateCertificateRequest(trstcrypto.CertificateRequestTemplate{
			CommonName:    g.CommonName,
			DNSNames:      g.DNSNames,
			RequestedEKUs: []string{g.EKU},
		}, leafSigner)
		if err != nil {
			t.Logf("create generated X.509 CSR: %v", err)
			return false
		}
		csrInfo, err := trstcrypto.InspectCSR(csrDER)
		if err != nil {
			t.Logf("inspect generated X.509 CSR: %v", err)
			return false
		}
		if csrInfo.CommonName != g.CommonName || !reflect.DeepEqual(csrInfo.DNSNames, g.DNSNames) || !reflect.DeepEqual(csrInfo.RequestedEKUs, []string{g.EKU}) || csrInfo.KeyAlgorithm != "ECDSA" || csrInfo.KeyBits != 256 {
			t.Logf("generated X.509 CSR changed: got=%+v want=%+v", csrInfo, g)
			return false
		}

		profile := trstcrypto.LeafProfile{
			CRLDistributionPoints: []string{"https://pki.example.test/root.crl"},
			OCSPServers:           []string{"https://ocsp.example.test"},
			IssuingCertificateURL: []string{"https://pki.example.test/root.der"},
			CertificatePolicyOIDs: []string{"1.3.6.1.4.1.55555.81"},
			MaxValidity:           2 * time.Hour,
			AllowedExtKeyUsage:    []string{g.EKU},
			PermittedDNSSuffixes:  []string{"example.test"},
		}
		leafDER, err := trstcrypto.SignLeafFromCSRWithProfile(caDER, caSigner, csrDER, time.Hour, profile)
		if err != nil {
			t.Logf("sign generated profiled leaf: %v", err)
			return false
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		derInfo, err := certinfo.Inspect(leafDER)
		if err != nil {
			t.Logf("inspect generated leaf DER: %v", err)
			return false
		}
		pemInfo, err := certinfo.Inspect(leafPEM)
		if err != nil {
			t.Logf("inspect generated leaf PEM: %v", err)
			return false
		}
		canonicalDER, err := certinfo.LeafDER(leafPEM)
		if err != nil {
			t.Logf("canonicalize generated leaf PEM: %v", err)
			return false
		}
		if !reflect.DeepEqual(derInfo, pemInfo) || !bytes.Equal(canonicalDER, leafDER) {
			t.Logf("DER/PEM X.509 normalization drift: der=%+v pem=%+v canonical_equal=%t", derInfo, pemInfo, bytes.Equal(canonicalDER, leafDER))
			return false
		}
		if derInfo.IsCA || !reflect.DeepEqual(derInfo.DNSNames, g.DNSNames) || !reflect.DeepEqual(derInfo.ExtKeyUsages, []string{g.EKU}) || !reflect.DeepEqual(derInfo.CRLDistributionPoints, profile.CRLDistributionPoints) || !reflect.DeepEqual(derInfo.OCSPServers, profile.OCSPServers) || !reflect.DeepEqual(derInfo.IssuingCertificateURL, profile.IssuingCertificateURL) || !reflect.DeepEqual(derInfo.PolicyOIDs, profile.CertificatePolicyOIDs) || derInfo.SubjectKeyID == "" {
			t.Logf("generated leaf profile changed: info=%+v generated=%+v", derInfo, g)
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{
		MaxCount: 128,
		Rand:     rand.New(rand.NewSource(x509PropertySeed)), // #nosec G404 -- deterministic property-test stream, not security randomness (CWE-338)
	}); err != nil {
		t.Fatalf("X.509 CSR/certificate canonicalization property violated: %v", err)
	}
}

// TestPropertyX509RejectsSignatureAndExtensionViolations proves two separate
// trust boundaries fail closed: changing one signed CSR byte invalidates it,
// and a correctly signed but out-of-profile DNS SAN is never issued.
func TestPropertyX509RejectsSignatureAndExtensionViolations(t *testing.T) {
	caSigner, err := trstcrypto.GenerateLockedKey(trstcrypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate X.509 rejection-property CA key: %v", err)
	}
	t.Cleanup(caSigner.Destroy)
	leafSigner, err := trstcrypto.GenerateLockedKey(trstcrypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate X.509 rejection-property leaf key: %v", err)
	}
	t.Cleanup(leafSigner.Destroy)
	caDER, err := trstcrypto.SelfSignedCACert(caSigner, "X.509 rejection property CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("create X.509 rejection-property CA: %v", err)
	}

	prop := func(g x509PropertyInput) bool {
		csrDER, err := trstcrypto.CreateCertificateRequest(trstcrypto.CertificateRequestTemplate{
			CommonName: g.CommonName,
			DNSNames:   g.DNSNames,
		}, leafSigner)
		if err != nil {
			t.Logf("create generated X.509 CSR: %v", err)
			return false
		}
		corruptCSR := bytes.Clone(csrDER)
		corruptCSR[len(corruptCSR)-1] ^= 0x01
		if err := trstcrypto.VerifyCertificateRequest(corruptCSR); err == nil {
			t.Logf("signature-corrupted CSR verified: common_name=%q", g.CommonName)
			return false
		}
		if info, err := trstcrypto.InspectCSR(corruptCSR); err == nil || !reflect.DeepEqual(info, trstcrypto.CSRInfo{}) {
			t.Logf("signature-corrupted CSR returned usable state: info=%+v err=%v", info, err)
			return false
		}
		if leaf, err := trstcrypto.SignLeafFromCSR(caDER, caSigner, corruptCSR, time.Hour); err == nil || len(leaf) != 0 {
			t.Logf("signature-corrupted CSR was issued: leaf_len=%d err=%v", len(leaf), err)
			return false
		}

		outsideDNS := "svc-" + x509PropertyToken(rand.New(rand.NewSource(int64(len(g.CommonName))+x509PropertySeed)), 12) + ".outside.invalid" // #nosec G404 -- deterministic property-test name, not security randomness (CWE-338)
		outsideCSR, err := trstcrypto.CreateCertificateRequest(trstcrypto.CertificateRequestTemplate{
			CommonName: outsideDNS,
			DNSNames:   []string{outsideDNS},
		}, leafSigner)
		if err != nil {
			t.Logf("create generated out-of-profile CSR: %v", err)
			return false
		}
		leaf, err := trstcrypto.SignLeafFromCSRWithProfile(caDER, caSigner, outsideCSR, time.Hour, trstcrypto.LeafProfile{
			PermittedDNSSuffixes: []string{"example.test"},
		})
		if err == nil || !trstcrypto.IsLeafProfileViolation(err) || len(leaf) != 0 {
			t.Logf("out-of-profile DNS SAN was issued: dns=%q leaf_len=%d err=%v", outsideDNS, len(leaf), err)
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{
		MaxCount: 128,
		Rand:     rand.New(rand.NewSource(x509PropertySeed + 1)), // #nosec G404 -- deterministic property-test stream, not security randomness (CWE-338)
	}); err != nil {
		t.Fatalf("X.509 signature/extension rejection property violated: %v", err)
	}
}

func x509PropertyToken(r *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func minX509Property(a, b int) int {
	if a < b {
		return a
	}
	return b
}
