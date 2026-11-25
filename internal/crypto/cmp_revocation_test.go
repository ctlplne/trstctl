// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"testing"
	"time"
)

func cmpCRLFixture(t testing.TB) (chain [][]byte, caDER []byte, caKey *LockedSigner, serial string) {
	t.Helper()
	var err error
	caKey, err = GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err = SelfSignedCACert(caKey, "CMP external issuer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deviceKey.Destroy)
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "cmp-device"}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := SignLeafFromCSR(caDER, caKey, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{leafDER, caDER}, caDER, caKey, leaf.SerialNumber.Text(16)
}

func TestCR057CMPExternalCRLRejectsWrongSignerAndMissingCoverage(t *testing.T) {
	chain, caDER, caKey, _ := cmpCRLFixture(t)
	now := time.Now().UTC()
	good, err := CreateCRL(caDER, caKey, nil, 1, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCMPProtectionCRLs(chain, [][]byte{good}, now); err != nil {
		t.Fatalf("good issuer CRL refused: %v", err)
	}
	if err := VerifyCMPProtectionCRLs(chain, nil, now); err == nil {
		t.Fatal("missing issuer CRL accepted")
	}
	wrongKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wrongKey.Destroy)
	wrongCA, err := SelfSignedCACert(wrongKey, "CMP external issuer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wrongCRL, err := CreateCRL(wrongCA, wrongKey, nil, 1, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCMPProtectionCRLs(chain, [][]byte{wrongCRL}, now); err == nil {
		t.Fatal("same-name CRL signed by a different key accepted")
	}
	if err := VerifyCMPProtectionCRLs(chain[:1], nil, now); err != nil {
		t.Fatalf("directly pinned identity needs no issuer CRL: %v", err)
	}
}

func FuzzVerifyCMPProtectionCRLs(f *testing.F) {
	chain, _, _, _ := cmpCRLFixture(f)
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte("not a CRL"))
	now := time.Now().UTC()
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2<<20 {
			return
		}
		_ = VerifyCMPProtectionCRLs(chain, [][]byte{raw}, now)
	})
}
