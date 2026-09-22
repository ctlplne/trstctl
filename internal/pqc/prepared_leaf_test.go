// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"bytes"
	"encoding/pem"
	"testing"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestPreparedPQCLeafPreservesPureAndHybridProofs(t *testing.T) {
	ca, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := boundarycrypto.SelfSignedCACert(ca, "prepared PQC CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"pure", "hybrid"} {
		t.Run(mode, func(t *testing.T) {
			var request []byte
			if mode == "pure" {
				key, err := GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}, MLDSA65)
				if err != nil {
					t.Fatal(err)
				}
				defer key.Destroy()
				request = key.CSRDER
			} else {
				classical, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
				if err != nil {
					t.Fatal(err)
				}
				defer classical.Destroy()
				pqc, err := GenerateKey(MLDSA44)
				if err != nil {
					t.Fatal(err)
				}
				defer pqc.Destroy()
				ext, err := HybridLeafCSRExtraExtension(classical.Public(), pqc)
				if err != nil {
					t.Fatal(err)
				}
				request, err = boundarycrypto.CreateCertificateRequest(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}, ExtraExtensions: []boundarycrypto.CertificateExtension{ext}}, classical)
				if err != nil {
					t.Fatal(err)
				}
				bad := ext
				bad.Value = append([]byte(nil), ext.Value...)
				bad.Value[len(bad.Value)-1] ^= 1
				badCSR, err := boundarycrypto.CreateCertificateRequest(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test", ExtraExtensions: []boundarycrypto.CertificateExtension{bad}}, classical)
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := boundarycrypto.NewLeafPreparation()
				if err != nil {
					t.Fatal(err)
				}
				if leaf, err := SignPQCLeafFromCSRWithPreparation(caDER, ca, badCSR, time.Minute, boundarycrypto.LeafProfile{}, prepared); err == nil || len(leaf.DER) != 0 {
					t.Fatal("valid classical CSR bypassed its invalid PQC proof")
				}
			}
			prepared, err := boundarycrypto.NewLeafPreparation()
			if err != nil {
				t.Fatal(err)
			}
			prepared.ValidityAnchor = prepared.ValidityAnchor.Add(-time.Minute)
			first, err := SignPQCLeafFromCSRWithPreparation(caDER, ca, request, 5*time.Minute, boundarycrypto.LeafProfile{ClampTTLToIssuer: true}, prepared)
			if err != nil {
				t.Fatal(err)
			}
			second, err := SignPQCLeafFromCSRWithPreparation(caDER, ca, request, 5*time.Minute, boundarycrypto.LeafProfile{ClampTTLToIssuer: true}, prepared)
			if err != nil {
				t.Fatal(err)
			}
			one, err := certinfo.Inspect(first.DER)
			if err != nil {
				t.Fatal(err)
			}
			two, err := certinfo.Inspect(second.DER)
			if err != nil {
				t.Fatal(err)
			}
			if one.SerialNumber != two.SerialNumber || !one.NotBefore.Equal(two.NotBefore) || !one.NotAfter.Equal(two.NotAfter) || !first.ValidityAnchor.Equal(prepared.ValidityAnchor) || !second.ValidityAnchor.Equal(prepared.ValidityAnchor) {
				t.Fatal("prepared PQC retry changed serial or validity")
			}
			if err := boundarycrypto.VerifyLeafSignedByCA(first.DER, caDER); err != nil {
				t.Fatal(err)
			}
			if mode == "hybrid" {
				if err := VerifyHybridLeaf(first.DER); err != nil {
					t.Fatal(err)
				}
			}
			tampered := append([]byte(nil), request...)
			tampered[len(tampered)-1] ^= 1
			if leaf, err := SignPQCLeafFromCSRWithPreparation(caDER, ca, tampered, time.Minute, boundarycrypto.LeafProfile{}, prepared); err == nil || len(leaf.DER) != 0 {
				t.Fatal("invalid subject signature accepted")
			}
		})
	}
}

func TestPreparedPQCLeafRetainsPureSubjectForStockOpenSSL(t *testing.T) {
	openssl := requireOpenSSLMLDSA(t)
	ca, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := boundarycrypto.SelfSignedCACert(ca, "prepared PQC CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	prepared, err := boundarycrypto.NewLeafPreparation()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := SignPQCLeafFromCSRWithPreparation(caDER, ca, key.CSRDER, 10*time.Minute, boundarycrypto.LeafProfile{ClampTTLToIssuer: true}, prepared)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.DER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certificatePath, caPath := writePreparedPQCLeafFixtures(t, leafPEM, caPEM)
	text := runOpenSSL(t, openssl, "x509", "-in", certificatePath, "-noout", "-text")
	if !bytes.Contains(text, []byte("ML-DSA-65")) {
		t.Fatal("OpenSSL did not see the requested pure subject key")
	}
	runOpenSSL(t, openssl, "verify", "-CAfile", caPath, "-verify_hostname", "api.example.test", certificatePath)
	checkPreparedPQCTLS(t, openssl, key, certificatePath, caPath)
}
