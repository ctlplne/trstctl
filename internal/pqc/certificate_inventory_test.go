// SPDX-License-Identifier: BUSL-1.1
package pqc

import (
	"testing"
	"time"
	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestMLDSACertificateInventoryDistinguishesSubjectFromIssuer(t *testing.T) {
	ca, err := boundarycrypto.GenerateLockedKey(boundarycrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := boundarycrypto.SelfSignedCACert(ca, "inventory issuer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, algorithm := range []boundarycrypto.Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(string(algorithm), func(t *testing.T) {
			key, err := GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "inventory.example.test", DNSNames: []string{"inventory.example.test"}}, algorithm)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			preparation, err := boundarycrypto.NewLeafPreparation()
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := SignPQCLeafFromCSRWithPreparation(caDER, ca, key.CSRDER, 10*time.Minute, boundarycrypto.LeafProfile{ClampTTLToIssuer: true}, preparation)
			if err != nil {
				t.Fatal(err)
			}
			info, err := certinfo.Inspect(leaf.DER)
			if err != nil {
				t.Fatal(err)
			}
			if info.KeyAlgorithm != string(algorithm) || info.PublicKeyBits != 0 || info.SignatureAlgorithm != "ECDSA-SHA256" || info.SHA256Fingerprint != boundarycrypto.SHA256Hex(leaf.DER) {
				t.Fatalf("inventory conflates key, issuer or strength: %+v", info)
			}
			all, err := certinfo.InspectAll(leaf.DER)
			if err != nil || len(all) != 1 || all[0].KeyAlgorithm != info.KeyAlgorithm || all[0].SHA256Fingerprint != info.SHA256Fingerprint {
				t.Fatalf("bundle inspection disagrees: %+v %v", all, err)
			}
		})
	}
}
