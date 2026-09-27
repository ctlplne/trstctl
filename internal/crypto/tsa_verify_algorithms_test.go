// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"math/big"
	"testing"
	"time"
)

// The stricter consumer must preserve every signing algorithm already accepted
// by signatureAlgFor, rather than qualifying only the P-256 fixture family.
func TestVerifyTimeStampTokenPreservesSupportedSignerAlgorithms(t *testing.T) {
	for _, algorithm := range []Algorithm{RSA2048, RSA3072, RSA4096, ECDSAP256, ECDSAP384, ECDSAP521} {
		t.Run(string(algorithm), func(t *testing.T) {
			root, err := GenerateLockedKey(ECDSAP256)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(root.Destroy)
			rootDER, err := SelfSignedCACert(root, "TSA algorithm compatibility root", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			key, err := GenerateLockedKey(algorithm)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(key.Destroy)
			csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "TSA algorithm compatibility"}, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := SignTimestampingCertFromCSR(rootDER, root, csr, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			params := TSTInfoParams{PolicyOID: "1.3.6.1.4.1.59551.2.1", HashedMessage: SHA256Sum([]byte("algorithm compatibility evidence")), SerialNumber: 739, GenTime: time.Now().UTC(), Nonce: big.NewInt(739)}
			content, err := EncodeTSTInfo(params)
			if err != nil {
				t.Fatal(err)
			}
			der, err := BuildTimeStampToken(content, cert, key)
			if err != nil {
				t.Fatalf("existing producer must accept %s: %v", algorithm, err)
			}
			if err := VerifyTimeStampToken(der, cert, params); err != nil {
				t.Fatalf("genuine %s artifact refused: %v", algorithm, err)
			}
			damaged := bytes.Clone(der)
			damaged[len(damaged)-1] ^= 1
			if err := VerifyTimeStampToken(damaged, cert, params); err == nil {
				t.Fatalf("damaged %s signature accepted", algorithm)
			}
		})
	}
}
