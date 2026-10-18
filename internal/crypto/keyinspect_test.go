// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"runtime"
	"strings"
	"testing"
)

func TestInspectPrivateKeyReturnsPublicMetadataOnly(t *testing.T) {
	der, err := GeneratePKCS8(ECDSAP256)
	if err != nil {
		t.Fatalf("GeneratePKCS8: %v", err)
	}
	defer wipeTestBytes(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer wipeTestBytes(pemBytes)

	info, err := InspectPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("InspectPrivateKey: %v", err)
	}
	if info.Format != "PKCS8" || info.Algorithm != ECDSAP256 || info.Encrypted {
		t.Fatalf("private-key info = %+v, want unencrypted PKCS8 ECDSA-P256", info)
	}
	if info.FingerprintSHA256 == "" || info.FingerprintBasis != "public-spki-sha256" {
		t.Fatalf("private-key fingerprint metadata = %+v, want public-key-derived fingerprint", info)
	}
	for _, got := range []string{info.Format, string(info.Algorithm), info.FingerprintSHA256, info.FingerprintBasis} {
		if strings.Contains(got, "BEGIN PRIVATE KEY") || strings.Contains(got, "PRIVATE KEY-----") {
			t.Fatalf("private-key inspector exposed key bytes in metadata field %q", got)
		}
	}
}

func TestInspectPrivateKeyClassifiesEncryptedPEMWithoutPassphrase(t *testing.T) {
	info, err := InspectPrivateKey([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n"))
	if err != nil {
		t.Fatalf("InspectPrivateKey encrypted PEM: %v", err)
	}
	if !info.Encrypted || info.Format != "PKCS8-ENCRYPTED" || info.FingerprintSHA256 != "" {
		t.Fatalf("encrypted private-key info = %+v, want encrypted metadata without fingerprint", info)
	}
}

func TestInspectPrivateKeyPreservesWhitespaceValuedDERTail(t *testing.T) {
	// DER is binary. A valid PKCS#8 key may end in an octet that is ASCII
	// whitespace; stripping it corrupts the ASN.1 before the parser sees it.
	// Deterministic scalars avoid depending on a random key landing on that tail.
	curve := elliptic.P384()
	for scalar := int64(1); scalar <= 1024; scalar++ {
		d := big.NewInt(scalar)
		var scalarBytes [48]byte
		d.FillBytes(scalarBytes[:])
		ecdhKey, err := ecdh.P384().NewPrivateKey(scalarBytes[:])
		if err != nil {
			t.Fatalf("derive deterministic P-384 test key: %v", err)
		}
		point := ecdhKey.PublicKey().Bytes()
		x := new(big.Int).SetBytes(point[1:49])
		y := new(big.Int).SetBytes(point[49:97])
		key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal deterministic P-384 PKCS#8 key: %v", err)
		}
		tail := der[len(der)-1]
		if tail != ' ' && tail != '\n' && tail != '\r' && tail != '\t' {
			wipeTestBytes(der)
			d.SetInt64(0)
			continue
		}
		info, err := InspectPrivateKey(der)
		wipeTestBytes(der)
		d.SetInt64(0)
		if err != nil {
			t.Fatalf("valid PKCS#8 DER with whitespace-valued final byte was rejected: %v", err)
		}
		if info.Format != "PKCS8-DER" || info.Algorithm != ECDSAP384 || info.Encrypted {
			t.Fatalf("key classification = %+v, want unencrypted P-384 PKCS8-DER", info)
		}
		return
	}
	t.Fatal("could not construct a deterministic valid PKCS#8 DER with whitespace-valued final byte")
}

func wipeTestBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
