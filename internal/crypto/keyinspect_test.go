// SPDX-License-Identifier: MPL-2.0

package crypto

import (
	"encoding/pem"
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

func wipeTestBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
