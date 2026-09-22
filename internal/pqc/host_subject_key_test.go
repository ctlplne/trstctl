// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"bytes"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestHostMLDSASubjectKeyRetainsEveryRequestedIdentifierAndProof(t *testing.T) {
	for _, algorithm := range []boundarycrypto.Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(string(algorithm), func(t *testing.T) {
			template := boundarycrypto.CertificateRequestTemplate{
				CommonName: "api.example.test", DNSNames: []string{"api.example.test", "alt.example.test"},
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, EmailAddresses: []string{"operator@example.test"},
				URIs: []string{"spiffe://example.test/workload/api"}, RequestedEKUs: []string{"serverAuth"},
			}
			key, err := GenerateHostMLDSASubjectKey(template, algorithm)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			info, recognized, err := ParsePureMLDSACSR(key.CSRDER)
			if err != nil || !recognized || info.KeyAlgorithm != string(algorithm) {
				t.Fatalf("recognized=%v info=%+v err=%v", recognized, info, err)
			}
			if info.CommonName != template.CommonName || !reflect.DeepEqual(info.DNSNames, template.DNSNames) || !reflect.DeepEqual(info.IPAddresses, []string{"127.0.0.1"}) || !reflect.DeepEqual(info.EmailAddresses, template.EmailAddresses) || !reflect.DeepEqual(info.URIs, template.URIs) || !reflect.DeepEqual(info.RequestedEKUs, template.RequestedEKUs) {
				t.Fatalf("host generation changed requested identity/profile: %+v", info)
			}
			public, err := boundarycrypto.InspectOpaqueCSR(key.CSRDER)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(public.RawSubjectPublicKeyInfo, key.PublicKeyDER) {
				t.Fatal("CSR names a different key")
			}
			if len(public.PublicKeyAlgorithmParamsDER) != 0 || len(public.SignatureAlgorithmParamsDER) != 0 {
				t.Fatal("ML-DSA algorithm parameters must be absent")
			}
			tampered := append([]byte(nil), key.CSRDER...)
			tampered[len(tampered)-1] ^= 1
			if _, recognized, err := ParsePureMLDSACSR(tampered); !recognized || err == nil {
				t.Fatalf("tampered proof accepted: recognized=%v err=%v", recognized, err)
			}
		})
	}
}

func TestHostMLDSASubjectKeyExportsUsableKeyUntilDestroy(t *testing.T) {
	key, err := GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test"}, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	for i := 0; i < 2; i++ {
		material, err := key.PrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		block, rest := pem.Decode(material)
		if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
			t.Fatal("host key is not PKCS#8 PEM")
		}
		secret.Wipe(block.Bytes)
		secret.Wipe(material)
	}
	key.Destroy()
	key.Destroy()
	if len(key.CSRDER) != 0 {
		t.Fatal("destroy left request buffer retained")
	}
	if material, err := key.PrivateKeyPEM(); err == nil || len(material) != 0 {
		secret.Wipe(material)
		t.Fatal("destroyed host key remained exportable")
	}
}

func TestHostMLDSASubjectKeyRefusesAlgorithmSubstitution(t *testing.T) {
	for _, algorithm := range []boundarycrypto.Algorithm{"", boundarycrypto.ECDSAP256, "unknown"} {
		key, err := GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test"}, algorithm)
		if key != nil {
			key.Destroy()
		}
		if err == nil {
			t.Fatalf("unsupported %q silently substituted", algorithm)
		}
	}
	if key, err := GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{}, MLDSA65); err == nil {
		key.Destroy()
		t.Fatal("empty identity accepted")
	}
}

func TestHostMLDSASubjectKeyAndCSRInteroperateWithStockOpenSSL(t *testing.T) {
	openssl := requireOpenSSLMLDSA(t)
	key, err := GenerateHostMLDSASubjectKey(boundarycrypto.CertificateRequestTemplate{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}}, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	material, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(material)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "host-key.pem")
	csrPath := filepath.Join(dir, "host.csr")
	if err := os.WriteFile(keyPath, material, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(csrPath, key.CSRDER, 0600); err != nil {
		t.Fatal(err)
	}
	runOpenSSL(t, openssl, "req", "-inform", "DER", "-in", csrPath, "-noout", "-verify")
	csrPublic := runOpenSSL(t, openssl, "req", "-inform", "DER", "-in", csrPath, "-noout", "-pubkey")
	keyPublic := runOpenSSL(t, openssl, "pkey", "-in", keyPath, "-pubout")
	if !bytes.Equal(bytes.TrimSpace(csrPublic), bytes.TrimSpace(keyPublic)) {
		t.Fatal("OpenSSL derived different keys from retained private material and CSR")
	}
	runOpenSSL(t, openssl, "pkey", "-in", keyPath, "-check", "-noout")
}
