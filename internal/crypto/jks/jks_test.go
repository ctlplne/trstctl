package jks_test

import (
	"bytes"
	"encoding/pem"
	"testing"

	"trstctl.com/trstctl/internal/crypto/jks"
)

// A real ECDSA P-256 key (PKCS#8) and self-signed certificate.
const (
	keyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguSjwYXld9WA6+GXM
uiBvryiQ90RZx9HA7kPBwGKEmiihRANCAAT7FkWuZX/8pAX39mA+sX9aNoBwwLiF
tC/tbv9HKUb/KCNxLa7F0pZJwVIPsHXaVwTardDEh0MnPgh0j3ulaa0G
-----END PRIVATE KEY-----
`
	certPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUcx0QtLdtk6up3COWRwqCyBvODsYwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNa2V5c3RvcmUudGVzdDAeFw0yNjA1MzAxNTQwMjdaFw0zNjA1
MjcxNTQwMjdaMBgxFjAUBgNVBAMMDWtleXN0b3JlLnRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT7FkWuZX/8pAX39mA+sX9aNoBwwLiFtC/tbv9HKUb/KCNx
La7F0pZJwVIPsHXaVwTardDEh0MnPgh0j3ulaa0Go1MwUTAdBgNVHQ4EFgQUxCW/
Ky+OGKi2+qs6KAJc8H3T6cgwHwYDVR0jBBgwFoAUxCW/Ky+OGKi2+qs6KAJc8H3T
6cgwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAsEewyxjXXOdT
Z574YJ/lLHBNf0zuGD0O54dwWStiBj0CIDtTvKZum/bUwvzvfEkaP9M9LonMANo4
4fmuDJ38Fgsy
-----END CERTIFICATE-----
`
)

const alias = "server"

// A JKS keystore round-trips: it decodes back to the original key and
// certificate, under the configured alias and password.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	blob, err := jks.EncodeDeterministic([]byte(keyPEM), []byte(certPEM), "changeit", alias)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Sanity: a JKS file starts with the magic 0xFEEDFEED.
	if len(blob) < 4 || blob[0] != 0xFE || blob[1] != 0xED || blob[2] != 0xFE || blob[3] != 0xED {
		t.Fatalf("not a JKS file (bad magic): % x", blob[:min(4, len(blob))])
	}

	gotKey, gotCert, err := jks.Decode(blob, "changeit", alias)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(der(t, gotKey), der(t, []byte(keyPEM))) {
		t.Error("round-tripped key DER mismatch")
	}
	if !bytes.Equal(der(t, gotCert), der(t, []byte(certPEM))) {
		t.Error("round-tripped certificate DER mismatch")
	}
}

// Encoding is deterministic: the same credential always produces byte-identical
// output, which is what makes the keystore deployment idempotent.
func TestEncodeIsDeterministic(t *testing.T) {
	a, err := jks.EncodeDeterministic([]byte(keyPEM), []byte(certPEM), "changeit", alias)
	if err != nil {
		t.Fatal(err)
	}
	b, err := jks.EncodeDeterministic([]byte(keyPEM), []byte(certPEM), "changeit", alias)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("EncodeDeterministic must produce identical bytes for identical input")
	}
}

// The keystore is genuinely password-protected: the wrong store password fails
// to load.
func TestDecodeWrongPasswordFails(t *testing.T) {
	blob, err := jks.EncodeDeterministic([]byte(keyPEM), []byte(certPEM), "changeit", alias)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := jks.Decode(blob, "wrong", alias); err == nil {
		t.Error("decode with the wrong password must fail")
	}
}

func der(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}
