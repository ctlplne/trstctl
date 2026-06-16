package certinfo_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// FuzzInspect drives arbitrary bytes through the X.509 inventory parser (PEM
// unwrap → crypto/x509 → metadata extraction). Inspect runs on every certificate
// observed by discovery, CT monitoring, and the CBOM, so a hostile or truncated
// certificate must fail closed (an error), never panic. CLAUDE.md §6.
//
// This test lives inside the AN-3 crypto boundary (internal/crypto/certinfo), so
// it may use crypto/x509 directly to mint a valid seed certificate.
func FuzzInspect(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err == nil {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "seed"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     []string{"seed.example.com"},
		}
		if der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key); err == nil {
			f.Add(der) // a valid DER cert reaches the success path
		}
	}
	f.Add([]byte(""))
	f.Add([]byte("not a certificate"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")) // valid PEM frame, junk DER
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Must never panic. A successful parse must carry a fingerprint (the parser
		// rejects a certificate with no serial number, so a returned Info is whole).
		info, err := certinfo.Inspect(raw)
		if err == nil && info.SHA256Fingerprint == "" {
			t.Fatal("Inspect returned a nil error but an empty fingerprint")
		}
	})
}
