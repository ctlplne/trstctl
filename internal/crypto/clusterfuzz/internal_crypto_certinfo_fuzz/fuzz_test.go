// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

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
		// Round-trip invariant (TEST-FUZZASSERT-001): Inspect is a pure decode, so
		// re-inspecting the same bytes must be deterministic — same success/failure
		// and, on success, the same fingerprint. A parser whose result depends on
		// hidden state or reads past its input would break this.
		info2, err2 := certinfo.Inspect(raw)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("Inspect is non-deterministic: first err=%v, second err=%v", err, err2)
		}
		if err == nil && info.SHA256Fingerprint != info2.SHA256Fingerprint {
			t.Fatalf("Inspect fingerprint is non-deterministic: %q vs %q", info.SHA256Fingerprint, info2.SHA256Fingerprint)
		}
	})
}
