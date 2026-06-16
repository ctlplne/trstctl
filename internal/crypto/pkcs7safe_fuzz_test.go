package crypto_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// scepCrasherFUZZ001 is the minimised input that reproduced FUZZ-001: a 2-byte
// CMS — 0x30 0x84 — a DER SEQUENCE whose long-form length octet (0x84) claims
// four length bytes follow, none of which are present. The smallstep/pkcs7 BER
// decoder (ber.go readObject) indexes out of range on it and panics with
// "index out of range [2] with length 2". After the safeParsePKCS7 guard every
// trstctl CMS boundary must return a clean error on this input, never panic.
var scepCrasherFUZZ001 = []byte{0x30, 0x84}

// TestPKCS7BoundaryRecoversFUZZ001Crasher is the FUZZ-001 regression test. It
// drives the original crashing input through EVERY untrusted CMS/PKCS7 parse
// boundary in the crypto package and asserts each returns an error and does not
// panic. It FAILS on the pre-fix tree (the calls panic) and PASSES after the
// safeParsePKCS7 guard is in place.
func TestPKCS7BoundaryRecoversFUZZ001Crasher(t *testing.T) {
	// Realistic recipient material so the parsers reach the decoder rather than
	// failing earlier on a nil key/cert. The crasher panics inside Parse, before
	// any of this is consulted, so it is belt-and-braces.
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	certDER, err := crypto.SelfSignedCACert(signer, "fuzz boundary", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPKCS8, err := signer.PKCS8()
	if err != nil {
		t.Fatal(err)
	}

	// A second valid CMS root for the VerifyCMSSignature path so it gets past the
	// "no trusted roots" guard and actually reaches the decoder.
	_, rootDER, err := crypto.SignCMS([]byte("seed"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		call func() error
	}{
		{"ParseSCEPRequest", func() error {
			_, err := crypto.ParseSCEPRequest(scepCrasherFUZZ001, certDER, keyPKCS8)
			return err
		}},
		{"ParseSCEPResponse", func() error {
			_, err := crypto.ParseSCEPResponse(scepCrasherFUZZ001, certDER, keyPKCS8)
			return err
		}},
		{"VerifyCMSSignature", func() error {
			_, err := crypto.VerifyCMSSignature(scepCrasherFUZZ001, [][]byte{rootDER})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s PANICKED on the FUZZ-001 crasher 0x30 0x84: %v", tc.name, r)
				}
			}()
			if err := tc.call(); err == nil {
				t.Fatalf("%s returned nil error on the FUZZ-001 crasher; want a clean error", tc.name)
			}
		})
	}
}

// FuzzParseSCEPResponse hardens the SCEP CertRep parser (ParseSCEPResponse,
// scep.go:202) — an untrusted-input decoder (CLAUDE.md §6) that shares the
// smallstep/pkcs7 BER decoder proven to panic in FUZZ-001. It is seeded with the
// original crasher (0x30 0x84) plus truncated/garbage DER; no input may panic the
// parser — it must always return cleanly (bytes or an error), never both, never a
// crash. This target FAILS on the pre-fix tree (panics on the seed) and PASSES
// after the safeParsePKCS7 guard.
func FuzzParseSCEPResponse(f *testing.F) {
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		f.Fatal(err)
	}
	defer signer.Destroy()
	certDER, err := crypto.SelfSignedCACert(signer, "fuzz recipient", time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	keyPKCS8, err := signer.PKCS8()
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add(scepCrasherFUZZ001)                   // the FUZZ-001 crasher
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00}) // minimal DER SEQUENCE
	f.Add([]byte{0x30, 0x84, 0x00, 0x00, 0x00}) // long-form length, truncated body
	f.Add([]byte("not der at all"))

	f.Fuzz(func(t *testing.T, reply []byte) {
		out, err := crypto.ParseSCEPResponse(reply, certDER, keyPKCS8)
		if err == nil && out == nil {
			t.Fatal("ParseSCEPResponse returned nil cert and nil error")
		}
	})
}

// FuzzVerifyCMSSignature hardens the cloud instance-identity CMS verifier
// (VerifyCMSSignature, verify.go:71) — reached pre-verification by the AWS/Azure
// node attesters on a caller-supplied document, sharing the FUZZ-001 decoder. It
// is seeded with a valid IID-shaped CMS and the crasher; no input may panic. This
// is the FUZZ-002 denominator fix for the proven-vulnerable decoder.
func FuzzVerifyCMSSignature(f *testing.F) {
	// A valid CMS + its signer cert (used as the trust root) so the corpus
	// includes a well-formed message, not only garbage.
	validP7, rootDER, err := crypto.SignCMS([]byte("instance-identity-document"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil), rootDER)
	f.Add(scepCrasherFUZZ001, rootDER) // the FUZZ-001 crasher
	f.Add(validP7, rootDER)            // a well-formed CMS
	f.Add([]byte{0x30, 0x84}, []byte(nil))
	f.Add([]byte("garbage"), rootDER)

	f.Fuzz(func(t *testing.T, p7DER, root []byte) {
		var roots [][]byte
		if len(root) > 0 {
			roots = [][]byte{root}
		}
		// We only assert the absence of a panic; an error (or nil content with a
		// nil error on a validly-signed-but-untrusted doc) are both acceptable.
		_, _ = crypto.VerifyCMSSignature(p7DER, roots)
	})
}
