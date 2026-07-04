package crypto_test

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzParseCMPRequest hardens the CMP PKIMessage parser (an untrusted-input parser per
// CLAUDE.md §6): no input may crash it; it must always return cleanly (a request or an
// error), never both, and never panic.
func FuzzParseCMPRequest(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte("not a CMP message"))
	valid := cmpFuzzRequestSeed(f)
	f.Add(valid)
	f.Add(append(append([]byte(nil), valid...), 0))

	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := crypto.ParseCMPRequest(data)
		if err == nil && req == nil {
			t.Fatal("ParseCMPRequest returned nil request and nil error")
		}
		if err == nil && len(data) > len(valid) && bytes.HasPrefix(data, valid) {
			t.Fatal("ParseCMPRequest accepted trailing bytes after a valid PKIMessage")
		}
	})
}

func cmpFuzzRequestSeed(f *testing.F) []byte {
	f.Helper()

	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatalf("generate CMP fuzz key: %v", err)
	}
	f.Cleanup(signer.Destroy)
	certDER, err := crypto.SelfSignedCACert(signer, "cmp-fuzz-client", time.Hour)
	if err != nil {
		f.Fatalf("build CMP fuzz cert: %v", err)
	}
	keyPKCS8, err := signer.PKCS8()
	if err != nil {
		f.Fatalf("export CMP fuzz key: %v", err)
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "cmp-fuzz-client"}, signer)
	if err != nil {
		f.Fatalf("build CMP fuzz CSR: %v", err)
	}
	reqDER, err := crypto.BuildCMPRequest(csrDER, certDER, keyPKCS8, []byte("cmp-fuzz-txid"), []byte("cmp-fuzz-nonce"))
	if err != nil {
		f.Fatalf("build CMP fuzz request: %v", err)
	}
	return reqDER
}
