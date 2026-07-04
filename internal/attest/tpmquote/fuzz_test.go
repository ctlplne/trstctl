// SPDX-License-Identifier: MPL-2.0

package tpmquote

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzTPMQuoteAttest hardens the TPM 2.0 quote attester's untrusted entry point
// (Attest), which JSON-decodes an attacker-supplied Quote envelope and then drives
// its AKCertDER / Message / Signature bytes through the crypto boundary
// (VerifyLeafSignedByCA, PublicKeyDERFromCert, VerifyMessage) BEFORE trust is
// established (FUZZ-003). No input — random bytes, malformed JSON, a JSON envelope
// carrying a garbage ak_cert, or a fully valid signed quote — may panic. Attest must
// always return cleanly (an attestation or an error). Seeded with a valid quote whose
// AK chains to a trusted manufacturer root so the corpus exercises the full
// verification happy path too.
func FuzzTPMQuoteAttest(f *testing.F) {
	manu, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatal(err)
	}
	defer manu.Destroy()
	manuCert, err := crypto.SelfSignedCACert(manu, "TPM Manufacturer CA", time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	ak, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		f.Fatal(err)
	}
	defer ak.Destroy()
	akCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "AK"}, ak)
	if err != nil {
		f.Fatal(err)
	}
	akCert, err := crypto.SignLeafFromCSR(manuCert, manu, akCSR, time.Hour)
	if err != nil {
		f.Fatal(err)
	}
	nonce := []byte("challenge-nonce-123")
	message := append([]byte("PCR0:abcd|nonce:"), nonce...)
	sig, err := crypto.SignMessage(ak, message)
	if err != nil {
		f.Fatal(err)
	}

	if good, err := json.Marshal(Quote{AKCertDER: akCert, Message: message, Signature: sig, Nonce: nonce}); err == nil {
		f.Add(good)
	}
	// Valid JSON envelope but a garbage ak_cert — exercises the cert-parse/verify
	// error path on attacker bytes (the certificate boundary must reject, not panic).
	if badCert, err := json.Marshal(Quote{AKCertDER: []byte{0x30, 0x82, 0x00, 0x00}, Message: message, Signature: sig, Nonce: nonce}); err == nil {
		f.Add(badCert)
	}
	// Valid JSON shape, all fields empty (forces the "missing ak_cert/message/sig"
	// guard).
	if empty, err := json.Marshal(Quote{}); err == nil {
		f.Add(empty)
	}

	f.Add([]byte(nil))
	f.Add([]byte("not json"))
	f.Add([]byte("{"))
	f.Add([]byte(`{"ak_cert":"!!!not base64!!!"}`)) // []byte field fed invalid base64
	f.Add([]byte(`{"ak_cert":"AAAA","message":"AAAA","signature":"AAAA","nonce":"AAAA"}`))

	a := &Attestor{ManufacturerRoots: [][]byte{manuCert}, ExpectedNonce: nonce}
	f.Fuzz(func(t *testing.T, payload []byte) {
		// Only the absence of a panic is asserted; a malformed envelope, an untrusted
		// AK, or a bad signature legitimately returns an error.
		_, _ = a.Attest(context.Background(), payload)
	})
}
