// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/deviceattest"
)

func FuzzParseAndVerifyTPMDeviceAttestation(f *testing.F) {
	f.Add([]byte(`{}`), []byte("challenge"), []byte("not a certificate"))
	f.Add([]byte(`{"type":"public-key","response":{}}`), make([]byte, 32), []byte("-----BEGIN CERTIFICATE-----"))
	f.Fuzz(func(t *testing.T, credentialJSON, challenge, rootPEM []byte) {
		if len(credentialJSON) > 1<<20 || len(challenge) > 1024 || len(rootPEM) > 1<<20 {
			t.Skip()
		}
		_, _ = deviceattest.ParseAndVerifyTPMDeviceAttestation(
			credentialJSON,
			challenge,
			[][]byte{rootPEM},
			[]int64{-7, -257},
			time.Unix(1_785_240_000, 0).UTC(),
		)
	})
}

// FuzzVerifyTPMCustodyEvidence covers offline re-verification of retained
// device-bound custody evidence: the binding JSON, the certificate DER, and
// the attestation envelope are all read back from storage or an export.
func FuzzVerifyTPMCustodyEvidence(f *testing.F) {
	f.Add([]byte(`{}`), []byte(`{"csr_key_sha256":"AAAA"}`), []byte("not a certificate"), []byte("not a root"))
	f.Add([]byte(`{"type":"public-key","response":{}}`), []byte(`{`), make([]byte, 64), []byte("-----BEGIN CERTIFICATE-----"))
	f.Fuzz(func(t *testing.T, credentialJSON, binding, certificateDER, rootPEM []byte) {
		if len(credentialJSON) > 1<<20 || len(binding) > 1<<20 || len(certificateDER) > 1<<20 || len(rootPEM) > 1<<20 {
			t.Skip()
		}
		_, _ = deviceattest.VerifyTPMCustodyEvidence(deviceattest.TPMCustodyEvidence{
			Credential: credentialJSON, Binding: binding, VerifiedAt: time.Unix(1_785_240_000, 0).UTC(),
		}, certificateDER, [][]byte{rootPEM})
	})
}
