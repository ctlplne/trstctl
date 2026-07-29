// SPDX-License-Identifier: MPL-2.0

package deviceattest_test

import (
	"bytes"
	"testing"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

func TestDeviceAttestTPMParserVerifiesChallengeKeyAlgorithmAndRoot(t *testing.T) {
	now := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	identity, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatalf("create TPM identity fixture: %v", err)
	}
	challenge := trstcrypto.SHA256Sum([]byte("tenant/account/order/challenge/nonce/device/csr/time"))
	credentialJSON, err := identity.CredentialJSON(challenge)
	if err != nil {
		t.Fatalf("build TPM credential response: %v", err)
	}

	got, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(
		credentialJSON,
		challenge,
		[][]byte{identity.RootPEM()},
		[]int64{-7},
		now,
	)
	if err != nil {
		t.Fatalf("verify TPM device attestation: %v", err)
	}
	csrDigest, err := deviceattest.CSRPublicKeySHA256(identity.CSRDER())
	if err != nil {
		t.Fatalf("digest CSR public key: %v", err)
	}
	if !bytes.Equal(got.PublicKeySHA256, csrDigest) {
		t.Fatalf("attested key digest = %x, want CSR key digest %x", got.PublicKeySHA256, csrDigest)
	}
	if got.Algorithm != -7 {
		t.Fatalf("attested algorithm = %d, want ES256 (-7)", got.Algorithm)
	}
	if len(got.AttestationCertificateSHA256) != 32 {
		t.Fatalf("attestation certificate digest length = %d, want 32", len(got.AttestationCertificateSHA256))
	}

	if _, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(
		credentialJSON,
		trstcrypto.SHA256Sum([]byte("other challenge")),
		[][]byte{identity.RootPEM()},
		[]int64{-7},
		now,
	); err == nil {
		t.Fatal("TPM attestation accepted a mismatched challenge")
	}
	if _, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(
		credentialJSON,
		challenge,
		[][]byte{identity.RootPEM()},
		[]int64{-257},
		now,
	); err == nil {
		t.Fatal("TPM attestation accepted a disallowed credential algorithm")
	}
	other, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatalf("create second TPM identity fixture: %v", err)
	}
	if _, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(
		credentialJSON,
		challenge,
		[][]byte{other.RootPEM()},
		[]int64{-7},
		now,
	); err == nil {
		t.Fatal("TPM attestation accepted an untrusted attestation root")
	}
}

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
