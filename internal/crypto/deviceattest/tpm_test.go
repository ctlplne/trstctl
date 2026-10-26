// SPDX-License-Identifier: BUSL-1.1

package deviceattest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
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

// A131: the verifier reports a key as device-bound only when the certified
// object's attributes say the TPM made it and will not release it; a valid
// attestation of a duplicable key verifies but is not device-bound.
func TestDeviceAttestTPMReportsWhetherTheAttestedKeyCanLeaveTheTPM(t *testing.T) {
	now := time.Date(2026, time.October, 26, 12, 0, 0, 0, time.UTC)
	identity, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	challenge := trstcrypto.SHA256Sum([]byte("device-bound attribute check"))
	for name, build := range map[string]func([]byte) ([]byte, error){
		"device-bound": identity.CredentialJSON, "duplicable": identity.DuplicableCredentialJSON,
	} {
		credential, err := build(challenge)
		if err != nil {
			t.Fatal(err)
		}
		result, err := deviceattest.ParseAndVerifyTPMDeviceAttestation(credential, challenge, [][]byte{identity.RootPEM()}, []int64{-7}, now)
		if err != nil {
			t.Fatalf("%s attestation did not verify: %v", name, err)
		}
		if result.DeviceBound != (name == "device-bound") {
			t.Fatalf("%s attestation DeviceBound = %t", name, result.DeviceBound)
		}
	}
}

// A131: retained custody evidence re-verifies offline against the
// certificate's key at the time it was first verified, and refuses another
// certificate, an edited binding, a duplicable key, and untrusted roots.
func TestVerifyTPMCustodyEvidenceRechecksTheClaimOffline(t *testing.T) {
	// The fixture's attestation key certificate is valid for a day around
	// verifiedAt, long before the test runs: re-verification checks the time
	// the claim was made, not the time it is read.
	verifiedAt := time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC)
	identity, err := deviceattesttest.NewTPMIdentity(verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	certificateDER := fixtureCertificateForCSR(t, identity.CSRDER(), verifiedAt)
	keyDigest, err := deviceattest.CSRPublicKeySHA256(identity.CSRDER())
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte(`{"version":1,"tenant_id":"t1","order_id":"o1","csr_key_sha256":"` +
		base64.RawURLEncoding.EncodeToString(keyDigest) + `"}`)
	credential, err := identity.CredentialJSON(trstcrypto.SHA256Sum(binding))
	if err != nil {
		t.Fatal(err)
	}
	evidence := deviceattest.TPMCustodyEvidence{Credential: credential, Binding: binding, VerifiedAt: verifiedAt}
	roots := [][]byte{identity.RootPEM()}
	result, err := deviceattest.VerifyTPMCustodyEvidence(evidence, certificateDER, roots)
	if err != nil || !result.DeviceBound || !bytes.Equal(result.PublicKeySHA256, keyDigest) {
		t.Fatalf("offline re-verification = %+v, %v", result, err)
	}

	other, err := deviceattesttest.NewTPMIdentity(verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceattest.VerifyTPMCustodyEvidence(evidence, fixtureCertificateForCSR(t, other.CSRDER(), verifiedAt), roots); err == nil {
		t.Fatal("evidence verified for another certificate's key")
	}
	edited := evidence
	edited.Binding = []byte(strings.Replace(string(binding), `"o1"`, `"o2"`, 1))
	if _, err := deviceattest.VerifyTPMCustodyEvidence(edited, certificateDER, roots); err == nil {
		t.Fatal("evidence verified with an edited binding")
	}
	if _, err := deviceattest.VerifyTPMCustodyEvidence(evidence, certificateDER, [][]byte{other.RootPEM()}); err == nil {
		t.Fatal("evidence verified under roots that did not issue its attestation key")
	}
	duplicable, err := identity.DuplicableCredentialJSON(trstcrypto.SHA256Sum(binding))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceattest.VerifyTPMCustodyEvidence(deviceattest.TPMCustodyEvidence{
		Credential: duplicable, Binding: binding, VerifiedAt: verifiedAt,
	}, certificateDER, roots); err == nil || !strings.Contains(err.Error(), "not device-bound") {
		t.Fatalf("a duplicable TPM key verified as device-bound: %v", err)
	}
}

// fixtureCertificateForCSR issues a throwaway certificate for the CSR's key.
func fixtureCertificateForCSR(t *testing.T, csrDER []byte, now time.Time) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: csr.Subject, DNSNames: csr.DNSNames,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
