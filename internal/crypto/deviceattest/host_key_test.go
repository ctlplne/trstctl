// SPDX-License-Identifier: BUSL-1.1

package deviceattest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

// TestHostKeyAttestationVerifiesOnlyTheJobsDeviceBoundKeyTPMO1: a host key's
// TPM credential over SHA-256 of its binding (the CSR's key, the job, the
// purpose) verifies under the operator's root, names the CSR's key and is
// device-bound; the same evidence re-verifies offline as the certificate's
// custody claim. Each other case is refused: a credential over another job's
// binding, a binding without the host-key purpose, another key's CSR, a root
// that is not the operator's, a key the TPM would let leave (no fixedTPM and
// fixedParent), and no credential at all.
func TestHostKeyAttestationVerifiesOnlyTheJobsDeviceBoundKeyTPMO1(t *testing.T) {
	now := time.Now().UTC()
	identity, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := identity.CSRDERFor("web.example.test")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := deviceattest.HostKeyBinding(7, csrDER)
	if err != nil {
		t.Fatal(err)
	}
	var stated map[string]any
	if err := json.Unmarshal(binding, &stated); err != nil || stated["purpose"] != deviceattest.HostKeyAttestationPurpose || stated["job_id"] != float64(7) || len(stated) != 3 {
		t.Fatalf("binding = %s (%v)", binding, err)
	}
	challenge := sha256.Sum256(binding)
	credential, err := identity.CredentialJSON(challenge[:])
	if err != nil {
		t.Fatal(err)
	}
	roots := [][]byte{identity.RootPEM()}

	result, err := deviceattest.VerifyHostKeyAttestation(credential, binding, csrDER, roots, now)
	if err != nil {
		t.Fatalf("the job's host key attestation: %v", err)
	}
	csrKey, err := deviceattest.CSRPublicKeySHA256(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if !result.DeviceBound || !bytes.Equal(result.PublicKeySHA256, csrKey) || len(result.AttestationCertificateSHA256) != 32 {
		t.Fatalf("result = %+v", result)
	}

	// The same evidence is the certificate's custody claim, re-checked offline
	// the way `trstctl certificates verify-key-attestation` does.
	ca, err := trstcrypto.GenerateLockedKey(trstcrypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := trstcrypto.SelfSignedCACert(ca, "TPM-O1 test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := trstcrypto.SignLeafFromCSR(caDER, ca, csrDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceattest.VerifyTPMCustodyEvidence(deviceattest.TPMCustodyEvidence{Credential: credential, Binding: binding, VerifiedAt: now},
		leafDER, roots); err != nil {
		t.Fatalf("offline custody verification of the host key evidence: %v", err)
	}

	otherJob, err := deviceattest.HostKeyBinding(8, csrDER)
	if err != nil {
		t.Fatal(err)
	}
	acmeShaped, err := json.Marshal(map[string]string{"csr_key_sha256": stated["csr_key_sha256"].(string)})
	if err != nil {
		t.Fatal(err)
	}
	acmeChallenge := sha256.Sum256(acmeShaped)
	acmeCredential, err := identity.CredentialJSON(acmeChallenge[:])
	if err != nil {
		t.Fatal(err)
	}
	otherCSR := other.CSRDER()
	duplicable, err := identity.DuplicableCredentialJSON(challenge[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		credential []byte
		binding    []byte
		csr        []byte
		roots      [][]byte
		want       string
	}{
		{"another job's binding", credential, otherJob, csrDER, roots, "host key attestation"},
		{"no host-key purpose", acmeCredential, acmeShaped, csrDER, roots, "different key or purpose"},
		{"another key's CSR", credential, binding, otherCSR, roots, "different key or purpose"},
		{"a root that is not the operator's", credential, binding, csrDER, [][]byte{other.RootPEM()}, "host key attestation"},
		{"a key that could leave the TPM", duplicable, binding, csrDER, roots, "could leave the TPM"},
		{"no credential", nil, binding, csrDER, roots, "no TPM attestation"},
	} {
		if _, err := deviceattest.VerifyHostKeyAttestation(tc.credential, tc.binding, tc.csr, tc.roots, now); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	if _, err := deviceattest.HostKeyBinding(0, csrDER); err == nil {
		t.Fatal("a binding without a job was built")
	}
}
