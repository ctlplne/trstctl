// SPDX-License-Identifier: BUSL-1.1

package deviceattest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
)

// HostKeyAttestationPurpose names a host endpoint key's attestation (TPM-O1).
const HostKeyAttestationPurpose = "trstctl-host-key"

// HostKeyBinding is the statement a host endpoint key's TPM attestation signs
// (TPM-O1): the CSR's key and the endpoint renewal job it was made for. The
// agent and the control plane build it identically from the job and the CSR
// (the control plane reads the job under the agent's own tenant); its SHA-256
// is the attestation's challenge, and it is kept with the evidence, so
// `trstctl certificates verify-key-attestation` re-checks the custody claim
// offline (its csr_key_sha256 names the certificate's key).
func HostKeyBinding(jobID int64, csrDER []byte) ([]byte, error) {
	if jobID <= 0 {
		return nil, errors.New("crypto: a host key binding needs its job")
	}
	key, err := CSRPublicKeySHA256(csrDER)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		CSRKeySHA256 string `json:"csr_key_sha256"`
		JobID        int64  `json:"job_id"`
		Purpose      string `json:"purpose"`
	}{base64.RawURLEncoding.EncodeToString(key), jobID, HostKeyAttestationPurpose})
}

// CreateHostKeyTPMCredential wraps TPM2_Certify of a host key (the CSR's key,
// objectPublicDER) by the attestation key aikHandle, whose certificate chain
// is aikChainPEM, in the WebAuthn TPM envelope over SHA-256(binding). certify
// is the device's TPM2_Certify over the envelope's qualifying data; the
// credential is verified locally before it leaves the host.
func CreateHostKeyTPMCredential(binding, csrDER, objectPublicDER []byte, aikHandle trstcrypto.EdgeCAKeyHandle, aikChainPEM []byte,
	certify func(qualifyingData []byte) (trstcrypto.EdgeTPMCertification, error)) ([]byte, error) {
	if certify == nil || len(binding) == 0 || len(binding) > maxDeviceAttestationBytes {
		return nil, errors.New("crypto: a host key attestation needs its binding and a TPM")
	}
	if aikHandle.Provider != "tpm2" || aikHandle.KeyID == "" || aikHandle.Version != 1 || aikHandle.Algorithm != trstcrypto.ECDSAP256 {
		return nil, errors.New("crypto: the attestation key must be a current-format TPM2 P-256 handle")
	}
	challenge := sha256.Sum256(binding)
	return buildTPMCredential(challenge[:], csrDER, objectPublicDER, aikHandle.PublicKeyDER, aikChainPEM, certify)
}

// VerifyHostKeyAttestation checks a host key's TPM credential (TPM-O1): it
// verifies under rootsPEM over SHA-256(binding) at now, the binding names the
// CSR's key, the TPM attested that same key, and the key is device-bound
// (fixedTPM, fixedParent and sensitiveDataOrigin: the TPM generated it and
// will not release it).
func VerifyHostKeyAttestation(credential, binding, csrDER []byte, rootsPEM [][]byte, now time.Time) (TPMDeviceAttestationResult, error) {
	if len(credential) == 0 {
		return TPMDeviceAttestationResult{}, errors.New("crypto: the host key carries no TPM attestation")
	}
	csrKey, err := CSRPublicKeySHA256(csrDER)
	if err != nil {
		return TPMDeviceAttestationResult{}, err
	}
	var stated struct {
		CSRKeySHA256 string `json:"csr_key_sha256"`
		Purpose      string `json:"purpose"`
	}
	if err := json.Unmarshal(binding, &stated); err != nil || stated.Purpose != HostKeyAttestationPurpose ||
		stated.CSRKeySHA256 != base64.RawURLEncoding.EncodeToString(csrKey) {
		return TPMDeviceAttestationResult{}, errors.New("crypto: the host key binding names a different key or purpose")
	}
	challenge := sha256.Sum256(binding)
	result, err := ParseAndVerifyTPMDeviceAttestation(credential, challenge[:], rootsPEM, []int64{int64(webauthncose.AlgES256)}, now)
	if err != nil {
		return TPMDeviceAttestationResult{}, fmt.Errorf("crypto: host key attestation: %w", err)
	}
	if subtle.ConstantTimeCompare(result.PublicKeySHA256, csrKey) != 1 {
		return TPMDeviceAttestationResult{}, errors.New("crypto: the TPM attested a different key than the CSR's")
	}
	if !result.DeviceBound {
		return TPMDeviceAttestationResult{}, errors.New("crypto: the attested host key could leave the TPM (fixedTPM, fixedParent and sensitiveDataOrigin are not all set)")
	}
	return result, nil
}
