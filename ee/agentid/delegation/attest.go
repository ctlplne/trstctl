// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// attest.go models the environment/custody attestation evidence the gate consumes and
// the min-attestation-class gate keyed on the chain head's designated authority class
// (claim 10). Verification is push-based: the gate verifies against a locally-configured
// AttestationVerifier, pulling no networked verifier into the AN-4 boundary.
//
// IMPORTANT (AN-4): this signer-linked package does NOT import internal/attest. The core
// internal/attest verifiers (TPM / cloud-IID) transitively pull internal/graph ->
// database/sql, which must never link into the isolated signer. Instead the gate depends
// on the narrow AttestationVerifier interface and a package-local VerifiedAttestation
// value; the concrete adapter over internal/attest is supplied by the control-plane
// wiring OUTSIDE the signer closure (or by a test fake). All hashing routes through
// internal/crypto (AN-3).

const attestEvidenceDomain = "agid/agentid/attestation-evidence/v1"

// Attestation errors.
var (
	// ErrDecodeAttestation is returned when the opaque attestation body cannot be
	// decoded. Fail-closed: it becomes a signed refusal, no key op.
	ErrDecodeAttestation = errors.New("delegation: cannot decode attestation evidence body")
	// ErrAttestationRequired is returned when a designated authority class requires
	// attestation but none was supplied.
	ErrAttestationRequired = errors.New("delegation: attestation evidence required for the designated authority class")
	// ErrAttestationInvalid is returned when the supplied attestation evidence fails
	// verification against the configured verifier.
	ErrAttestationInvalid = errors.New("delegation: attestation evidence failed verification")
	// ErrBelowMinClass is returned when verified evidence is below the minimum
	// attestation class the designated authority class requires (claim 10). Its
	// message NAMES the class not met.
	ErrBelowMinClass = errors.New("delegation: attestation class below the minimum required for the designated authority class")
)

// AttestationClass is an attestation class, ordered weakest to strongest, mirroring the
// succession custody-attestation model so the two data planes agree on class ordering.
type AttestationClass int

const (
	ClassNone        AttestationClass = iota // no / unknown attestation
	ClassSoftware                            // software-only attestation
	ClassVirtualTPM                          // virtual TPM / cloud instance identity
	ClassHardwareTPM                         // hardware TPM
	ClassHSM                                 // HSM-rooted attestation
)

// String renders a class for refusal messages (never a secret).
func (c AttestationClass) String() string {
	switch c {
	case ClassSoftware:
		return "software"
	case ClassVirtualTPM:
		return "virtual-tpm"
	case ClassHardwareTPM:
		return "hardware-tpm"
	case ClassHSM:
		return "hsm"
	default:
		return "none"
	}
}

// methodClass maps an attestation method (or an attestation-class claim value) to its
// class. The mapping is the fixed policy the relying party mirrors. An unknown method
// maps to ClassNone (fail-closed: unknown never meets a positive minimum).
var methodClass = map[string]AttestationClass{
	"software":     ClassSoftware,
	"virtual-tpm":  ClassVirtualTPM,
	"aws_iid":      ClassVirtualTPM,
	"aws-iid":      ClassVirtualTPM,
	"k8s_sat":      ClassVirtualTPM,
	"github_oidc":  ClassVirtualTPM,
	"gcp":          ClassVirtualTPM,
	"azure":        ClassVirtualTPM,
	"tpm":          ClassHardwareTPM,
	"hardware-tpm": ClassHardwareTPM,
	"hsm":          ClassHSM,
}

// ClassOfMethod returns the attestation class a method/claim denotes (ClassNone if
// unknown).
func ClassOfMethod(method string) AttestationClass { return methodClass[method] }

// VerifiedAttestation is the gate's package-local view of a verified attestation: the
// non-secret facts the gate needs (the method, the verified subject, and the
// verified attributes/claims). It deliberately mirrors the subset of
// internal/attest.Attestation the gate uses, WITHOUT importing internal/attest, so the
// signer-linked gate does not transitively link a datastore (AN-4). The control-plane
// adapter converts a core attest.Attestation into this value outside the signer closure.
type VerifiedAttestation struct {
	Method  string
	Subject string
	// Claims are method-specific verified attributes. The "attestation_class" claim,
	// when present and recognized, sets the class; otherwise the method maps.
	Claims map[string]string
}

// AttestationBody is the decoded attestation-evidence body carried opaquely in
// signing.IssuancePreconditions.Attestation. Payload is the raw proof the verifier
// consumes; Method (mirrored from IssuancePreconditions.AttestationMethod) selects the
// verifier path.
type AttestationBody struct {
	Method  string `json:"method"`
	Payload []byte `json:"payload"`
}

// decodeAttestation decodes the opaque attestation body fail-closed. An empty body
// decodes to the zero body (no attestation supplied); the gate decides whether that is
// acceptable given the designated class.
func decodeAttestation(b []byte, method string) (AttestationBody, error) {
	if len(b) == 0 {
		return AttestationBody{Method: method}, nil
	}
	var body AttestationBody
	if err := json.Unmarshal(b, &body); err != nil {
		return AttestationBody{}, fmt.Errorf("%w: %v", ErrDecodeAttestation, err)
	}
	if body.Method == "" {
		body.Method = method
	}
	return body, nil
}

// AttestationVerifier verifies attestation evidence against locally-configured roots and
// returns the verified attestation. The gate is constructed with one; tests inject a
// fake so the gate is testable with software crypto. A verifier MUST NOT reach networked
// services (push-based discipline inside the AN-4 boundary). The concrete adapter over
// internal/attest lives OUTSIDE the signer closure (control-plane wiring), so the
// signer-linked gate never imports internal/attest.
type AttestationVerifier interface {
	// VerifyEvidence verifies the evidence for method and returns the verified
	// attestation, or an error (forged/replayed/malformed evidence fails closed).
	VerifyEvidence(method string, payload []byte) (VerifiedAttestation, error)
}

// classOfAttestation returns the class a verified attestation asserts: the
// "attestation_class" claim when present and recognized, else the method's class.
// Fail-closed: an unrecognized class claim value falls back to the method mapping, and
// an unknown method is ClassNone.
func classOfAttestation(att VerifiedAttestation) AttestationClass {
	if att.Claims != nil {
		if v, ok := att.Claims["attestation_class"]; ok {
			if c, known := methodClass[v]; known {
				return c
			}
		}
	}
	return ClassOfMethod(att.Method)
}

// MinClassPolicy maps a designated authority class to the minimum attestation class its
// issuance requires (claim 10). A class absent from the map requires ClassNone (no
// attestation gate). The empty policy gates nothing.
type MinClassPolicy map[string]AttestationClass

// Min returns the minimum attestation class required for designatedClass (ClassNone when
// unmapped or when the policy is nil).
func (p MinClassPolicy) Min(designatedClass string) AttestationClass {
	if p == nil || designatedClass == "" {
		return ClassNone
	}
	return p[designatedClass]
}

// attestationEvidenceDigest is a domain-separated digest of the verified attestation,
// bound into the issuance record so a third party can recompute it.
func attestationEvidenceDigest(att VerifiedAttestation) []byte {
	var b bytes.Buffer
	b.WriteString(attestEvidenceDomain)
	writeStr(&b, att.Method)
	writeStr(&b, att.Subject)
	return crypto.SHA256Sum(b.Bytes())
}
