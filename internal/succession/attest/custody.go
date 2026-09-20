// SPDX-License-Identifier: BUSL-1.1

// Package attest models custody-attestation evidence for a succession's successor
// key and the class gate over it (PCAS-claim-35, FIG. 9; establishes the attested-pre-gen
// limb of INV-15). A succession request carries the successor custodian's attestation
// evidence (a TPM quote, a cloud instance identity, …); the signer verifies it BEFORE
// generating the successor key, binds its digest + type into the record, and refuses
// evidence below the minimum attestation class a policy requires for the target
// algorithm class. The relying party mirrors that refusal. The attestation-evidence
// verifier FORMATS are core internal/attest (TPM / cloud-IID verifiers); this package
// is the evidence-class model, the digest binding, and the gate. Verification is
// push-based: the signer verifies against locally-configured roots, pulling no
// networked verifier into the boundary. All hashing routes through the core AN-3
// boundary.
package attest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const evidenceDomain = "trstctl/pcas/custody-attestation/v1"

// Errors.
var (
	ErrEvidenceDecode  = errors.New("attest: cannot decode attestation evidence")
	ErrEvidenceInvalid = errors.New("attest: attestation evidence failed verification")
	ErrClassMismatch   = errors.New("attest: verified custody class does not match the evidence type")
	ErrBelowMinClass   = errors.New("attest: custody attestation class is below the minimum required for the target algorithm class")
)

// Class is a custody-attestation class, ordered from weakest to strongest.
type Class int

const (
	ClassNone        Class = iota // no / unknown custody
	ClassSoftware                 // software-only custody
	ClassVirtualTPM               // virtual TPM / cloud instance identity
	ClassHardwareTPM              // hardware TPM
	ClassHSM                      // HSM-rooted custody
)

// typeClass is the fixed mapping from an attestation-type identifier to its class.
var typeClass = map[string]Class{
	"software":     ClassSoftware,
	"virtual-tpm":  ClassVirtualTPM,
	"aws-iid":      ClassVirtualTPM,
	"hardware-tpm": ClassHardwareTPM,
	"hsm":          ClassHSM,
}

// ClassOfType returns the custody class an attestation type denotes (ClassNone if
// unknown). A record binds the type; the relying party maps it back to a class.
func ClassOfType(attestationType string) Class { return typeClass[attestationType] }

// Evidence is the successor custodian's attestation evidence. Type is the
// attestation-type identifier; Blob is the opaque evidence (verified by the core
// internal/attest verifiers against locally-configured roots).
type Evidence struct {
	Type string `json:"type"`
	Blob []byte `json:"blob"`
}

// Encode / Decode serialize evidence for carriage in a mint request.
func Encode(e Evidence) ([]byte, error) { return json.Marshal(e) }
func Decode(b []byte) (Evidence, error) {
	var e Evidence
	if err := json.Unmarshal(b, &e); err != nil {
		return Evidence{}, fmt.Errorf("%w: %v", ErrEvidenceDecode, err)
	}
	return e, nil
}

// Digest is the evidence digest bound into the record (PCAS-claim-35): a domain-separated
// hash of the type + blob, so a third party recomputes it from the published evidence.
func Digest(e Evidence) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(evidenceDomain))
	writeField(&b, []byte(e.Type))
	writeField(&b, e.Blob)
	return crypto.SHA256Sum(b.Bytes())
}

// Verifier verifies attestation evidence against locally-configured roots and returns
// the verified custody class. The core internal/attest verifiers implement it; a
// verifier must not reach out to networked services (push-based discipline).
type Verifier interface {
	Verify(e Evidence) (Class, error)
}

// Gate verifies successor-custodian evidence and enforces the class gate before
// keygen. It implements the minter's AttestationGate seam.
type Gate struct {
	Verifier   Verifier
	MinByClass map[string]Class              // algorithm-class key -> minimum custody class
	AlgClass   func(crypto.Algorithm) string // successor algorithm -> algorithm-class key
}

// Verify decodes and verifies the request's attestation evidence, checks the verified
// class is consistent with the evidence type, and enforces the minimum-class gate for
// the target algorithm's class. On success it returns the evidence digest + type to
// bind into the record; any failure refuses the mint (before keygen).
func (g Gate) Verify(req signing.MintRequest) (evidenceDigest []byte, attestationType string, err error) {
	ev, err := Decode(req.Attestation)
	if err != nil {
		return nil, "", err
	}
	class, err := g.Verifier.Verify(ev)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrEvidenceInvalid, err)
	}
	if class != ClassOfType(ev.Type) {
		return nil, "", ErrClassMismatch
	}
	min := ClassNone
	if g.AlgClass != nil && g.MinByClass != nil {
		min = g.MinByClass[g.AlgClass(req.TargetAlgorithm)]
	}
	if class < min {
		return nil, "", fmt.Errorf("%w: class %d < min %d", ErrBelowMinClass, class, min)
	}
	return Digest(ev), ev.Type, nil
}

func writeField(b *bytes.Buffer, v []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(v)))
	b.Write(l[:])
	b.Write(v)
}
