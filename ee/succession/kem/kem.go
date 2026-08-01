// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package kem implements succession for key-establishment (confidentiality)
// credentials — e.g. ML-KEM — where the successor cannot sign the commitment
// (PCAS-claims 15, 30). A KEM successor proves possession one of two ways, and the
// record NAMES which it uses:
//
//   - Variant A (interactive): the signer encapsulates a challenge to the successor
//     KEM public key; the holder demonstrates decapsulation; the transcript is bound
//     to the commitment digest. It convinces only the challenger (who holds the
//     encapsulated secret) — it is NOT publicly verifiable.
//   - Variant B (publicly verifiable, preferred): the KEM identity is paired, in the
//     same succession, with an epoch-bound signing key that signs the commitment;
//     that key also signs a binding naming the KEM public key. An arbitrary third
//     party verifies both offline.
//
// For a predecessor that is itself a KEM (PCAS-claim-30), predecessor possession is
// proven by decapsulation of a challenge to the FIRST public key, and BOTH
// transcripts are bound to the commitment. All ML-KEM primitives route through
// ee/pqc and the core internal/crypto AN-3 boundary; this package imports no
// crypto/* directly.
package kem

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

// Domain separators for the KEM transcript and the Variant-B binding. Frozen.
const (
	challengeDomain = "trstctl/pcas/kem/challenge/v1"
	bindingDomain   = "trstctl/pcas/kem/binding/v1"
)

// Errors.
var (
	ErrDecapProof         = errors.New("kem: decapsulation transcript does not verify")
	ErrBinding            = errors.New("kem: paired-key KEM binding does not verify")
	ErrMechanismMismatch  = errors.New("kem: record does not correctly name its possession-proof mechanism")
	ErrNotPubliclyVerif   = errors.New("kem: interactive (decap-transcript) record is not publicly verifiable; policy requires the paired-signing-key variant")
	ErrRewrapIncomplete   = errors.New("kem: re-wrap under the successor key is not complete; predecessor retirement is blocked")
	ErrMissingTranscripts = errors.New("kem: predecessor-KEM record must bind both predecessor and successor transcripts")
)

// Transcript is a KEM challenge/response: the ciphertext the challenger encapsulated
// and the holder's response proving decapsulation, bound to the commitment.
type Transcript struct {
	Ciphertext []byte `json:"ciphertext"`
	Response   []byte `json:"response"`
}

func (t Transcript) encode() []byte { b, _ := json.Marshal(t); return b }

func decodeTranscript(b []byte) (Transcript, error) {
	var t Transcript
	err := json.Unmarshal(b, &t)
	return t, err
}

// response binds the shared secret to the commitment and the ciphertext:
// H(domain || commitment || ciphertext || sharedSecret). A holder who cannot
// decapsulate cannot produce it; a challenger who encapsulated recomputes it.
func response(commitment, ciphertext, sharedSecret []byte) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(challengeDomain))
	writeField(&b, commitment)
	writeField(&b, ciphertext)
	writeField(&b, sharedSecret)
	return crypto.SHA256Sum(b.Bytes())
}

// EncapsulateChallenge encapsulates a fresh challenge to a successor/predecessor KEM
// public key, returning the ciphertext to send and the challenger secret to retain
// for verification (Variant A / PCAS-claim-30 challenger side).
func EncapsulateChallenge(kemAlg string, kemPubDER []byte) (ciphertext, challengerSecret []byte, err error) {
	return eepqc.Encapsulate(crypto.PublicKey{Algorithm: crypto.Algorithm(kemAlg), DER: kemPubDER})
}

// Respond decapsulates the challenge with the KEM private key and returns the
// transcript bound to commitment (holder side).
func Respond(kemPriv *eepqc.KEMPrivateKey, ciphertext, commitment []byte) (Transcript, error) {
	ss, err := kemPriv.Decapsulate(ciphertext)
	if err != nil {
		return Transcript{}, fmt.Errorf("kem: decapsulate: %w", err)
	}
	return Transcript{Ciphertext: ciphertext, Response: response(commitment, ciphertext, ss)}, nil
}

// VerifyTranscript checks a transcript against the challenger secret and commitment
// (Variant A challenger side). It proves the holder decapsulated the challenge and
// bound it to this commitment.
func VerifyTranscript(challengerSecret, commitment []byte, t Transcript) error {
	want := response(commitment, t.Ciphertext, challengerSecret)
	if len(t.Response) == 0 || !bytes.Equal(want, t.Response) {
		return ErrDecapProof
	}
	return nil
}

// --- Variant A record (interactive) ----------------------------------------

// BuildInteractiveRecord assembles a Variant-A KEM succession record: the successor
// KEM key is named in the commitment (fields.SuccessorAlg/SuccessorPub), the
// predecessor signs the commitment, and the possession proof is the decap transcript.
func BuildInteractiveRecord(fields succession.CommitmentFields, predecessorAtt []byte, t Transcript) succession.SuccessionRecord {
	return succession.SuccessionRecord{
		Fields:         fields,
		PredecessorAtt: predecessorAtt,
		Possession:     succession.PossessionProof{Kind: succession.ProofDecapTranscript, Transcript: t.encode()},
	}
}

// VerifyInteractiveRecord verifies a Variant-A record: the predecessor attestation
// (a signature) over the commitment, and the successor decap transcript against the
// challenger secret. It is NOT publicly verifiable — only the challenger can call it.
func VerifyInteractiveRecord(rec succession.SuccessionRecord, challengerSecret []byte) error {
	if err := VerifyNamesMechanism(rec.Possession); err != nil {
		return err
	}
	if rec.Possession.Kind != succession.ProofDecapTranscript {
		return fmt.Errorf("%w: not an interactive record", ErrMechanismMismatch)
	}
	commitment, err := succession.Commit(rec.Fields)
	if err != nil {
		return err
	}
	if len(rec.PredecessorAtt) == 0 {
		return succession.ErrPredecessorAttestation
	}
	if err := crypto.VerifyMessage(rec.Fields.PredecessorPub, commitment, rec.PredecessorAtt); err != nil {
		return fmt.Errorf("%w: %v", succession.ErrPredecessorAttestation, err)
	}
	tr, err := decodeTranscript(rec.Possession.Transcript)
	if err != nil {
		return fmt.Errorf("kem: decode transcript: %w", err)
	}
	return VerifyTranscript(challengerSecret, commitment, tr)
}

// --- Variant B record (publicly verifiable) --------------------------------

// bindingMessage is the message the paired signing key signs to bind the KEM public
// key to the commitment: H over domain || commitment || kemAlg || kemPub.
func bindingMessage(commitment []byte, kemAlg string, kemPubDER []byte) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(bindingDomain))
	writeField(&b, commitment)
	writeField(&b, []byte(kemAlg))
	writeField(&b, kemPubDER)
	return b.Bytes()
}

// SignKEMBinding signs, with the paired epoch-bound signing key, a binding naming
// the KEM public key over this commitment (Variant B).
func SignKEMBinding(paired crypto.Signer, commitment []byte, kemAlg string, kemPubDER []byte) ([]byte, error) {
	return paired.Sign(bindingMessage(commitment, kemAlg, kemPubDER), crypto.SignOptions{Hash: crypto.SHA256})
}

// PairedRecord is a Variant-B KEM succession: a base record whose successor is the
// paired epoch-bound SIGNING key (named in the commitment, base-verifiable), plus a
// binding by that key naming the KEM public key. Both limbs verify offline.
type PairedRecord struct {
	Base    succession.SuccessionRecord
	KEMAlg  string
	KEMPub  []byte
	Binding []byte
}

// VerifyPaired verifies a Variant-B record for an arbitrary third party: the base
// dual-attestation over the commitment (predecessor signature + paired-key
// possession signature) and the paired-key binding naming the KEM public key. No
// challenger secret is needed — it is publicly verifiable.
func VerifyPaired(rec PairedRecord) error {
	if err := VerifyNamesMechanism(rec.Base.Possession); err != nil {
		return err
	}
	if rec.Base.Possession.Kind != succession.ProofSuccessorSignature {
		return fmt.Errorf("%w: Variant B requires a paired-signing-key possession proof", ErrMechanismMismatch)
	}
	if err := succession.VerifyRecord(rec.Base); err != nil {
		return err
	}
	commitment, err := succession.Commit(rec.Base.Fields)
	if err != nil {
		return err
	}
	if len(rec.KEMPub) == 0 || rec.KEMAlg == "" {
		return fmt.Errorf("%w: missing KEM public key", ErrBinding)
	}
	// The paired signing key (the commitment's successor key) signs the KEM binding.
	if err := crypto.VerifyMessage(rec.Base.Fields.SuccessorPub, bindingMessage(commitment, rec.KEMAlg, rec.KEMPub), rec.Binding); err != nil {
		return fmt.Errorf("%w: %v", ErrBinding, err)
	}
	return nil
}

// --- mechanism naming (PCAS-claim-15) -------------------------------------------

// VerifyNamesMechanism enforces that a possession proof names exactly one mechanism
// and carries exactly that limb: a successor-signature proof must carry a signature
// and no transcript; a decap-transcript proof must carry a transcript and no
// signature. A record that names one but carries the other is rejected.
func VerifyNamesMechanism(p succession.PossessionProof) error {
	switch p.Kind {
	case succession.ProofSuccessorSignature:
		if len(p.Signature) == 0 {
			return fmt.Errorf("%w: names successor_signature but carries none", ErrMechanismMismatch)
		}
		if len(p.Transcript) != 0 {
			return fmt.Errorf("%w: names successor_signature but carries a decap transcript", ErrMechanismMismatch)
		}
	case succession.ProofDecapTranscript:
		if len(p.Transcript) == 0 {
			return fmt.Errorf("%w: names decap_transcript but carries none", ErrMechanismMismatch)
		}
		if len(p.Signature) != 0 {
			return fmt.Errorf("%w: names decap_transcript but carries a signature", ErrMechanismMismatch)
		}
	default:
		return fmt.Errorf("%w: unknown mechanism %q", ErrMechanismMismatch, p.Kind)
	}
	return nil
}

// PubliclyVerifiable reports whether a possession-proof mechanism can be verified by
// an arbitrary third party offline. The decap-transcript (Variant A) mechanism
// cannot; the paired-signing-key (Variant B) mechanism can.
func PubliclyVerifiable(kind succession.PossessionProofKind) bool {
	return kind == succession.ProofSuccessorSignature
}

// RequirePublicVerifiability returns ErrNotPubliclyVerif for a record whose mechanism
// is not publicly verifiable, so a policy that demands third-party offline
// verification refuses a Variant-A record.
func RequirePublicVerifiability(kind succession.PossessionProofKind) error {
	if !PubliclyVerifiable(kind) {
		return ErrNotPubliclyVerif
	}
	return nil
}

// --- predecessor-KEM chains (PCAS-claim-30) -------------------------------------

// PredecessorKEMRecord is a succession whose predecessor AND successor are KEM keys.
// Neither can sign, so both possession proofs are decap transcripts bound to the
// same commitment: the predecessor transcript against the FIRST (predecessor) public
// key, the successor transcript against the successor public key.
type PredecessorKEMRecord struct {
	Fields                succession.CommitmentFields
	PredecessorTranscript []byte // decap transcript against Fields.PredecessorPub
	SuccessorTranscript   []byte // decap transcript against Fields.SuccessorPub
}

// BuildPredecessorKEMRecord assembles a PCAS-claim-30 record binding both transcripts.
func BuildPredecessorKEMRecord(fields succession.CommitmentFields, predTr, succTr Transcript) PredecessorKEMRecord {
	return PredecessorKEMRecord{
		Fields:                fields,
		PredecessorTranscript: predTr.encode(),
		SuccessorTranscript:   succTr.encode(),
	}
}

// VerifyPredecessorKEM verifies both decap transcripts against the commitment using
// the respective challenger secrets (predecessor-first-pub and successor). Both must
// bind the same commitment (PCAS-claim-30); a missing limb is rejected.
func VerifyPredecessorKEM(rec PredecessorKEMRecord, predChallengerSecret, succChallengerSecret []byte) error {
	if len(rec.PredecessorTranscript) == 0 || len(rec.SuccessorTranscript) == 0 {
		return ErrMissingTranscripts
	}
	commitment, err := succession.Commit(rec.Fields)
	if err != nil {
		return err
	}
	predTr, err := decodeTranscript(rec.PredecessorTranscript)
	if err != nil {
		return fmt.Errorf("kem: decode predecessor transcript: %w", err)
	}
	if err := VerifyTranscript(predChallengerSecret, commitment, predTr); err != nil {
		return fmt.Errorf("predecessor: %w", err)
	}
	succTr, err := decodeTranscript(rec.SuccessorTranscript)
	if err != nil {
		return fmt.Errorf("kem: decode successor transcript: %w", err)
	}
	if err := VerifyTranscript(succChallengerSecret, commitment, succTr); err != nil {
		return fmt.Errorf("successor: %w", err)
	}
	return nil
}

// --- re-wrap gate (consumed by ee/succession/retirement, PCAS-10) ----------

// RewrapLedger reports whether data protected under an identity's predecessor KEM
// key at predecessorEpoch has been re-wrapped under the successor.
type RewrapLedger interface {
	RewrapComplete(tenantID, identityID string, predecessorEpoch uint64) (bool, error)
}

// RetirementGate returns a retirement PreRetire precondition that blocks predecessor
// retirement until re-wrap is complete (PCAS-claim-15 re-wrap-before-retire). The staged,
// resumable re-wrap job engine is PCAS-25; this is only the gate.
func RetirementGate(led RewrapLedger, tenantID, identityID string, predecessorEpoch uint64) func(context.Context) error {
	return func(context.Context) error {
		ok, err := led.RewrapComplete(tenantID, identityID, predecessorEpoch)
		if err != nil {
			return err
		}
		if !ok {
			return ErrRewrapIncomplete
		}
		return nil
	}
}

func writeField(b *bytes.Buffer, v []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(v)))
	b.Write(l[:])
	b.Write(v)
}
