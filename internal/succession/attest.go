// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// attest.go carries the signer-attributable evidence bound to every succession
// record (PCAS-claims-28, 42; establishes INV-13). INV-13 is an ATTRIBUTION property, not
// a prevention one: a compromised signer can still mint, but every record it mints
// carries a countersignature that NAMES it, and the authorization under which it
// minted is verifiable from the published record — so misissuance is attributable.

const (
	attestDomain      = "trstctl/pcas/signer-attestation/v1"
	authzDigestDomain = "trstctl/pcas/authz-digest/v1"
)

// ErrSignerAttestation is returned when a record's signer attestation is missing,
// malformed, names an unknown signer, or does not verify.
var ErrSignerAttestation = errors.New("succession: signer attestation invalid or missing")

// SignerAttestationEnvelope is the minting signer's countersignature: it NAMES the
// signer (PCAS-claim-28) and carries its signature over the attested record.
type SignerAttestationEnvelope struct {
	SignerID  string `json:"signer_id"`
	Signature []byte `json:"sig"`
}

// AuthzDigest is the digest of the PCAS-claim-5 authorization artifact (a dual-control
// token), bound into a record as authz_digest (PCAS-claim-42). It is domain-separated and
// hashed through the core AN-3 boundary. An empty artifact yields a well-defined
// digest (the "no dual-control" case).
func AuthzDigest(authorizationArtifact []byte) []byte {
	var b bytes.Buffer
	writeField(&b, []byte(authzDigestDomain))
	writeField(&b, authorizationArtifact)
	return crypto.SHA256Sum(b.Bytes())
}

// attestMessage is the domain-separated message the signer attestation covers: the
// signer id, the record's commitment, and its authz_digest. Binding all three means
// the attestation names the signer and cannot be moved to another record or have its
// authz_digest swapped.
func attestMessage(rec SuccessionRecord, signerID string) ([]byte, error) {
	commitment, err := Commit(rec.Fields)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	writeField(&b, []byte(attestDomain))
	writeField(&b, []byte(signerID))
	writeField(&b, commitment)
	writeField(&b, rec.AuthzDigest)
	// Bind the record type so an exceptional record's kind (revocation / ceremony /
	// emergency, PCAS-23) is signer-attested and cannot be stripped or altered.
	writeField(&b, []byte(rec.RecordType))
	// Bind the custody attestation evidence digest + type (PCAS-claim-35, PCAS-29), so the
	// custody evidence that gated the succession is tamper-evidently part of the record.
	writeField(&b, rec.AttestationEvidenceDigest)
	writeField(&b, []byte(rec.AttestationType))
	return b.Bytes(), nil
}

// Attest countersigns rec with the minting signer's attestation key and returns the
// envelope bytes to store in rec.SignerAttestation. Set rec.AuthzDigest before
// attesting so it is bound.
func Attest(attestSigner crypto.Signer, signerID string, rec SuccessionRecord) ([]byte, error) {
	if signerID == "" {
		return nil, fmt.Errorf("succession: attestation requires a signer id")
	}
	msg, err := attestMessage(rec, signerID)
	if err != nil {
		return nil, err
	}
	sig, err := attestSigner.Sign(msg, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	return json.Marshal(SignerAttestationEnvelope{SignerID: signerID, Signature: sig})
}

// VerifyAttestation verifies rec's signer attestation against a roster of signer
// attestation keys (keyed by signer id) and returns the naming signer id (PCAS-claim-28).
func VerifyAttestation(roster map[string][]byte, rec SuccessionRecord) (string, error) {
	env, err := decodeAttestation(rec.SignerAttestation)
	if err != nil {
		return "", err
	}
	pub, ok := roster[env.SignerID]
	if !ok {
		return "", fmt.Errorf("%w: unknown signer %q", ErrSignerAttestation, env.SignerID)
	}
	msg, err := attestMessage(rec, env.SignerID)
	if err != nil {
		return "", err
	}
	if crypto.VerifyMessage(pub, msg, env.Signature) != nil {
		return "", ErrSignerAttestation
	}
	return env.SignerID, nil
}

// MintingSignerID returns the signer id a record's attestation names, without
// verifying the signature (use VerifyAttestation to verify). Used to name the minting
// signer of a misissuance-proof record (PCAS-claim-28).
func MintingSignerID(rec SuccessionRecord) (string, error) {
	env, err := decodeAttestation(rec.SignerAttestation)
	if err != nil {
		return "", err
	}
	return env.SignerID, nil
}

func decodeAttestation(b []byte) (SignerAttestationEnvelope, error) {
	if len(b) == 0 {
		return SignerAttestationEnvelope{}, ErrSignerAttestation
	}
	var env SignerAttestationEnvelope
	if err := json.Unmarshal(b, &env); err != nil || env.SignerID == "" || len(env.Signature) == 0 {
		return SignerAttestationEnvelope{}, ErrSignerAttestation
	}
	return env, nil
}

// AttestedVerify verifies both dual-attestation limbs (VerifyRecord) AND requires a
// verifying signer countersignature (INV-13): an unattested record is rejected. It
// returns the naming minting signer id.
func AttestedVerify(rec SuccessionRecord, roster map[string][]byte) (string, error) {
	if err := VerifyRecord(rec); err != nil {
		return "", err
	}
	return VerifyAttestation(roster, rec)
}

// VerifyAuthzDigest checks that a record's authz_digest is the digest of the supplied
// authorization artifact (PCAS-claim-42): a third party recomputes it from the published
// artifact.
func VerifyAuthzDigest(rec SuccessionRecord, authorizationArtifact []byte) error {
	if !bytes.Equal(rec.AuthzDigest, AuthzDigest(authorizationArtifact)) {
		return fmt.Errorf("succession: authz_digest does not match the authorization artifact")
	}
	return nil
}
