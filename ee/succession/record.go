// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import "trstctl.com/trstctl/internal/crypto"

// PossessionProofKind names the mechanism of the successor possession-proof limb
// (claim 25). PCAS-04 implements the successor-signature variant; the KEM
// decapsulation-transcript and non-interactive proof-of-possession variants are
// modeled here and implemented in PCAS-14. A record names its mechanism so a
// verifier knows exactly what it is checking.
type PossessionProofKind string

const (
	ProofSuccessorSignature PossessionProofKind = "successor_signature"
	ProofDecapTranscript    PossessionProofKind = "decap_transcript"
	ProofNIZKPoP            PossessionProofKind = "nizk_pop"
)

// PossessionProof is the successor limb of the dual attestation: proof that the
// holder of the successor private key possesses it and consents to the binding.
type PossessionProof struct {
	Kind       PossessionProofKind
	Signature  []byte // ProofSuccessorSignature: signature over the commitment
	Transcript []byte // ProofDecapTranscript: challenge/response transcript (PCAS-14)
}

// SuccessionRecord is the dual-attested succession artifact (claim 25 genus): the
// committed fields, a predecessor attestation, and a successor possession proof,
// such that neither limb alone establishes the succession. The predecessor and
// successor public keys are named inside Fields (bound in the commitment); the
// verifier uses those, negotiating no algorithm and loading no provider.
type SuccessionRecord struct {
	Fields         CommitmentFields
	PredecessorAtt []byte          // predecessor signature over the commitment
	Possession     PossessionProof // successor possession proof over the commitment

	// Optional fields (r11 succession-record fields). SignerAttestation is a
	// countersignature by the minting signer (populated by PCAS-05/20);
	// InclusionProof is a transparency-log inclusion proof (PCAS-06).
	SignerAttestation []byte
	InclusionProof    []byte
}

// GenesisRecord anchors an identity's chain at epoch 0 (r11 genesis-establishment
// embodiment): the stable identity identifier, tenant, initial algorithm and
// public key, signed by a tenant trust root and attested by the signer. Relying
// parties obtain the trust-root public key out of band, exactly as trust anchors
// are obtained today.
type GenesisRecord struct {
	DeploymentScope string
	IdentityID      string
	TenantID        string
	Algorithm       crypto.Algorithm
	PublicKey       []byte // SubjectPublicKeyInfo (PKIX/DER)
	Epoch           uint64 // genesis is epoch 0

	TrustRootAtt      []byte // tenant-trust-root signature over the genesis encoding
	SignerAttestation []byte // optional signer countersignature
}
