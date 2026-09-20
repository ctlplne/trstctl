// SPDX-License-Identifier: BUSL-1.1

package succession

import "trstctl.com/trstctl/internal/crypto"

// PossessionProofKind names the mechanism of the successor possession-proof limb
// (PCAS-claim-25). PCAS-04 implements the successor-signature variant; the KEM
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

// SuccessionRecord is the dual-attested succession artifact (PCAS-claim-25 genus): the
// committed fields, a predecessor attestation, and a successor possession proof,
// such that neither limb alone establishes the succession. The predecessor and
// successor public keys are named inside Fields (bound in the commitment); the
// verifier uses those, negotiating no algorithm and loading no provider.
//
// It is also the succession-record limb of the independent method claim
// (PCAS-claim-1): the committed fields, a first signature over the commitment
// generated with the predecessor private key, and a second signature over the
// commitment generated with the successor private key, such that neither
// signature alone is sufficient to establish the succession.
type SuccessionRecord struct {
	Fields         CommitmentFields
	PredecessorAtt []byte          // predecessor signature over the commitment
	Possession     PossessionProof // successor possession proof over the commitment

	// Optional fields (r11 succession-record fields). SignerAttestation is a
	// countersignature by the minting signer (populated by PCAS-05/20);
	// InclusionProof is a transparency-log inclusion proof (PCAS-06).
	SignerAttestation []byte
	InclusionProof    []byte

	// AuthzDigest is the digest of the PCAS-claim-5 dual-control authorization artifact
	// under which this record was minted (PCAS-claim-42, PCAS-20). It is bound by the
	// signer attestation, so the authorization is verifiable from the published
	// record alone.
	AuthzDigest []byte

	// BreakGlassAuth, when present, is the authority-signed, single-use break-glass
	// token that authorized a forward strength-downgrade succession (PCAS-claim-17 /
	// INV-8, PCAS-15). It is self-authenticating (verified against the break-glass
	// authority's key) and marks the record as a break-glass succession; the RP
	// requires it for any weaker-class succession.
	BreakGlassAuth []byte

	// RecordType distinguishes exceptional-but-chained records (PCAS-claims-36, 37,
	// PCAS-23): a revocation tombstone, or a ceremony / break-glass / emergency
	// record. The empty value is an ordinary succession. Exceptional records still
	// chain, stay epoch-monotonic, and require a transparency-log inclusion proof.
	RecordType RecordType

	// AttestationEvidenceDigest and AttestationType bind the successor-custodian
	// attestation evidence that gated the succession (PCAS-claim-35, PCAS-29): the signer
	// verified the evidence before generating the successor key, and bound its digest
	// + type here so the record proves what custody evidence gated it. They are bound
	// by the signer attestation (tamper-evident).
	AttestationEvidenceDigest []byte
	AttestationType           string
}

// RecordType marks an exceptional-but-chained succession record (PCAS-claims-36, 37).
type RecordType string

const (
	// RecOrdinary is an ordinary succession (the zero value).
	RecOrdinary RecordType = ""
	// RecRevocation is a revocation tombstone recorded as a chain record at the next
	// epoch; the chain itself is the revocation status (PCAS-claim-36).
	RecRevocation RecordType = "revocation"
	// RecCeremony is a break-glass / ceremony record (a PCAS-claim-17 strength downgrade or
	// an operator ceremony) recorded as a distinct chained record (PCAS-claim-37).
	RecCeremony RecordType = "ceremony"
	// RecEmergency is a control-plane-unavailable emergency issuance recorded as a
	// distinct chained record (PCAS-claim-37).
	RecEmergency RecordType = "emergency"
)

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
