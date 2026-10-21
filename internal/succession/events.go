// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/eventspec"
)

// Ledger event types for the NHI algorithm lifecycle, carried on the AN-2 event
// log. Dotted-lowercase per repo convention (cf. "ca.authority.rekeyed").
const (
	// TypeGenesis binds the first signer-held key to its tenant trust root.
	TypeGenesis = "nhi.algorithm.genesis"
	// TypeFinding records a classification finding that an identity's credential
	// uses an out-of-policy or quantum-vulnerable algorithm (lifecycle step 2).
	TypeFinding = "nhi.crypto.finding"
	// TypeSuccession announces that a dual-signed succession record was minted,
	// advancing the identity to a new algorithm-epoch (lifecycle step 4).
	TypeSuccession = "nhi.algorithm.succession"
	// TypeRetirement records retirement of a predecessor key after a succession
	// (lifecycle step 7).
	TypeRetirement = "nhi.algorithm.retirement"
	// TypeRPAck is a signed relying-party capability acknowledgment (step 6).
	TypeRPAck = "nhi.rp.ack"
	// TypeRefusal records a signer's signed refusal of a mint (PCAS-claim-41, PCAS-20):
	// the refused request and the violated constraint, attributable to the signer.
	TypeRefusal = "nhi.algorithm.refusal"
	// TypeRewrapStage records completion of one bounded, health-verified re-wrap stage
	// (PCAS-claim-39, PCAS-25).
	TypeRewrapStage = "nhi.rewrap.stage"
	// TypeRewrapCompleted records that all re-wrap stages for a predecessor completed;
	// the predecessor's retirement condition consumes this event (PCAS-claim-39).
	TypeRewrapCompleted = "nhi.rewrap.completed"
	// TypeMisissuance records a detected algorithm-epoch equivocation: two distinct
	// dual-signed records for one identity at the same epoch (PCAS-claims-11, 28). A monitor
	// emits it, binding both record commitments and the named minting signers, so the
	// misissuance is durable and attributable on the ledger.
	TypeMisissuance = "nhi.algorithm.misissuance"
	// TypeDelegationApplied records the isolated signer's signed state readback.
	TypeDelegationApplied = "nhi.delegation.applied"
	// TypeRecoveryPolicyConfigured records public, tenant-bound recovery authority.
	TypeRecoveryPolicyConfigured = "nhi.recovery.policy.configured"
	// TypeRecoverySuccessorPrepared records a signer-held key before custodians
	// sign a recovery statement naming that exact public key.
	TypeRecoverySuccessorPrepared = "nhi.recovery.successor.prepared"
	// TypeRecoveryRecorded is the immutable source for one threshold-recovery
	// record. The SQL chain row and high-water are projections of this event.
	TypeRecoveryRecorded = "nhi.recovery.recorded"
	// TypeRecoveryProofIssued binds a record's commitment to a signer-signed
	// append-only per-identity recovery log before the worker reports delivery.
	TypeRecoveryProofIssued = "nhi.recovery.proof.issued"
	// TypeKEMRewrapRecorded is the immutable source for the signed paired KEM
	// record; SQL chain and high-water rows are rebuildable projections.
	TypeKEMRewrapRecorded = "nhi.kem.rewrap.recorded"
	// TypeKEMRewrapRequested records the accepted outbox intent and stage names.
	// Its projection gives queued jobs a replayable source before completion.
	TypeKEMRewrapRequested = "nhi.kem.rewrap.requested"
	// TypeKEMDataKeyRegistered records one KEM-wrapped data key registered for
	// an identity epoch (A16). The row in pcas_kem_data_key is its projection.
	TypeKEMDataKeyRegistered = "nhi.kem.data_key.registered"
	// TypeKEMDataKeyRewrapped is the per-target receipt of a signer-held
	// re-wrap: the successor envelope, its readback digest, and the request,
	// epochs and digests it is bound to.
	TypeKEMDataKeyRewrapped = "nhi.kem.data_key.rewrapped"
	// TypeKEMRewrapStageCompleted closes one stage of a re-wrap request over the
	// fenced predecessor-epoch inventory; the job row's data receipt is its
	// projection and the retirement gate reads it.
	TypeKEMRewrapStageCompleted = "nhi.kem.rewrap.stage_completed"
	// TypeIssuerAuthorityRegistered binds a tenant's managed CA to one PCAS epoch.
	TypeIssuerAuthorityRegistered = "nhi.issuer.authority.registered"
	// TypeFederationBridgeImported records a verified, locally signed foreign trust bridge.
	TypeFederationBridgeImported = "nhi.federation.bridge.imported"
)

// Baseline (v1) payload-shape versions for each type (SCHEMA-001). Bump the
// producer's version when a type's payload shape changes; Decode dispatches on
// (Type, SchemaVersion) and treats an unknown or newer-than-known version as a
// skip (Unknown), so replay is forward-compatible and never mis-projects.
const (
	GenesisSchemaV1                   = 1
	FindingSchemaV1                   = 1
	SuccessionSchemaV1                = 1
	RetirementSchemaV1                = 1
	RPAckSchemaV1                     = 1
	RefusalSchemaV1                   = 1
	RewrapStageSchemaV1               = 1
	RewrapCompletedSchemaV1           = 1
	MisissuanceSchemaV1               = 1
	DelegationAppliedSchemaV1         = 1
	RecoveryPolicyConfiguredSchemaV1  = 1
	RecoverySuccessorPreparedSchemaV1 = 1
	RecoveryRecordedSchemaV1          = 1
	RecoveryProofIssuedSchemaV1       = 1
	KEMRewrapRecordedSchemaV1         = 1
	KEMRewrapRequestedSchemaV1        = 1
	KEMDataKeyRegisteredSchemaV1      = 1
	KEMDataKeyRewrappedSchemaV1       = 1
	KEMRewrapStageCompletedSchemaV1   = 1
	IssuerAuthorityRegisteredSchemaV1 = 1
	FederationBridgeImportedSchemaV1  = 1
)

// Coarse algorithm-class hints carried on a succession event for posture only.
// The enforceable partial order over classes (strength-ordered succession) is
// out of scope here and lives in PCAS-15 / INV-8; these strings drive nothing
// but the projected posture state.
const (
	ClassClassical = "classical"
	ClassHybrid    = "hybrid"
	ClassPurePQ    = "pure_pq"
)

// Payload is a decoded, typed succession-lifecycle event payload.
type Payload interface{ isSuccessionPayload() }

// GenesisV1 is the immutable public anchor for a newly registered identity.
// The trust-root signature is part of the evidence and must never be rewritten.
type GenesisV1 struct {
	RequestID          string `json:"request_id"`
	IdentityID         string `json:"identity_id"`
	TenantID           string `json:"tenant_id"`
	DeploymentScope    string `json:"deployment_scope"`
	Algorithm          string `json:"algorithm"`
	PublicKeyDER       []byte `json:"public_key_der"`
	Epoch              uint64 `json:"epoch"`
	TrustRootAtt       []byte `json:"trust_root_att"`
	TrustRootPublicDER []byte `json:"trust_root_public_der"`
	PredecessorCustody string `json:"predecessor_custody,omitempty"`
}

// DelegationAppliedV1 carries signed public signer state; the serving table is
// rebuilt from this immutable evidence after a projection crash.
type DelegationAppliedV1 struct {
	TenantID    string `json:"tenant_id"`
	ReceiptJSON []byte `json:"receipt_json"`
}

func (DelegationAppliedV1) isSuccessionPayload() {}

// RecoveryPolicyConfiguredV1 is the public recovery policy source event. A
// projected policy can be rebuilt from this event after a read-model reset.
type RecoveryPolicyConfiguredV1 struct {
	TenantID     string          `json:"tenant_id"`
	IdentityID   string          `json:"identity_id"`
	Threshold    int             `json:"threshold"`
	Roster       json.RawMessage `json:"roster"`
	TrustRootDER []byte          `json:"trust_root_der"`
}

func (RecoveryPolicyConfiguredV1) isSuccessionPayload() {}

// RecoverySuccessorPreparedV1 is public, signer-signed custody evidence. The
// private successor key stays inside the isolated signer process.
type RecoverySuccessorPreparedV1 struct {
	TenantID        string `json:"tenant_id"`
	IdentityID      string `json:"identity_id"`
	Epoch           uint64 `json:"epoch"`
	Algorithm       string `json:"algorithm"`
	Handle          string `json:"handle"`
	PublicKeyDER    []byte `json:"public_key_der"`
	DeploymentScope string `json:"deployment_scope"`
	RequestID       string `json:"request_id"`
	SignerSignature []byte `json:"signer_signature"`
}

func (RecoverySuccessorPreparedV1) isSuccessionPayload() {}

// KEMRewrapRecordedV1 binds one signer-verified paired record to its exact
// tenant identity epoch and outbox request before any serving-row update.
type KEMRewrapRecordedV1 struct {
	TenantID      string   `json:"tenant_id"`
	IdentityID    string   `json:"identity_id"`
	Epoch         uint64   `json:"epoch"`
	RequestID     string   `json:"request_id"`
	RequestDigest []byte   `json:"request_digest"`
	RecordJSON    []byte   `json:"record_json"`
	Stages        []string `json:"stages"`
}

func (KEMRewrapRecordedV1) isSuccessionPayload() {}

type KEMRewrapRequestedV1 struct {
	TenantID         string   `json:"tenant_id"`
	IdentityID       string   `json:"identity_id"`
	PredecessorEpoch uint64   `json:"predecessor_epoch"`
	RequestID        string   `json:"request_id"`
	RequestDigest    []byte   `json:"request_digest"`
	Stages           []string `json:"stages"`
	// InventorySequence snapshots the predecessor epoch's data-key inventory
	// at acceptance (the highest registration source sequence); the request
	// moves exactly the envelopes registered up to it. EmptyInventoryAttested
	// lets a stage with no envelopes complete: without it a stage that would
	// move nothing stays key_ready rather than reading as migrated (A16).
	InventorySequence      uint64 `json:"inventory_sequence,omitempty"`
	EmptyInventoryAttested bool   `json:"empty_inventory_attested,omitempty"`
}

func (KEMRewrapRequestedV1) isSuccessionPayload() {}

// KEMDataKeyRegisteredV1 is one data-key envelope registered for an identity
// epoch. It carries ciphertext only: the KEM ciphertext for the epoch's public
// key and the data key sealed under the derived key.
type KEMDataKeyRegisteredV1 struct {
	TenantID      string `json:"tenant_id"`
	IdentityID    string `json:"identity_id"`
	Epoch         uint64 `json:"epoch"`
	TargetRef     string `json:"target_ref"`
	Stage         string `json:"stage"`
	KEMCiphertext []byte `json:"kem_ciphertext"`
	WrappedDEK    []byte `json:"wrapped_dek"`
	DEKSHA256     []byte `json:"dek_sha256"`
}

func (KEMDataKeyRegisteredV1) isSuccessionPayload() {}

// KEMDataKeyRewrappedV1 is the receipt for one target: the successor envelope
// the signer produced, the digest the signer read back under the successor key,
// and the request, epochs and predecessor ciphertext digest it is bound to.
type KEMDataKeyRewrappedV1 struct {
	TenantID                    string `json:"tenant_id"`
	IdentityID                  string `json:"identity_id"`
	PredecessorEpoch            uint64 `json:"predecessor_epoch"`
	Epoch                       uint64 `json:"epoch"`
	TargetRef                   string `json:"target_ref"`
	Stage                       string `json:"stage"`
	RequestID                   string `json:"request_id"`
	RequestDigest               []byte `json:"request_digest"`
	PredecessorCiphertextSHA256 []byte `json:"predecessor_ciphertext_sha256"`
	KEMCiphertext               []byte `json:"kem_ciphertext"`
	WrappedDEK                  []byte `json:"wrapped_dek"`
	DEKSHA256                   []byte `json:"dek_sha256"`
	ReadbackDEKSHA256           []byte `json:"readback_dek_sha256"`
}

func (KEMDataKeyRewrappedV1) isSuccessionPayload() {}

// KEMRewrapStageCompletedV1 closes one stage: every data key the stage held at
// the predecessor epoch has a read-back successor row. ReceiptsSHA256 commits
// to the ordered per-target receipts.
type KEMRewrapStageCompletedV1 struct {
	TenantID         string `json:"tenant_id"`
	IdentityID       string `json:"identity_id"`
	PredecessorEpoch uint64 `json:"predecessor_epoch"`
	Epoch            uint64 `json:"epoch"`
	RequestID        string `json:"request_id"`
	RequestDigest    []byte `json:"request_digest"`
	Stage            string `json:"stage"`
	TargetCount      int    `json:"target_count"`
	ReceiptsSHA256   []byte `json:"receipts_sha256"`
}

func (KEMRewrapStageCompletedV1) isSuccessionPayload() {}

// RecoveryRecordedV1 keeps the exact signed record and the public verification
// root in the source log. RequestID and epoch are first-writer bound; neither a
// retry nor a different request can replace an accepted recovery record.
type RecoveryRecordedV1 struct {
	TenantID      string `json:"tenant_id"`
	IdentityID    string `json:"identity_id"`
	Epoch         uint64 `json:"epoch"`
	RequestID     string `json:"request_id"`
	RequestDigest []byte `json:"request_digest"`
	TrustRootDER  []byte `json:"trust_root_der"`
	RecordJSON    []byte `json:"record_json"`
}

func (RecoveryRecordedV1) isSuccessionPayload() {}

// RecoveryProofIssuedV1 is a separately durable result of transparency
// inclusion. The predecessor record event stays immutable; replay applies the
// first proof event to its serving copy after validating the signed tree head.
type RecoveryProofIssuedV1 struct {
	TenantID        string `json:"tenant_id"`
	IdentityID      string `json:"identity_id"`
	Epoch           uint64 `json:"epoch"`
	RequestID       string `json:"request_id"`
	RecordEventID   string `json:"record_event_id"`
	LogPublicKeyDER []byte `json:"log_public_key_der"`
	ProofBytes      []byte `json:"proof_bytes"`
}

func (RecoveryProofIssuedV1) isSuccessionPayload() {}

// IssuerAuthorityRegisteredV1 is public CA and signer-handle metadata. The
// isolated signer retains the private key; replay rebuilds only this serving
// registration from the immutable tenant-bound source event.
type IssuerAuthorityRegisteredV1 struct {
	TenantID     string `json:"tenant_id"`
	IssuerID     string `json:"issuer_id"`
	IdentityID   string `json:"identity_id"`
	CurrentEpoch uint64 `json:"current_epoch"`
	CAKeyHandle  string `json:"ca_key_handle"`
	CACertDER    []byte `json:"ca_cert_der"`
}

func (IssuerAuthorityRegisteredV1) isSuccessionPayload() {}

// FederationBridgeImportedV1 contains only public proof. RequestDigest binds
// crash retries to the exact import command that produced the signed bridge.
type FederationBridgeImportedV1 struct {
	TenantID                string          `json:"tenant_id"`
	RequestID               string          `json:"request_id"`
	RequestDigest           []byte          `json:"request_digest"`
	ForeignDeploymentID     string          `json:"foreign_deployment_id"`
	LocalDeploymentID       string          `json:"local_deployment_id"`
	IdentityID              string          `json:"identity_id"`
	ForeignTrustRootDER     []byte          `json:"foreign_trust_root_der"`
	LocalAuthorityPublicDER []byte          `json:"local_authority_public_der"`
	LocalBaseEpoch          uint64          `json:"local_base_epoch"`
	Bridge                  json.RawMessage `json:"bridge"`
}

func (FederationBridgeImportedV1) isSuccessionPayload() {}

func (GenesisV1) isSuccessionPayload() {}

// FindingV1 seeds posture at an observed (pre-succession) credential.
type FindingV1 struct {
	IdentityID   string `json:"identity_id"`
	TenantID     string `json:"tenant_id"`
	Epoch        uint64 `json:"epoch"` // observed algorithm-epoch (genesis is 0)
	Algorithm    string `json:"algorithm"`
	PublicKeyDER []byte `json:"public_key_der,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

func (FindingV1) isSuccessionPayload() {}

// SuccessionV1 is the ledger announcement of a minted succession. The
// cryptographic record itself is defined by PCAS-04; RecordDigest is an opaque
// reference to it so PCAS-01 stays free of crypto.
type SuccessionV1 struct {
	IdentityID              string `json:"identity_id"`
	TenantID                string `json:"tenant_id"`
	PredecessorEpoch        uint64 `json:"predecessor_epoch"`
	Epoch                   uint64 `json:"epoch"`
	PredecessorAlgorithm    string `json:"predecessor_algorithm,omitempty"`
	PredecessorPublicKeyDER []byte `json:"predecessor_public_key_der,omitempty"`
	SuccessorAlgorithm      string `json:"successor_algorithm"`
	SuccessorPublicKeyDER   []byte `json:"successor_public_key_der,omitempty"`
	PolicyRef               string `json:"policy_ref,omitempty"`
	AlgorithmClass          string `json:"algorithm_class,omitempty"`
	RecordDigest            []byte `json:"record_digest,omitempty"`
}

func (SuccessionV1) isSuccessionPayload() {}

// RetirementV1 records retirement of the predecessor at a given epoch. The
// succession record persists as durable proof linking the epochs (PCAS-claim-8).
// AckSetDigest binds a digest of the signed relying-party acknowledgments that
// satisfied the cutover quorum, so the evidence condition is itself offline
// verifiable (PCAS-claim-3); it is empty for a policy-time-bound retirement embodiment.
type RetirementV1 struct {
	IdentityID    string `json:"identity_id"`
	TenantID      string `json:"tenant_id"`
	Epoch         uint64 `json:"epoch"`
	RetiredAlg    string `json:"retired_algorithm,omitempty"`
	SuccessionRef []byte `json:"succession_ref,omitempty"`
	AckSetDigest  []byte `json:"ack_set_digest,omitempty"`
}

func (RetirementV1) isSuccessionPayload() {}

// RPAckV1 is evidence for evidence-gated cutover (PCAS-10) and does not itself
// change posture.
type RPAckV1 struct {
	IdentityID   string `json:"identity_id"`
	TenantID     string `json:"tenant_id"`
	Epoch        uint64 `json:"epoch"`
	RelyingParty string `json:"relying_party"`
	AckSignature []byte `json:"ack_signature,omitempty"`
}

func (RPAckV1) isSuccessionPayload() {}

// RefusalV1 records a signer's signed refusal of a mint (PCAS-claim-41, PCAS-20). It
// carries the refusal artifact so a verifier can attribute the refusal to the signer.
type RefusalV1 struct {
	IdentityID    string `json:"identity_id"`
	TenantID      string `json:"tenant_id"`
	SignerID      string `json:"signer_id"`
	Constraint    string `json:"constraint"`
	RequestDigest []byte `json:"request_digest,omitempty"`
	IssuedAt      int64  `json:"issued_at"`
	Signature     []byte `json:"signature,omitempty"`
}

func (RefusalV1) isSuccessionPayload() {}

// RewrapStageV1 records completion of one re-wrap stage (PCAS-claim-39, PCAS-25).
type RewrapStageV1 struct {
	JobID            string `json:"job_id"`
	IdentityID       string `json:"identity_id"`
	TenantID         string `json:"tenant_id"`
	PredecessorEpoch uint64 `json:"predecessor_epoch"`
	StageID          string `json:"stage_id"`
}

func (RewrapStageV1) isSuccessionPayload() {}

// RewrapCompletedV1 records that all re-wrap stages completed for a predecessor; the
// retirement condition requires it for KEM/confidentiality credentials (PCAS-claim-39).
type RewrapCompletedV1 struct {
	JobID            string `json:"job_id"`
	IdentityID       string `json:"identity_id"`
	TenantID         string `json:"tenant_id"`
	PredecessorEpoch uint64 `json:"predecessor_epoch"`
	Stages           int    `json:"stages"`
}

func (RewrapCompletedV1) isSuccessionPayload() {}

// MisissuanceV1 records a detected algorithm-epoch equivocation (PCAS-claims-11, 28): two
// distinct dual-signed records for one identity at the same epoch. It binds both
// record commitments and, when the records carry verifiable signer attestations, the
// named minting signers — so the misissuance is durable and attributable from the
// ledger event alone (the self-contained proof re-derives from the two records).
type MisissuanceV1 struct {
	IdentityID    string `json:"identity_id"`
	TenantID      string `json:"tenant_id"`
	Epoch         uint64 `json:"epoch"`
	RecordADigest []byte `json:"record_a_digest,omitempty"`
	RecordBDigest []byte `json:"record_b_digest,omitempty"`
	SignerA       string `json:"signer_a,omitempty"`
	SignerB       string `json:"signer_b,omitempty"`
}

func (MisissuanceV1) isSuccessionPayload() {}

// Unknown is returned for an event whose type is not a succession type, or whose
// (known-type) schema version is newer than this build understands. It carries
// no posture effect; the fold skips it. This is the forward-compatible "skip"
// arm of the skip-or-carry rule: a newer producer cannot break replay.
type Unknown struct {
	Type    string
	Version int
	Raw     []byte
}

func (Unknown) isSuccessionPayload() {}

// Encode marshals a typed payload into an AN-2 event envelope, stamping the type
// and baseline schema version and propagating the tenant (AN-1). ID, Time, and
// Sequence are assigned by events.Log.Append.
func Encode(p Payload) (eventspec.Event, error) {
	switch v := p.(type) {
	case GenesisV1:
		return marshalEvent(TypeGenesis, GenesisSchemaV1, v.TenantID, v)
	case DelegationAppliedV1:
		return marshalEvent(TypeDelegationApplied, DelegationAppliedSchemaV1, v.TenantID, v)
	case RecoveryPolicyConfiguredV1:
		return marshalEvent(TypeRecoveryPolicyConfigured, RecoveryPolicyConfiguredSchemaV1, v.TenantID, v)
	case RecoverySuccessorPreparedV1:
		return marshalEvent(TypeRecoverySuccessorPrepared, RecoverySuccessorPreparedSchemaV1, v.TenantID, v)
	case RecoveryRecordedV1:
		return marshalEvent(TypeRecoveryRecorded, RecoveryRecordedSchemaV1, v.TenantID, v)
	case RecoveryProofIssuedV1:
		return marshalEvent(TypeRecoveryProofIssued, RecoveryProofIssuedSchemaV1, v.TenantID, v)
	case KEMRewrapRecordedV1:
		return marshalEvent(TypeKEMRewrapRecorded, KEMRewrapRecordedSchemaV1, v.TenantID, v)
	case KEMRewrapRequestedV1:
		return marshalEvent(TypeKEMRewrapRequested, KEMRewrapRequestedSchemaV1, v.TenantID, v)
	case KEMDataKeyRegisteredV1:
		return marshalEvent(TypeKEMDataKeyRegistered, KEMDataKeyRegisteredSchemaV1, v.TenantID, v)
	case KEMDataKeyRewrappedV1:
		return marshalEvent(TypeKEMDataKeyRewrapped, KEMDataKeyRewrappedSchemaV1, v.TenantID, v)
	case KEMRewrapStageCompletedV1:
		return marshalEvent(TypeKEMRewrapStageCompleted, KEMRewrapStageCompletedSchemaV1, v.TenantID, v)
	case IssuerAuthorityRegisteredV1:
		return marshalEvent(TypeIssuerAuthorityRegistered, IssuerAuthorityRegisteredSchemaV1, v.TenantID, v)
	case FederationBridgeImportedV1:
		return marshalEvent(TypeFederationBridgeImported, FederationBridgeImportedSchemaV1, v.TenantID, v)
	case FindingV1:
		return marshalEvent(TypeFinding, FindingSchemaV1, v.TenantID, v)
	case SuccessionV1:
		return marshalEvent(TypeSuccession, SuccessionSchemaV1, v.TenantID, v)
	case RetirementV1:
		return marshalEvent(TypeRetirement, RetirementSchemaV1, v.TenantID, v)
	case RPAckV1:
		return marshalEvent(TypeRPAck, RPAckSchemaV1, v.TenantID, v)
	case RefusalV1:
		return marshalEvent(TypeRefusal, RefusalSchemaV1, v.TenantID, v)
	case RewrapStageV1:
		return marshalEvent(TypeRewrapStage, RewrapStageSchemaV1, v.TenantID, v)
	case RewrapCompletedV1:
		return marshalEvent(TypeRewrapCompleted, RewrapCompletedSchemaV1, v.TenantID, v)
	case MisissuanceV1:
		return marshalEvent(TypeMisissuance, MisissuanceSchemaV1, v.TenantID, v)
	default:
		return eventspec.Event{}, fmt.Errorf("succession: cannot encode payload of type %T", p)
	}
}

func marshalEvent(typ string, ver int, tenant string, v any) (eventspec.Event, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("succession: marshal %s: %w", typ, err)
	}
	return eventspec.Event{Type: typ, TenantID: tenant, SchemaVersion: ver, Data: data}, nil
}

// Decode returns the typed payload for an AN-2 event. Unknown event types and
// newer-than-known schema versions of known types decode to Unknown (skip) —
// never an error and never a panic — so replay is forward-compatible and safe on
// untrusted input. A malformed payload of a known type+version is an error.
func Decode(e eventspec.Event) (Payload, error) {
	ver := e.SchemaVersion
	if ver == 0 {
		ver = eventspec.DefaultSchemaVersion
	}
	switch e.Type {
	case TypeGenesis:
		if ver > GenesisSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p GenesisV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeDelegationApplied:
		if ver > DelegationAppliedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p DelegationAppliedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRecoveryPolicyConfigured:
		if ver > RecoveryPolicyConfiguredSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RecoveryPolicyConfiguredV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRecoverySuccessorPrepared:
		if ver > RecoverySuccessorPreparedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RecoverySuccessorPreparedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRecoveryRecorded:
		if ver > RecoveryRecordedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RecoveryRecordedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRecoveryProofIssued:
		if ver > RecoveryProofIssuedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RecoveryProofIssuedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeKEMRewrapRecorded:
		if ver > KEMRewrapRecordedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p KEMRewrapRecordedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeKEMRewrapRequested:
		if ver > KEMRewrapRequestedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p KEMRewrapRequestedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeKEMDataKeyRegistered:
		if ver > KEMDataKeyRegisteredSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p KEMDataKeyRegisteredV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeKEMDataKeyRewrapped:
		if ver > KEMDataKeyRewrappedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p KEMDataKeyRewrappedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeKEMRewrapStageCompleted:
		if ver > KEMRewrapStageCompletedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p KEMRewrapStageCompletedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeIssuerAuthorityRegistered:
		if ver > IssuerAuthorityRegisteredSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p IssuerAuthorityRegisteredV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeFederationBridgeImported:
		if ver > FederationBridgeImportedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p FederationBridgeImportedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeFinding:
		if ver > FindingSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p FindingV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeSuccession:
		if ver > SuccessionSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p SuccessionV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRetirement:
		if ver > RetirementSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RetirementV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRPAck:
		if ver > RPAckSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RPAckV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRefusal:
		if ver > RefusalSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RefusalV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRewrapStage:
		if ver > RewrapStageSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RewrapStageV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRewrapCompleted:
		if ver > RewrapCompletedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RewrapCompletedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeMisissuance:
		if ver > MisissuanceSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p MisissuanceV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("succession: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	default:
		return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
	}
}
