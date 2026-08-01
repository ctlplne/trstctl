// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/eventspec"
)

// Ledger event types for the NHI algorithm lifecycle, carried on the AN-2 event
// log. Dotted-lowercase per repo convention (cf. "ca.authority.rekeyed").
const (
	// TypeFinding records a classification finding that an identity's credential
	// uses an out-of-policy or quantum-vulnerable algorithm (lifecycle step 2).
	TypeFinding = "nhi.crypto.finding"
	// TypeSuccession announces that a dual-signed succession record was minted,
	// advancing the identity to a new algorithm-epoch (lifecycle step 4).
	TypeSuccession = "nhi.algorithm.succession"
	// TypeRetirement records retirement of a predecessor key after a succession
	// (lifecycle step 7).
	TypeRetirement = "nhi.algorithm.retirement"
	// TypeRPAck is a signed relying-party capability acknowledgement (step 6).
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
)

// Baseline (v1) payload-shape versions for each type (SCHEMA-001). Bump the
// producer's version when a type's payload shape changes; Decode dispatches on
// (Type, SchemaVersion) and treats an unknown or newer-than-known version as a
// skip (Unknown), so replay is forward-compatible and never mis-projects.
const (
	FindingSchemaV1         = 1
	SuccessionSchemaV1      = 1
	RetirementSchemaV1      = 1
	RPAckSchemaV1           = 1
	RefusalSchemaV1         = 1
	RewrapStageSchemaV1     = 1
	RewrapCompletedSchemaV1 = 1
	MisissuanceSchemaV1     = 1
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
// AckSetDigest binds a digest of the signed relying-party acknowledgements that
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
