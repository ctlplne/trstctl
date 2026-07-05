// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/events"
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
)

// Baseline (v1) payload-shape versions for each type (SCHEMA-001). Bump the
// producer's version when a type's payload shape changes; Decode dispatches on
// (Type, SchemaVersion) and treats an unknown or newer-than-known version as a
// skip (Unknown), so replay is forward-compatible and never mis-projects.
const (
	FindingSchemaV1    = 1
	SuccessionSchemaV1 = 1
	RetirementSchemaV1 = 1
	RPAckSchemaV1      = 1
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
// succession record persists as durable proof linking the epochs (claim 8).
// AckSetDigest binds a digest of the signed relying-party acknowledgements that
// satisfied the cutover quorum, so the evidence condition is itself offline
// verifiable (claim 3); it is empty for a policy-time-bound retirement embodiment.
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
func Encode(p Payload) (events.Event, error) {
	switch v := p.(type) {
	case FindingV1:
		return marshalEvent(TypeFinding, FindingSchemaV1, v.TenantID, v)
	case SuccessionV1:
		return marshalEvent(TypeSuccession, SuccessionSchemaV1, v.TenantID, v)
	case RetirementV1:
		return marshalEvent(TypeRetirement, RetirementSchemaV1, v.TenantID, v)
	case RPAckV1:
		return marshalEvent(TypeRPAck, RPAckSchemaV1, v.TenantID, v)
	default:
		return events.Event{}, fmt.Errorf("succession: cannot encode payload of type %T", p)
	}
}

func marshalEvent(typ string, ver int, tenant string, v any) (events.Event, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return events.Event{}, fmt.Errorf("succession: marshal %s: %w", typ, err)
	}
	return events.Event{Type: typ, TenantID: tenant, SchemaVersion: ver, Data: data}, nil
}

// Decode returns the typed payload for an AN-2 event. Unknown event types and
// newer-than-known schema versions of known types decode to Unknown (skip) —
// never an error and never a panic — so replay is forward-compatible and safe on
// untrusted input. A malformed payload of a known type+version is an error.
func Decode(e events.Event) (Payload, error) {
	ver := e.SchemaVersion
	if ver == 0 {
		ver = events.DefaultSchemaVersion
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
	default:
		return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
	}
}
