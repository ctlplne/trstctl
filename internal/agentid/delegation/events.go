// SPDX-License-Identifier: BUSL-1.1

package delegation

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/eventspec"
)

// Ledger event types for the AGID delegation lifecycle, carried on the AN-2 event
// log. Dotted-lowercase per repo convention (cf. "issuer.created"). This card defines
// the event TYPES and their versioned encode/decode only; the issuance / attestation
// / refusal / revocation projections and their DDL land in AGID-02.
const (
	// TypeDelegationRecorded records that a signed delegation record was appended to
	// a chain (the delegator conferred a no-broader authority set on a delegate).
	TypeDelegationRecorded = "agent.delegation.recorded"
	// TypeIssuanceRecorded records that an agent credential was issued for a subject,
	// binding a digest of the verified delegation chain. (Issuance itself, and the
	// in-signer verification that precedes it, is AGID-04; this is the ledger fact.)
	TypeIssuanceRecorded = "agent.issuance.recorded"
	// TypeRefusalRecorded records a signer's signed refusal of an issuance, naming the
	// failed check (INV-A1's signed refusal artifact is produced in AGID-04; this is
	// its ledger event type).
	TypeRefusalRecorded = "agent.refusal.recorded"
	// TypeRevocationDirective records a revocation directive against a subject and the
	// watermark of the determining projection (the cascade itself is AGID-10/11).
	TypeRevocationDirective = "agent.revocation.directive"
)

// Baseline (v1) payload-shape versions for each type (SCHEMA-001). Bump the
// producer's version when a type's payload shape changes; Decode dispatches on
// (Type, SchemaVersion) and treats an unknown or newer-than-known version as a skip
// (Unknown, carrying the raw bytes forward), so replay is forward-compatible and
// never mis-projects on untrusted or newer input.
const (
	DelegationRecordedSchemaV1  = 1
	IssuanceRecordedSchemaV1    = 1
	RefusalRecordedSchemaV1     = 1
	RevocationDirectiveSchemaV1 = 1
)

// Payload is a decoded, typed delegation-lifecycle event payload.
type Payload interface{ isDelegationPayload() }

// DelegationRecordedV1 is the ledger announcement of an appended delegation record.
// RecordDigest is an opaque reference to the record (Record.Digest); the record's
// full structure and the authority set live in the record itself, not the event.
type DelegationRecordedV1 struct {
	TenantID       string `json:"tenant_id"`
	RecordDigest   []byte `json:"record_digest,omitempty"`
	DelegatorID    string `json:"delegator_id"`
	DelegateID     string `json:"delegate_id"`
	ParentDigest   []byte `json:"parent_digest,omitempty"`
	RootAnchor     bool   `json:"root_anchor,omitempty"`
	DepthRemaining uint32 `json:"depth_remaining"`
}

func (DelegationRecordedV1) isDelegationPayload() {}

// IssuanceRecordedV1 records issuance of an agent credential bound to a chain digest.
type IssuanceRecordedV1 struct {
	TenantID         string `json:"tenant_id"`
	CredentialID     string `json:"credential_id,omitempty"`
	CredentialDigest []byte `json:"credential_digest,omitempty"`
	SubjectID        string `json:"subject_id"`
	ChainDigest      []byte `json:"chain_digest,omitempty"`
}

func (IssuanceRecordedV1) isDelegationPayload() {}

// RefusalRecordedV1 records a signer's signed refusal naming the failed check.
type RefusalRecordedV1 struct {
	TenantID      string `json:"tenant_id"`
	SubjectID     string `json:"subject_id"`
	FailedCheck   string `json:"failed_check"`
	RequestDigest []byte `json:"request_digest,omitempty"`
	Signature     []byte `json:"signature,omitempty"`
}

func (RefusalRecordedV1) isDelegationPayload() {}

// RevocationDirectiveV1 records a revocation directive and the determining watermark.
type RevocationDirectiveV1 struct {
	TenantID  string `json:"tenant_id"`
	SubjectID string `json:"subject_id"`
	Reason    string `json:"reason,omitempty"`
	Watermark uint64 `json:"watermark"`
}

func (RevocationDirectiveV1) isDelegationPayload() {}

// Unknown is returned for an event whose type is not a delegation type, or whose
// (known-type) schema version is newer than this build understands. It carries no
// projection effect; a projector skips it. This is the forward-compatible "carry"
// arm of the skip-or-carry rule — the raw payload is preserved (Raw) so a newer
// producer cannot break replay and no information is lost on an older reader.
type Unknown struct {
	Type    string
	Version int
	Raw     []byte
}

func (Unknown) isDelegationPayload() {}

// Encode marshals a typed payload into an AN-2 event envelope, stamping the type and
// baseline schema version and propagating the tenant (AN-1). ID, Time, and Sequence
// are assigned by events.Log.Append.
func Encode(p Payload) (eventspec.Event, error) {
	switch v := p.(type) {
	case DelegationRecordedV1:
		return marshalEvent(TypeDelegationRecorded, DelegationRecordedSchemaV1, v.TenantID, v)
	case IssuanceRecordedV1:
		return marshalEvent(TypeIssuanceRecorded, IssuanceRecordedSchemaV1, v.TenantID, v)
	case RefusalRecordedV1:
		return marshalEvent(TypeRefusalRecorded, RefusalRecordedSchemaV1, v.TenantID, v)
	case RevocationDirectiveV1:
		return marshalEvent(TypeRevocationDirective, RevocationDirectiveSchemaV1, v.TenantID, v)
	default:
		return eventspec.Event{}, fmt.Errorf("delegation: cannot encode payload of type %T", p)
	}
}

func marshalEvent(typ string, ver int, tenant string, v any) (eventspec.Event, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("delegation: marshal %s: %w", typ, err)
	}
	return eventspec.Event{Type: typ, TenantID: tenant, SchemaVersion: ver, Data: data}, nil
}

// Decode returns the typed payload for an AN-2 event. Unknown event types and
// newer-than-known schema versions of known types decode to Unknown (skip/carry) —
// never an error and never a panic — so replay is forward-compatible and safe on
// untrusted input. A malformed payload of a known type+version is an error.
func Decode(e eventspec.Event) (Payload, error) {
	ver := e.SchemaVersion
	if ver == 0 {
		ver = eventspec.DefaultSchemaVersion
	}
	switch e.Type {
	case TypeDelegationRecorded:
		if ver > DelegationRecordedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p DelegationRecordedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("delegation: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeIssuanceRecorded:
		if ver > IssuanceRecordedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p IssuanceRecordedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("delegation: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRefusalRecorded:
		if ver > RefusalRecordedSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RefusalRecordedV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("delegation: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	case TypeRevocationDirective:
		if ver > RevocationDirectiveSchemaV1 {
			return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
		}
		var p RevocationDirectiveV1
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return nil, fmt.Errorf("delegation: decode %s v%d: %w", e.Type, ver, err)
		}
		return p, nil
	default:
		return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
	}
}

// MemSink is an in-memory, ordered AN-2 event sink. It is NOT a durable store (the
// RLS serving copy and projections are AGID-02); it exists so a delegation-lifecycle
// event sequence can be asserted by deterministic replay in tests and offline tooling
// (mirrors the succession MemSink precedent).
type MemSink struct{ evs []eventspec.Event }

// Append records e at the tail of the sink.
func (m *MemSink) Append(e eventspec.Event) { m.evs = append(m.evs, e) }

// Events returns a copy of the recorded events, in append order.
func (m *MemSink) Events() []eventspec.Event {
	out := make([]eventspec.Event, len(m.evs))
	copy(out, m.evs)
	return out
}
