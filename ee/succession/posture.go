// SPDX-License-Identifier: LicenseRef-trstctl-EE

package succession

import (
	"fmt"

	"trstctl.com/trstctl/internal/events"
)

// State is the per-identity cryptographic-posture state (FIG. 4). It advances
// monotonically as succession events are folded and never regresses.
type State string

const (
	StateUnknown            State = ""
	StateVulnerable         State = "vulnerable"
	StateActive             State = "active"
	StateHybridActive       State = "hybrid_active"
	StatePurePQ             State = "pure_pq"
	StatePredecessorRetired State = "predecessor_retired"
)

// IdentityPosture is the current cryptographic posture of one NHI, projected
// from the succession ledger (claim 10). It is a projection only — never written
// directly (AN-2); the durable RLS serving copy is PCAS-02.
type IdentityPosture struct {
	IdentityID       string
	TenantID         string
	CurrentEpoch     uint64
	CurrentAlgorithm string
	CurrentPublicDER []byte
	State            State
}

// Posture maps a stable identity identifier to its current posture. The stable
// identity identifier is, by definition, a non-personal tenant-scoped identifier
// assigned at genesis, so it is unique across the deployment.
type Posture map[string]IdentityPosture

func stateForClass(class string) State {
	switch class {
	case ClassHybrid:
		return StateHybridActive
	case ClassPurePQ:
		return StatePurePQ
	default:
		return StateActive
	}
}

// Fold deterministically reduces an ordered event sequence to the per-identity
// crypto-posture projection (claim 10 / INV-10). It is:
//
//   - deterministic: the output depends only on the event sequence;
//   - idempotent and at-least-once safe (INV-4): re-delivering an event, or
//     replaying the whole sequence, yields the same posture, because posture
//     advances only on a strictly greater algorithm-epoch and every state write
//     is idempotent;
//   - forward-compatible: unknown event types and newer-than-known schema
//     versions are skipped (see Decode).
//
// A malformed payload of a known type+version is a corruption error and fails
// the fold closed rather than being silently dropped.
func Fold(seq []events.Event) (Posture, error) {
	p := make(Posture)
	for i, e := range seq {
		pl, err := Decode(e)
		if err != nil {
			return nil, fmt.Errorf("succession: fold event %d (%s): %w", i, e.Type, err)
		}
		switch v := pl.(type) {
		case FindingV1:
			cur, ok := p[v.IdentityID]
			if !ok {
				// Seed posture at the observed vulnerable credential.
				p[v.IdentityID] = IdentityPosture{
					IdentityID:       v.IdentityID,
					TenantID:         v.TenantID,
					CurrentEpoch:     v.Epoch,
					CurrentAlgorithm: v.Algorithm,
					CurrentPublicDER: v.PublicKeyDER,
					State:            StateVulnerable,
				}
			} else if cur.State == StateUnknown {
				cur.State = StateVulnerable
				p[v.IdentityID] = cur
			}
			// A finding never regresses an already-succeeded identity.
		case SuccessionV1:
			cur, ok := p[v.IdentityID]
			if !ok || v.Epoch > cur.CurrentEpoch {
				p[v.IdentityID] = IdentityPosture{
					IdentityID:       v.IdentityID,
					TenantID:         v.TenantID,
					CurrentEpoch:     v.Epoch,
					CurrentAlgorithm: v.SuccessorAlgorithm,
					CurrentPublicDER: v.SuccessorPublicKeyDER,
					State:            stateForClass(v.AlgorithmClass),
				}
			}
			// Epoch <= current is ignored: duplicate delivery / stale replay.
		case RetirementV1:
			if cur, ok := p[v.IdentityID]; ok && v.Epoch >= 1 && cur.CurrentEpoch >= v.Epoch {
				cur.State = StatePredecessorRetired
				p[v.IdentityID] = cur
			}
		case RPAckV1, Unknown:
			// No posture effect: acks are cutover evidence (PCAS-10); Unknown is
			// a skipped forward-compatible event.
		}
	}
	return p, nil
}

// Source is anything that yields an ordered AN-2 event sequence for replay.
type Source interface{ Events() []events.Event }

// Replay folds every event yielded by src, in order, into the posture
// projection. It is a thin convenience over Fold that reads from a Source.
func Replay(src Source) (Posture, error) {
	return Fold(src.Events())
}

// MemSink is an in-memory, ordered AN-2 event sink. It is NOT a durable store
// (PCAS-02 provides the serving copy); it exists so a posture projection can be
// asserted by deterministic replay in tests and offline tooling.
type MemSink struct{ evs []events.Event }

// Append records e at the tail of the sink.
func (m *MemSink) Append(e events.Event) { m.evs = append(m.evs, e) }

// Events returns a copy of the recorded events, in append order.
func (m *MemSink) Events() []events.Event {
	out := make([]events.Event, len(m.evs))
	copy(out, m.evs)
	return out
}
