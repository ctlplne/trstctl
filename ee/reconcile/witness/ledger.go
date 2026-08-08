// SPDX-License-Identifier: LicenseRef-trstctl-EE

package witness

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"trstctl.com/trstctl/ee/reconcile/digest"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/idem"
)

const (
	EventTypeWitnessRecorded      = "xrec.witness.recorded"
	EventTypeWitnessCountersigned = "xrec.witness.countersigned"
	EventTypeWitnessDisputed      = "xrec.witness.disputed"
)

type EventAppender interface {
	Append(context.Context, eventspec.Event) (eventspec.Event, error)
}

type Recorder struct {
	log  EventAppender
	idem idem.Idempotencer
}

type WitnessRecorded struct {
	WitnessID   string   `json:"witness_id"`
	TenantID    string   `json:"tenant_id"`
	RoundID     string   `json:"round_id"`
	WitnessHash string   `json:"witness_hash"`
	Authorities []string `json:"authorities"`
	Evidence    Evidence `json:"evidence"`
	// Digests are the full signed state digests the witness's DigestRefs point
	// at (epic C4). The evidence alone carries only digest hashes and
	// signatures; VerifyOffline needs the signed bodies to re-derive them. With
	// the digests ON the recorded event, the ledger event is the complete
	// offline verification input — no callback to either authority, and no
	// separate digest store that could diverge from the witness (XREC-claim-15).
	Digests []digest.SignedDigest `json:"digests,omitempty"`
}

type WitnessCountersigned struct {
	WitnessID   string           `json:"witness_id"`
	TenantID    string           `json:"tenant_id"`
	AuthorityID string           `json:"authority_id"`
	ContentHash string           `json:"content_hash"`
	Countersign WitnessSignature `json:"countersign"`
}

type WitnessDisputed struct {
	WitnessID   string        `json:"witness_id"`
	TenantID    string        `json:"tenant_id"`
	AuthorityID string        `json:"authority_id"`
	Reason      string        `json:"reason"`
	Dispute     DisputeRecord `json:"dispute"`
}

type LedgerState struct {
	WitnessID       string
	Recorded        bool
	Evidence        *Evidence
	CountersignedBy map[string]*WitnessSignature
	DisputedBy      map[string]*DisputeRecord
}

func NewRecorder(log EventAppender, idempotencer idem.Idempotencer) *Recorder {
	return &Recorder{log: log, idem: idempotencer}
}

// RecordWitness appends the witness-recorded event. Together with the
// countersigned and disputed events it forms the XREC ledger vocabulary the
// drift projection is rebuilt from (XREC-claim-19). Pass the round's signed
// digests so the event carries the complete offline verification input.
func (r *Recorder) RecordWitness(ctx context.Context, idempotencyKey string, evidence Evidence, digests ...digest.SignedDigest) (eventspec.Event, error) {
	if err := evidence.validateShape(); err != nil {
		return eventspec.Event{}, err
	}
	payload := WitnessRecorded{
		WitnessID:   evidence.Body.WitnessID,
		TenantID:    evidence.Body.TenantID,
		RoundID:     evidence.Body.RoundID,
		WitnessHash: hex.EncodeToString(evidence.ContentHash()),
		Authorities: evidenceAuthorities(evidence),
		Evidence:    evidence,
		Digests:     digests,
	}
	return r.append(ctx, idempotencyKey, EventTypeWitnessRecorded, evidence.Body.TenantID, payload)
}

func (r *Recorder) RecordCountersign(ctx context.Context, idempotencyKey string, evidence Evidence, sig WitnessSignature) (eventspec.Event, error) {
	if err := evidence.validateShape(); err != nil {
		return eventspec.Event{}, err
	}
	if sig.WitnessID != evidence.Body.WitnessID || sig.AuthorityID == "" {
		return eventspec.Event{}, ErrInvalidWitness
	}
	payload := WitnessCountersigned{
		WitnessID:   evidence.Body.WitnessID,
		TenantID:    evidence.Body.TenantID,
		AuthorityID: sig.AuthorityID,
		ContentHash: hex.EncodeToString(sig.ContentHash),
		Countersign: sig,
	}
	return r.append(ctx, idempotencyKey, EventTypeWitnessCountersigned, evidence.Body.TenantID, payload)
}

func (r *Recorder) RecordDispute(ctx context.Context, idempotencyKey string, evidence Evidence, dispute DisputeRecord) (eventspec.Event, error) {
	if err := evidence.validateShape(); err != nil {
		return eventspec.Event{}, err
	}
	if dispute.WitnessID != evidence.Body.WitnessID || dispute.AuthorityID == "" {
		return eventspec.Event{}, ErrInvalidWitness
	}
	payload := WitnessDisputed{
		WitnessID:   evidence.Body.WitnessID,
		TenantID:    evidence.Body.TenantID,
		AuthorityID: dispute.AuthorityID,
		Reason:      dispute.Reason,
		Dispute:     dispute,
	}
	return r.append(ctx, idempotencyKey, EventTypeWitnessDisputed, evidence.Body.TenantID, payload)
}

func (r *Recorder) append(ctx context.Context, key, typ, tenantID string, payload any) (eventspec.Event, error) {
	if r == nil || r.log == nil || strings.TrimSpace(key) == "" {
		return eventspec.Event{}, ErrInvalidWitness
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return eventspec.Event{}, err
	}
	run := func(runCtx context.Context) ([]byte, error) {
		ev, err := r.log.Append(runCtx, eventspec.Event{
			Type:          typ,
			TenantID:      tenantID,
			SchemaVersion: eventspec.DefaultSchemaVersion,
			Data:          data,
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(ev)
	}
	var raw []byte
	if r.idem != nil {
		raw, err = r.idem.Do(ctx, tenantID, strings.TrimSpace(key), run)
	} else {
		raw, err = run(ctx)
	}
	if err != nil {
		return eventspec.Event{}, err
	}
	var ev eventspec.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return eventspec.Event{}, err
	}
	return ev, nil
}

func FoldEvents(events []eventspec.Event) (map[string]LedgerState, error) {
	state := map[string]LedgerState{}
	for _, ev := range events {
		switch ev.Type {
		case EventTypeWitnessRecorded:
			var payload WitnessRecorded
			if err := json.Unmarshal(ev.Data, &payload); err != nil {
				return nil, err
			}
			if payload.WitnessID == "" || payload.TenantID == "" {
				return nil, ErrInvalidWitness
			}
			cur := ensureLedgerState(state, payload.WitnessID)
			evidence := payload.Evidence
			cur.Recorded = true
			cur.Evidence = &evidence
			state[payload.WitnessID] = cur
		case EventTypeWitnessCountersigned:
			var payload WitnessCountersigned
			if err := json.Unmarshal(ev.Data, &payload); err != nil {
				return nil, err
			}
			cur := ensureLedgerState(state, payload.WitnessID)
			sig := payload.Countersign
			cur.CountersignedBy[payload.AuthorityID] = &sig
			state[payload.WitnessID] = cur
		case EventTypeWitnessDisputed:
			var payload WitnessDisputed
			if err := json.Unmarshal(ev.Data, &payload); err != nil {
				return nil, err
			}
			cur := ensureLedgerState(state, payload.WitnessID)
			dispute := payload.Dispute
			cur.DisputedBy[payload.AuthorityID] = &dispute
			state[payload.WitnessID] = cur
		default:
			continue
		}
	}
	return state, nil
}

func ensureLedgerState(state map[string]LedgerState, witnessID string) LedgerState {
	cur := state[witnessID]
	cur.WitnessID = witnessID
	if cur.CountersignedBy == nil {
		cur.CountersignedBy = map[string]*WitnessSignature{}
	}
	if cur.DisputedBy == nil {
		cur.DisputedBy = map[string]*DisputeRecord{}
	}
	return cur
}

func evidenceAuthorities(e Evidence) []string {
	out := make([]string, 0, len(e.Body.DigestRefs))
	seen := map[string]struct{}{}
	for _, ref := range e.Body.DigestRefs {
		if ref.AuthorityID == "" {
			continue
		}
		if _, ok := seen[ref.AuthorityID]; ok {
			continue
		}
		seen[ref.AuthorityID] = struct{}{}
		out = append(out, ref.AuthorityID)
	}
	return out
}
