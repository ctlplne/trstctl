// SPDX-License-Identifier: LicenseRef-trstctl-EE

package gate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

type LedgerSegmentV1 struct {
	Version    int               `json:"version"`
	FinalEpoch uint64            `json:"final_epoch,omitempty"`
	Events     []eventspec.Event `json:"events"`
}

type RequiredSetV1 struct {
	Version        int                  `json:"version"`
	TenantID       string               `json:"tenant_id"`
	SubjectRef     string               `json:"subject_ref"`
	LedgerPosition uint64               `json:"ledger_position"`
	Registered     []depstate.Dependent `json:"registered"`
}

func EncodeLedgerSegment(finalEpoch uint64, events []eventspec.Event) ([]byte, error) {
	body := LedgerSegmentV1{
		Version:    SchemaV1,
		FinalEpoch: finalEpoch,
		Events:     cloneEvents(events),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vdec gate: encode ledger segment: %w", err)
	}
	return raw, nil
}

func DecodeLedgerSegment(raw []byte) (LedgerSegmentV1, error) {
	if len(raw) == 0 {
		return LedgerSegmentV1{}, fmt.Errorf("%w: missing ledger segment", ErrInvalidEvidence)
	}
	var seg LedgerSegmentV1
	if err := json.Unmarshal(raw, &seg); err != nil {
		return LedgerSegmentV1{}, fmt.Errorf("%w: decode ledger segment: %v", ErrInvalidEvidence, err)
	}
	if seg.Version != 0 && seg.Version != SchemaV1 {
		return LedgerSegmentV1{}, fmt.Errorf("%w: unsupported ledger segment version %d", ErrInvalidEvidence, seg.Version)
	}
	seg.Events = cloneEvents(seg.Events)
	return seg, nil
}

func RequiredSetBytes(state depstate.KeyState) ([]byte, error) {
	body := RequiredSetV1{
		Version:        SchemaV1,
		TenantID:       state.TenantID,
		SubjectRef:     state.KeyID,
		LedgerPosition: state.LedgerPosition,
		Registered:     sortedDependents(state.Registered),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vdec gate: encode required set: %w", err)
	}
	return raw, nil
}

func RequiredSetDigest(state depstate.KeyState) ([]byte, error) {
	raw, err := RequiredSetBytes(state)
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(raw), nil
}

func VerifyRequiredSet(raw []byte, state depstate.KeyState) error {
	var got RequiredSetV1
	if err := json.Unmarshal(raw, &got); err != nil {
		return fmt.Errorf("%w: decode required set: %v", ErrInvalidEvidence, err)
	}
	wantRaw, err := RequiredSetBytes(state)
	if err != nil {
		return err
	}
	got.Registered = sortedDependents(got.Registered)
	got.Version = SchemaV1
	normalized, err := json.Marshal(got)
	if err != nil {
		return fmt.Errorf("vdec gate: normalize required set: %w", err)
	}
	if !bytes.Equal(normalized, wantRaw) {
		return fmt.Errorf("%w: required set body mismatch", ErrInvalidEvidence)
	}
	return nil
}

func BoundEvents(events []eventspec.Event, bound uint64) []eventspec.Event {
	out := make([]eventspec.Event, 0, len(events))
	for i, ev := range events {
		pos := ev.Sequence
		if pos == 0 {
			pos = uint64(i + 1)
		}
		if pos > bound {
			continue
		}
		ev.Sequence = pos
		ev.Data = append([]byte(nil), ev.Data...)
		if ev.Actor != nil {
			actor := *ev.Actor
			actor.Roles = append([]string(nil), ev.Actor.Roles...)
			ev.Actor = &actor
		}
		out = append(out, ev)
	}
	return out
}

func AuditChainHead(events []eventspec.Event) []byte {
	head := crypto.SHA256Sum([]byte("trstctl/vdec/gated-destruction/audit-head/v1"))
	for _, ev := range events {
		entry := struct {
			Previous      []byte           `json:"previous"`
			ID            string           `json:"id,omitempty"`
			Type          string           `json:"type"`
			TenantID      string           `json:"tenant_id"`
			Sequence      uint64           `json:"sequence"`
			SchemaVersion int              `json:"schema_version"`
			DataDigest    []byte           `json:"data_digest"`
			Actor         *eventspec.Actor `json:"actor,omitempty"`
		}{
			Previous:      head,
			ID:            ev.ID,
			Type:          ev.Type,
			TenantID:      ev.TenantID,
			Sequence:      ev.Sequence,
			SchemaVersion: ev.SchemaVersion,
			DataDigest:    crypto.SHA256Sum(ev.Data),
			Actor:         ev.Actor,
		}
		raw, _ := json.Marshal(entry)
		head = crypto.SHA256Sum(raw)
	}
	return head
}

func cloneEvents(events []eventspec.Event) []eventspec.Event {
	out := make([]eventspec.Event, len(events))
	for i, ev := range events {
		out[i] = ev
		out[i].Data = append([]byte(nil), ev.Data...)
		if ev.Actor != nil {
			actor := *ev.Actor
			actor.Roles = append([]string(nil), ev.Actor.Roles...)
			out[i].Actor = &actor
		}
	}
	return out
}

func sortedDependents(in []depstate.Dependent) []depstate.Dependent {
	out := append([]depstate.Dependent(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].ID < out[j].ID
	})
	return out
}
