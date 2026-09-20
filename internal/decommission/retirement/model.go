// SPDX-License-Identifier: BUSL-1.1

// Package retirement owns the event-sourced CA-key retirement command, its
// durable outbox receiver, and its tenant-scoped serving projection.
package retirement

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/decommission/gate"
	"trstctl.com/trstctl/internal/decommission/record"
	"trstctl.com/trstctl/internal/decommission/retirementwire"
	"trstctl.com/trstctl/internal/eventspec"
)

const (
	SchemaV1 = 1

	TypeRetirementRequested = "decommission.retirement.requested"
	TypeRetirementRefused   = "decommission.retirement.refused"
	TypeDestructionRecorded = "decommission.destruction_record.recorded"

	DestinationRetirement = "vdec.retirement.destroy"

	StatusPending   = "pending"
	StatusRefused   = "refused"
	StatusDestroyed = "destroyed"

	defaultKeyClass = "ca-signing-key"
	sha256DigestLen = 32
)

var (
	ErrInvalidCommand      = errors.New("vdec retirement: invalid command")
	ErrCommandConflict     = errors.New("vdec retirement: another command is active")
	ErrSignerUnavailable   = errors.New("vdec retirement: isolated signer is unavailable")
	ErrProjectionMissing   = errors.New("vdec retirement: command projection is missing")
	ErrDestructionRefused  = errors.New("vdec retirement: destruction refused")
	ErrRecordNotVerifiable = errors.New("vdec retirement: signed record is not verifiable")
)

// RequestedV1 is the immutable public command. It binds the exact retained
// event prefix the signer must verify; no private material crosses the boundary.
type RequestedV1 struct {
	TenantID                   string   `json:"tenant_id"`
	KeyID                      string   `json:"key_id"`
	SignerHandle               string   `json:"signer_handle"`
	FinalEpoch                 uint64   `json:"final_epoch"`
	LedgerPosition             uint64   `json:"ledger_position"`
	RequiredSet                []byte   `json:"required_set"`
	RequiredSetDigest          []byte   `json:"required_set_digest"`
	AuditChainHead             []byte   `json:"audit_chain_head"`
	CompletionEventsDigest     []byte   `json:"completion_events_digest"`
	RevocationCompletionDigest []byte   `json:"revocation_completion_digest,omitempty"`
	KeyClass                   string   `json:"key_class"`
	Approvals                  []string `json:"approvals,omitempty"`
}

// RefusedV1 carries the signer's public signed refusal and local append receipt.
// A later command may retry only after a newer ledger snapshot exists.
type RefusedV1 struct {
	TenantID       string `json:"tenant_id"`
	KeyID          string `json:"key_id"`
	CommandEventID string `json:"command_event_id"`
	FinalEpoch     uint64 `json:"final_epoch"`
	LedgerPosition uint64 `json:"ledger_position"`
	RefusalRecord  []byte `json:"refusal_record"`
	SignerEvidence []byte `json:"signer_evidence,omitempty"`
}

// RecordedV1 wraps the full offline-verifiable record with the command that
// caused it. The nested record remains the byte-stable downloadable artifact.
type RecordedV1 struct {
	TenantID       string              `json:"tenant_id"`
	KeyID          string              `json:"key_id"`
	CommandEventID string              `json:"command_event_id"`
	Record         record.SignedRecord `json:"record"`
}

type FinalizationContextV1 = retirementwire.FinalizationContextV1

// State is the tenant-filtered serving view rebuilt from the three immutable
// event types above.
type State struct {
	TenantID          string
	KeyID             string
	CommandEventID    string
	Status            string
	FinalEpoch        uint64
	LedgerPosition    uint64
	RefusalRecord     []byte
	DestructionRecord []byte
}

func (r RequestedV1) Validate() error {
	if strings.TrimSpace(r.TenantID) == "" || strings.TrimSpace(r.KeyID) == "" ||
		strings.TrimSpace(r.SignerHandle) == "" || r.FinalEpoch == 0 || r.LedgerPosition == 0 ||
		len(r.RequiredSet) == 0 || len(r.RequiredSetDigest) == 0 || len(r.AuditChainHead) == 0 ||
		len(r.CompletionEventsDigest) == 0 || strings.TrimSpace(r.KeyClass) == "" {
		return ErrInvalidCommand
	}
	if len(r.AuditChainHead) != sha256DigestLen || len(r.CompletionEventsDigest) != sha256DigestLen ||
		len(r.RevocationCompletionDigest) != sha256DigestLen {
		return fmt.Errorf("%w: public evidence digests must be SHA-256", ErrInvalidCommand)
	}
	if !bytes.Equal(crypto.SHA256Sum(r.RequiredSet), r.RequiredSetDigest) {
		return fmt.Errorf("%w: required-set digest mismatch", ErrInvalidCommand)
	}
	return nil
}

func (r RefusedV1) Validate() error {
	if strings.TrimSpace(r.TenantID) == "" || strings.TrimSpace(r.KeyID) == "" ||
		strings.TrimSpace(r.CommandEventID) == "" || r.FinalEpoch == 0 || r.LedgerPosition == 0 ||
		len(r.RefusalRecord) == 0 {
		return ErrInvalidCommand
	}
	return nil
}

func (r RecordedV1) Validate() error {
	if strings.TrimSpace(r.TenantID) == "" || strings.TrimSpace(r.KeyID) == "" ||
		strings.TrimSpace(r.CommandEventID) == "" || r.Record.Commitment.TenantID != r.TenantID ||
		r.Record.Commitment.StableKeyID != r.KeyID {
		return ErrInvalidCommand
	}
	trust := crypto.PublicKey{Algorithm: r.Record.AttestationAlgorithm, DER: append([]byte(nil), r.Record.AttestationPublicKeyDER...)}
	if err := record.VerifyRecord(r.Record, trust); err != nil {
		return fmt.Errorf("%w: %v", ErrRecordNotVerifiable, err)
	}
	return nil
}

func EncodeRequested(v RequestedV1) (eventspec.Event, error) {
	if err := v.Validate(); err != nil {
		return eventspec.Event{}, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return eventspec.Event{}, err
	}
	return eventspec.Event{Type: TypeRetirementRequested, TenantID: v.TenantID, SchemaVersion: SchemaV1, Data: raw}, nil
}

func EncodeRefused(v RefusedV1) (eventspec.Event, error) {
	if err := v.Validate(); err != nil {
		return eventspec.Event{}, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return eventspec.Event{}, err
	}
	return eventspec.Event{Type: TypeRetirementRefused, TenantID: v.TenantID, SchemaVersion: SchemaV1, Data: raw}, nil
}

func EncodeRecorded(v RecordedV1) (eventspec.Event, error) {
	if err := v.Validate(); err != nil {
		return eventspec.Event{}, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return eventspec.Event{}, err
	}
	return eventspec.Event{Type: TypeDestructionRecorded, TenantID: v.TenantID, SchemaVersion: SchemaV1, Data: raw}, nil
}

func DecodeRequested(ev eventspec.Event) (RequestedV1, error) {
	var value RequestedV1
	if err := decodeExact(ev, TypeRetirementRequested, &value); err != nil {
		return RequestedV1{}, err
	}
	return value, value.Validate()
}

func DecodeRefused(ev eventspec.Event) (RefusedV1, error) {
	var value RefusedV1
	if err := decodeExact(ev, TypeRetirementRefused, &value); err != nil {
		return RefusedV1{}, err
	}
	return value, value.Validate()
}

func DecodeRecorded(ev eventspec.Event) (RecordedV1, error) {
	var value RecordedV1
	if err := decodeExact(ev, TypeDestructionRecorded, &value); err != nil {
		return RecordedV1{}, err
	}
	return value, value.Validate()
}

func EncodeFinalizationContext(commandEventID string, requested RequestedV1) ([]byte, error) {
	raw, err := retirementwire.Encode(commandEventID, requested.KeyClass,
		requested.CompletionEventsDigest, requested.RevocationCompletionDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCommand, err)
	}
	return raw, nil
}

func DecodeFinalizationContext(raw []byte) (FinalizationContextV1, error) {
	value, err := retirementwire.Decode(raw)
	if err != nil {
		return FinalizationContextV1{}, fmt.Errorf("%w: %v", ErrInvalidCommand, err)
	}
	return value, nil
}

func KeyClass(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return defaultKeyClass
}

func RequiredSetAndDigest(stateBytes []byte) ([]byte, []byte) {
	body := append([]byte(nil), stateBytes...)
	return body, crypto.SHA256Sum(body)
}

func CompletionDigest(events []eventspec.Event, eventTypes ...string) []byte {
	wanted := make(map[string]struct{}, len(eventTypes))
	for _, typ := range eventTypes {
		wanted[typ] = struct{}{}
	}
	selected := make([]eventspec.Event, 0)
	for _, ev := range events {
		if _, ok := wanted[ev.Type]; ok {
			selected = append(selected, ev)
		}
	}
	raw, _ := json.Marshal(selected)
	return crypto.SHA256Sum(raw)
}

func CommandEventID(v RequestedV1) string {
	body := struct {
		Domain  string      `json:"domain"`
		Command RequestedV1 `json:"command"`
	}{Domain: "trstctl/vdec/retirement-command/v1", Command: v}
	raw, _ := json.Marshal(body)
	return "vdec-retirement-" + crypto.SHA256Hex(raw)
}

func TerminalEventID(commandEventID, terminal string) string {
	return "vdec-retirement-" + crypto.SHA256Hex([]byte(commandEventID+"\x00"+terminal))
}

func EncodeApprovals(keyClass string, approvals []string) ([]byte, error) {
	return gate.EncodeQuorumApprovals(KeyClass(keyClass), approvals)
}

func decodeExact(ev eventspec.Event, want string, dst any) error {
	if ev.Type != want || ev.SchemaVersion != SchemaV1 || strings.TrimSpace(ev.TenantID) == "" {
		return ErrInvalidCommand
	}
	if err := decodeStrictJSON(ev.Data, dst); err != nil {
		return fmt.Errorf("%w: decode %s: %v", ErrInvalidCommand, want, err)
	}
	return nil
}

func decodeStrictJSON(raw []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
