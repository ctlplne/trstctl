// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/eventspec"
)

const (
	EventRequested = "tenant.event_protection.requested"
	EventActivated = "tenant.event_protection.activated"
	EventDestroyed = "tenant.event_protection.key_destroyed"
)

var ErrSource = errors.New("event privacy: invalid retained protection authority")

type Requested struct {
	RegistrationIdentity string `json:"registration_identity"`
	OperationID          string `json:"operation_id"`
	KeyID                string `json:"key_id"`
	RetentionNanos       int64  `json:"retention_ns"`
}

type Activated struct {
	RegistrationIdentity string                           `json:"registration_identity"`
	OperationID          string                           `json:"operation_id"`
	KeyID                string                           `json:"key_id"`
	RetentionNanos       int64                            `json:"retention_ns"`
	RequestedEventID     string                           `json:"requested_event_id"`
	RequestedSequence    uint64                           `json:"requested_sequence"`
	RequestedAt          time.Time                        `json:"requested_at"`
	Creation             eventprotect.KeyCreationEvidence `json:"creation"`
}

type Destroyed struct {
	JWS string `json:"jws"`
}

func validIdentity(identity string) bool {
	return identity != "" && len(identity) <= 512 && utf8.ValidString(identity) &&
		strings.TrimSpace(identity) == identity && !strings.ContainsFunc(identity, unicode.IsControl)
}

func NewRequested(tenantID, registration string, retention time.Duration) (Requested, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil || !validIdentity(registration) || retention <= 0 {
		return Requested{}, ErrSource
	}
	tenantID = tenant.String()
	operation := crypto.UUIDv5OID([]byte("trstctl.event-protection.v1\x00" + tenantID + "\x00" + registration))
	return Requested{RegistrationIdentity: registration, OperationID: operation, KeyID: operation, RetentionNanos: int64(retention)}, nil
}

func RequestedEventID(request Requested) string { return request.OperationID + ":requested" }

// Control records have one closed canonical encoding and contain no private
// key, subject or user-supplied diagnostic. This decoder validates syntax;
// retained parent events and independent key readback still grant authority.
func decodeControl(wire []byte, target any) error {
	if len(wire) == 0 || len(wire) > 16<<10 || json.Unmarshal(wire, target) != nil {
		return ErrSource
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(wire, canonical) {
		return ErrSource
	}
	return nil
}

func ParseRequested(tenantID string, wire []byte) (Requested, error) {
	var request Requested
	if decodeControl(wire, &request) != nil {
		return Requested{}, ErrSource
	}
	expected, err := NewRequested(tenantID, request.RegistrationIdentity, time.Duration(request.RetentionNanos))
	if err != nil || expected != request {
		return Requested{}, ErrSource
	}
	return request, nil
}

func (activation Activated) Requested() Requested {
	return Requested{RegistrationIdentity: activation.RegistrationIdentity, OperationID: activation.OperationID, KeyID: activation.KeyID, RetentionNanos: activation.RetentionNanos}
}

func ParseActivated(event eventspec.Event) (Activated, error) {
	return parseActivated(event, true)
}

func parseActivated(event eventspec.Event, retained bool) (Activated, error) {
	var activation Activated
	if event.Type != EventActivated || event.SchemaVersion != 1 || event.Actor != nil || event.Protection != nil || event.SensitiveErased || decodeControl(event.Data, &activation) != nil {
		return Activated{}, ErrSource
	}
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant == uuid.Nil {
		return Activated{}, ErrSource
	}
	event.TenantID = tenant.String()
	expected, err := NewRequested(event.TenantID, activation.RegistrationIdentity, time.Duration(activation.RetentionNanos))
	if err != nil || expected != activation.Requested() || event.ID != activation.KeyID ||
		activation.RequestedEventID != RequestedEventID(expected) || activation.RequestedSequence == 0 ||
		(retained && (event.Sequence == 0 || activation.RequestedSequence >= event.Sequence)) || activation.RequestedAt.IsZero() ||
		activation.Creation.Ref.TenantID != event.TenantID || activation.Creation.Ref.ID != activation.KeyID ||
		activation.Creation.Digest() == "" || activation.Creation.CreatedAt.Before(activation.RequestedAt) ||
		event.Time.Before(activation.Creation.CreatedAt) {
		return Activated{}, ErrSource
	}
	return activation, nil
}

func ParseDestroyed(event eventspec.Event) (Destroyed, error) {
	var destroyed Destroyed
	if event.Type != EventDestroyed || event.SchemaVersion != 1 || event.Actor != nil || event.Protection != nil || event.SensitiveErased ||
		decodeControl(event.Data, &destroyed) != nil || len(destroyed.JWS) == 0 || len(destroyed.JWS) > 12<<10 {
		return Destroyed{}, ErrSource
	}
	return destroyed, nil
}
