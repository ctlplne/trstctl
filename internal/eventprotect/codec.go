// SPDX-License-Identifier: BUSL-1.1

// Package eventprotect preserves exact sensitive source bytes inside an
// authenticated tenant-key envelope. Custody, retention and destruction authority
// are separate from this codec; an envelope alone does not prove erasure.
package eventprotect

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventspec"
)

const (
	ScopeEvent       = "event"
	ScopePostgresRow = "postgres_row"
	ScopeSnapshot    = "snapshot"
	formatVersion    = 1
	maxDataBytes     = 32 << 20
	maxActorBytes    = 256 << 10
	frameHeaderBytes = 20
	maxCipherBytes   = maxDataBytes + maxActorBytes + (128 << 10)
)

var (
	ErrContext  = errors.New("eventprotect: invalid protection context")
	ErrEnvelope = errors.New("eventprotect: invalid protected envelope")
	ErrPayload  = errors.New("eventprotect: invalid protected payload")
	ErrKey      = errors.New("eventprotect: key is unavailable")
	ErrOpen     = errors.New("eventprotect: authenticated opening failed")
)

// Context is public source identity, not a caller's authorization claim. A
// storage adapter constructs it from the exact source envelope being processed.
type Context struct {
	Scope         string    `json:"scope"`
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	TenantID      string    `json:"tenant_id"`
	SchemaVersion int       `json:"schema_version"`
	Time          time.Time `json:"time"`
}

type Envelope = eventspec.ProtectedPayload

// Payload contains readable bytes. The recipient owns Data and must wipe it
// when it is no longer needed; nothing here is an immutable audit record.
type Payload struct {
	Data  []byte
	Actor *eventspec.Actor
}

func Protect(key seal.KeyWrapper, context Context, keyID, policyDigest string, payload Payload) (Envelope, error) {
	aad, domain, err := protectionBindings(context, keyID, policyDigest)
	if err != nil {
		return Envelope{}, err
	}
	if key == nil {
		return Envelope{}, ErrKey
	}
	frame, err := encodePayload(payload)
	if err != nil {
		return Envelope{}, err
	}
	defer secret.Wipe(frame)
	ciphertext, err := seal.SealDomain(key, frame, aad, domain)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Version: formatVersion, KeyID: keyID, PolicyDigest: policyDigest, Ciphertext: ciphertext}, nil
}

func Open(key seal.KeyWrapper, context Context, expectedPolicy string, envelope Envelope) (Payload, error) {
	if err := ValidateEnvelope(context, expectedPolicy, envelope); err != nil {
		return Payload{}, err
	}
	aad, domain, err := protectionBindings(context, envelope.KeyID, expectedPolicy)
	if err != nil {
		return Payload{}, err
	}
	if key == nil {
		return Payload{}, ErrKey
	}
	frame, err := seal.OpenDomain(key, envelope.Ciphertext, aad, domain)
	if err != nil {
		return Payload{}, ErrOpen
	}
	defer secret.Wipe(frame)
	return decodePayload(frame)
}

// ValidateEnvelope checks the public framing and bindings without opening any
// data. Backup/source-index code can preserve ciphertext without key access.
// This is structural validation; it never claims ciphertext authentication.
func ValidateEnvelope(context Context, expectedPolicy string, envelope Envelope) error {
	if envelope.Version != formatVersion || envelope.PolicyDigest != expectedPolicy ||
		len(envelope.Ciphertext) == 0 || len(envelope.Ciphertext) > maxCipherBytes {
		return ErrEnvelope
	}
	_, _, err := protectionBindings(context, envelope.KeyID, expectedPolicy)
	return err
}

func protectionBindings(context Context, keyID, policyDigest string) ([]byte, []byte, error) {
	if context.Scope != ScopeEvent && context.Scope != ScopePostgresRow && context.Scope != ScopeSnapshot {
		return nil, nil, ErrContext
	}
	for _, value := range []string{context.ID, context.Type, context.TenantID, keyID} {
		if len(value) == 0 || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
			return nil, nil, ErrContext
		}
	}
	if context.SchemaVersion <= 0 || context.Time.IsZero() || len(policyDigest) != 64 || strings.ToLower(policyDigest) != policyDigest {
		return nil, nil, ErrContext
	}
	if _, err := hex.DecodeString(policyDigest); err != nil {
		return nil, nil, ErrContext
	}
	context.Time = context.Time.UTC()
	aad, err := json.Marshal(struct {
		Format       string  `json:"format"`
		Version      int     `json:"version"`
		Context      Context `json:"context"`
		KeyID        string  `json:"key_id"`
		PolicyDigest string  `json:"policy_digest"`
	}{"trstctl.protected-source", formatVersion, context, keyID, policyDigest})
	if err != nil {
		return nil, nil, ErrContext
	}
	domain, err := json.Marshal([]string{"trstctl.protected-source.v1", context.Scope, context.TenantID, keyID})
	if err != nil {
		return nil, nil, ErrContext
	}
	return aad, domain, nil
}

// The authenticated frame length-prefixes original domain bytes and a separate
// actor JSON object. Embedding domain JSON in another JSON document would compact
// whitespace and escape spelling, breaking exact first-writer recovery.
func encodePayload(payload Payload) ([]byte, error) {
	if len(payload.Data) > maxDataBytes {
		return nil, ErrPayload
	}
	var actor []byte
	if payload.Actor != nil {
		if !utf8.ValidString(payload.Actor.Subject) {
			return nil, ErrPayload
		}
		for _, role := range payload.Actor.Roles {
			if !utf8.ValidString(role) {
				return nil, ErrPayload
			}
		}
		var err error
		actor, err = json.Marshal(payload.Actor)
		if err != nil {
			return nil, ErrPayload
		}
		defer secret.Wipe(actor)
		if len(actor) > maxActorBytes {
			return nil, ErrPayload
		}
	}
	frame := make([]byte, 0, frameHeaderBytes+len(payload.Data)+len(actor))
	frame = append(frame, 'E', 'P', 'F', '1')
	frame = binary.BigEndian.AppendUint64(frame, uint64(len(payload.Data)))
	frame = binary.BigEndian.AppendUint64(frame, uint64(len(actor)))
	frame = append(frame, payload.Data...)
	return append(frame, actor...), nil
}

func decodePayload(frame []byte) (Payload, error) {
	if len(frame) < frameHeaderBytes || !bytes.Equal(frame[:4], []byte("EPF1")) {
		return Payload{}, ErrPayload
	}
	dataLen, actorLen := binary.BigEndian.Uint64(frame[4:12]), binary.BigEndian.Uint64(frame[12:20])
	body := frame[frameHeaderBytes:]
	if dataLen > maxDataBytes || actorLen > maxActorBytes || dataLen > uint64(len(body)) || actorLen != uint64(len(body))-dataLen {
		return Payload{}, ErrPayload
	}
	var actor *eventspec.Actor
	if actorLen != 0 {
		var value eventspec.Actor
		if err := json.Unmarshal(body[dataLen:], &value); err != nil {
			return Payload{}, ErrPayload
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return Payload{}, ErrPayload
		}
		defer secret.Wipe(canonical)
		if !bytes.Equal(canonical, body[dataLen:]) {
			return Payload{}, ErrPayload
		}
		actor = &value
	}
	return Payload{Data: append([]byte(nil), body[:dataLen]...), Actor: actor}, nil
}
