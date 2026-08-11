// SPDX-License-Identifier: MPL-2.0

// Package codesigningref defines opaque, non-PII identities shared by the
// code-signing projector and the event-history privacy rewriter. It is a leaf so
// the event package never needs to import the SQL store or projection packages.
package codesigningref

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const legacyStorageKeyPrefix = "privacy:codesign-legacy-key:v1:"

// LegacyApprovedCommandSemanticBasis is the privacy-stable operational identity
// of an approved schema-v2 command. Every field is available both from the event
// and from its already-authorized SQL projection. Actor and reviewer prose are
// deliberately absent because privacy erasure may rewrite or delete them; the
// exact approval capability is still revalidated by the projector.
type LegacyApprovedCommandSemanticBasis struct {
	EventID              string
	TenantID             string
	EventTime            time.Time
	OperationID          string
	KeyDigest            string
	Mode                 string
	RequestHash          string
	SealedCommand        []byte
	ApprovalRequestID    string
	ApprovalIntentDigest string
}

// IdempotencyKeyDigest is the shared one-way mutation-key evidence. Keeping the
// domain here makes the event rewriter and SQL projector incapable of inventing
// subtly different legacy mappings.
func IdempotencyKeyDigest(idempotencyKey string) string {
	return crypto.SHA256Hex([]byte("trstctl:codesign-idempotency-key:v1\x00" + idempotencyKey))
}

// LegacyApprovedCommandSemanticDigest gives raw and privacy-mapped schema-v2
// commands one exact semantic identity. PostgreSQL's timestamptz precision is
// part of this compatibility format, so historical nanoseconds are intentionally
// reduced to the durable microsecond value instead of being guessed on recovery.
func LegacyApprovedCommandSemanticDigest(basis LegacyApprovedCommandSemanticBasis) (string, error) {
	if basis.EventID == "" || basis.TenantID == "" || basis.EventTime.IsZero() ||
		basis.OperationID == "" || basis.Mode == "" || basis.RequestHash == "" ||
		len(basis.SealedCommand) == 0 || basis.ApprovalRequestID == "" ||
		basis.ApprovalIntentDigest == "" {
		return "", errors.New("codesigningref: legacy approved semantic basis is incomplete")
	}
	if len(basis.KeyDigest) != 64 || strings.ToLower(basis.KeyDigest) != basis.KeyDigest {
		return "", errors.New("codesigningref: legacy approved key digest is invalid")
	}
	decoded, err := hex.DecodeString(basis.KeyDigest)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("codesigningref: legacy approved key digest is invalid")
	}
	canonical := struct {
		ID                   string    `json:"id"`
		Type                 string    `json:"type"`
		TenantID             string    `json:"tenant_id"`
		Time                 time.Time `json:"time"`
		SchemaVersion        int       `json:"schema_version"`
		OperationID          string    `json:"operation_id"`
		IdempotencyKeyDigest string    `json:"idempotency_key_digest"`
		Mode                 string    `json:"mode"`
		RequestHash          string    `json:"request_hash"`
		SealedCommand        []byte    `json:"sealed_command"`
		ApprovalRequestID    string    `json:"approval_request_id"`
		ApprovalIntentDigest string    `json:"approval_intent_digest"`
	}{
		ID: basis.EventID, Type: "codesign.commanded", TenantID: basis.TenantID,
		Time: basis.EventTime.UTC().Truncate(time.Microsecond), SchemaVersion: 2,
		OperationID: basis.OperationID, IdempotencyKeyDigest: basis.KeyDigest,
		Mode: basis.Mode, RequestHash: basis.RequestHash,
		SealedCommand:        append([]byte(nil), basis.SealedCommand...),
		ApprovalRequestID:    basis.ApprovalRequestID,
		ApprovalIntentDigest: basis.ApprovalIntentDigest,
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl:approved-code-signing-event:legacy-privacy:v1\x00"), raw...)), nil
}

// LegacyStorageKey replaces a schema-v1/v2 raw Idempotency-Key in hot history
// and SQL. OperationID preserves deterministic historical lookup; KeyDigest
// preserves the exact approval-resource binding without retaining or recovering
// the caller's raw key.
func LegacyStorageKey(operationID, keyDigest string) string {
	return legacyStorageKeyPrefix + operationID + ":" + keyDigest
}

func LegacyStorageKeyForRaw(operationID, idempotencyKey string) string {
	return LegacyStorageKey(operationID, IdempotencyKeyDigest(idempotencyKey))
}

// IsLegacyStorageKeyForOperation accepts only the exact versioned mapping for
// one operation. Prefix-only recognition would let a raw legacy key impersonate
// another operation's privacy disposition.
func IsLegacyStorageKeyForOperation(value, operationID string) bool {
	_, ok := LegacyStorageKeyDigest(value, operationID)
	return ok
}

// LegacyStorageKeyDigest returns the exact one-way key evidence only after the
// mapping is proven to belong to operationID.
func LegacyStorageKeyDigest(value, operationID string) (string, bool) {
	prefix := legacyStorageKeyPrefix + operationID + ":"
	if operationID == "" || !strings.HasPrefix(value, prefix) {
		return "", false
	}
	digest := strings.TrimPrefix(value, prefix)
	if len(digest) != 64 || strings.ToLower(digest) != digest {
		return "", false
	}
	decoded, err := hex.DecodeString(digest)
	return digest, err == nil && len(decoded) == 32
}

// IsLegacyStorageKey reports whether value is in the reserved mapping domain.
// Callers that authorize or project work must additionally bind it to an exact
// operation with IsLegacyStorageKeyForOperation.
func IsLegacyStorageKey(value string) bool {
	return strings.HasPrefix(value, legacyStorageKeyPrefix)
}
