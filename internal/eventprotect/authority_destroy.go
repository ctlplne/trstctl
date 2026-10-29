// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/jose"
)

var (
	ErrDestroyed           = errors.New("eventprotect: key destruction is verified")
	ErrRetention           = errors.New("eventprotect: offboarding retention window has not elapsed")
	ErrDestructionConflict = errors.New("eventprotect: key is bound to another destruction command")
)

const destructionReceiptSchema = "trstctl.event-key-destruction/v1"

// DestructionRequest binds a single key and durable command to its retained
// offboard event and retention deadline. It contains no readable tenant data.
type DestructionRequest struct {
	Ref                  KeyRef    `json:"ref"`
	OperationID          string    `json:"operation_id"`
	RegistrationIdentity string    `json:"registration_identity"`
	ActivationEventID    string    `json:"activation_event_id"`
	ActivationSequence   uint64    `json:"activation_sequence"`
	CreationDigest       string    `json:"creation_digest"`
	OffboardEventID      string    `json:"offboard_event_id"`
	OffboardSequence     uint64    `json:"offboard_sequence"`
	OffboardedAt         time.Time `json:"offboarded_at"`
	NotBefore            time.Time `json:"not_before"`
}

// DestructionAuthorizer verifies the retained source, exact protection policy
// and committed outbox intent. Caller-supplied timestamps are not authority.
// This check runs again on recovery, before a key can be removed.
type DestructionAuthorizer interface {
	AuthorizeDestruction(context.Context, DestructionRequest) error
}

type DestructionClaims struct {
	Schema    string             `json:"schema"`
	Request   DestructionRequest `json:"request"`
	RemovedAt time.Time          `json:"removed_at"`
}

type fileDestruction struct {
	Request   DestructionRequest `json:"request"`
	RemovedAt time.Time          `json:"removed_at,omitempty"`
	Receipt   string             `json:"receipt,omitempty"`
}

func validateDestructionRequest(request DestructionRequest) error {
	ref, err := normalizedKeyRef(request.Ref)
	if err != nil || ref != request.Ref {
		return ErrContext
	}
	operation, err := uuid.Parse(request.OperationID)
	if err != nil || operation == uuid.Nil || operation.String() != request.OperationID {
		return ErrContext
	}
	for _, identity := range []string{request.RegistrationIdentity, request.ActivationEventID, request.OffboardEventID} {
		if identity == "" || len(identity) > 512 || !utf8.ValidString(identity) || strings.TrimSpace(identity) != identity ||
			strings.ContainsFunc(identity, unicode.IsControl) {
			return ErrContext
		}
	}
	if len(request.CreationDigest) != 64 || strings.ToLower(request.CreationDigest) != request.CreationDigest {
		return ErrContext
	}
	if _, err := hex.DecodeString(request.CreationDigest); err != nil {
		return ErrContext
	}
	if request.ActivationSequence == 0 || request.ActivationSequence >= request.OffboardSequence ||
		request.OffboardedAt.IsZero() || !request.NotBefore.After(request.OffboardedAt) {
		return ErrContext
	}
	return nil
}

func sameDestructionRequest(a, b DestructionRequest) bool {
	left, leftErr := json.Marshal(a)
	right, rightErr := json.Marshal(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

// VerifyDestructionReceipt verifies against separately pinned audit trust. The
// signature covers the complete canonical authority and observed removal time;
// an unsigned outer status or a missing key file is never sufficient evidence.
func VerifyDestructionReceipt(trust *jose.JWKSet, receipt string) (DestructionClaims, error) {
	if trust == nil || len(receipt) == 0 || len(receipt) > 12<<10 {
		return DestructionClaims{}, ErrKey
	}
	wire, err := trust.VerifyArtifact(receipt, jose.ArtifactEventKeyDestruction)
	if err != nil {
		return DestructionClaims{}, ErrKey
	}
	return decodeDestructionClaims(wire)
}

func decodeDestructionClaims(wire []byte) (DestructionClaims, error) {
	if len(wire) > 8<<10 {
		return DestructionClaims{}, ErrKey
	}
	var claims DestructionClaims
	if err := json.Unmarshal(wire, &claims); err != nil {
		return DestructionClaims{}, ErrKey
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(wire, canonical) || claims.Schema != destructionReceiptSchema ||
		validateDestructionRequest(claims.Request) != nil || claims.RemovedAt.Before(claims.Request.NotBefore) {
		return DestructionClaims{}, ErrKey
	}
	return claims, nil
}

func (a *FileAuthority) verifyReceipt(receipt string) (DestructionClaims, error) {
	if a.evidenceKey != nil {
		if claims, err := VerifyDestructionReceipt(a.evidenceKey.JWKS(), receipt); err == nil {
			return claims, nil
		}
	}
	return VerifyDestructionReceipt(a.verificationKeys, receipt)
}

func (a *FileAuthority) destroyedState(record fileKeyRecord) error {
	if record.Destruction == nil {
		return ErrKey
	}
	claims, err := a.verifyReceipt(record.Destruction.Receipt)
	if err != nil || !sameDestructionRequest(claims.Request, record.Destruction.Request) ||
		!claims.RemovedAt.Equal(record.Destruction.RemovedAt) || claims.Request.Ref != record.Ref ||
		creationEvidenceFor(record).Digest() != claims.Request.CreationDigest {
		return ErrKey
	}
	if _, err := a.root.Lstat(keyName(record.Ref)); !errors.Is(err, os.ErrNotExist) {
		return ErrKey
	}
	return ErrDestroyed
}

// Destroy is the custody effect of an already committed outbox command. The
// exclusive key lock also excludes every WithKey callback across replicas.
// A durable intent precedes removal, and a signed completion follows independent
// absence readback. A retry returns the exact first signed result.
func (a *FileAuthority) Destroy(ctx context.Context, request DestructionRequest) (string, error) {
	if err := validateDestructionRequest(request); err != nil {
		return "", err
	}
	var receipt string
	err := a.withLock(ctx, request.Ref, func(ctx context.Context, ref KeyRef) error {
		if a.destructionAuthority == nil || a.evidenceKey == nil {
			return ErrKey
		}
		if err := a.destructionAuthority.AuthorizeDestruction(ctx, request); err != nil {
			return err
		}
		record, found, err := a.readRecord(ref)
		if err != nil || !found || record.CreatedAt.After(request.OffboardedAt) {
			return ErrKey
		}
		if creationEvidenceFor(record).Digest() != request.CreationDigest {
			return ErrKey
		}
		if record.Destruction != nil && !sameDestructionRequest(record.Destruction.Request, request) {
			return ErrDestructionConflict
		}
		if record.Phase == "destroyed" {
			if !errors.Is(a.destroyedState(record), ErrDestroyed) {
				return ErrKey
			}
			receipt = record.Destruction.Receipt
			return nil
		}
		if a.now().Before(request.NotBefore) {
			return ErrRetention
		}
		if record.Phase == "active" {
			// Refuse to turn unexplained prior loss into a destruction claim.
			key, err := a.loadKey(ref, record)
			if err != nil {
				return err
			}
			key.Destroy()
			record.Phase = "destroying"
			record.Destruction = &fileDestruction{Request: request}
			if err := a.writeRecord(record); err != nil {
				return err
			}
		}
		if record.Phase != "destroying" || record.Destruction == nil {
			return ErrKey
		}
		if err := a.root.Remove(keyName(ref)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := a.syncTenantDirectory(ref); err != nil {
			return err
		}
		if _, err := a.root.Lstat(keyName(ref)); !errors.Is(err, os.ErrNotExist) {
			return ErrKey
		}
		if record.Destruction.RemovedAt.IsZero() {
			record.Destruction.RemovedAt = a.now().UTC()
			if record.Destruction.RemovedAt.Before(request.NotBefore) {
				return ErrRetention
			}
			if err := a.writeRecord(record); err != nil {
				return err
			}
		}
		claims := DestructionClaims{Schema: destructionReceiptSchema, Request: request, RemovedAt: record.Destruction.RemovedAt}
		wire, err := json.Marshal(claims)
		if err != nil {
			return err
		}
		signed, err := a.evidenceKey.SignArtifact(jose.ArtifactEventKeyDestruction, wire)
		if err != nil {
			return err
		}
		verified, err := VerifyDestructionReceipt(a.evidenceKey.JWKS(), signed)
		if err != nil || !sameDestructionRequest(verified.Request, request) || !verified.RemovedAt.Equal(claims.RemovedAt) {
			return ErrKey
		}
		record.Destruction.Receipt, record.Phase = signed, "destroyed"
		if err := a.writeRecord(record); err != nil {
			return err
		}
		if !errors.Is(a.destroyedState(record), ErrDestroyed) {
			return ErrKey
		}
		receipt = signed
		return nil
	})
	return receipt, err
}

func (a *FileAuthority) syncTenantDirectory(ref KeyRef) error {
	directory, err := a.root.Open(ref.TenantID)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
