// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/codesigningref"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	CodeSigningCommandDestination = "codesign.command"
	CodeSigningCleanupDestination = "codesign.cleanup"

	codeSigningIdempotencyKeyRefPrefix = "sha256:"
)

var (
	// Keep this namespace byte-exact forever: schema-v1/v2 operation IDs are
	// persistent API and event identities.
	codeSigningLegacyOperationNamespace = uuid.MustParse("85cc5d6f-07c5-5cfa-a9f1-7c16659787af")
	// V3 uses a child namespace as well as a versioned input. Otherwise a legacy
	// raw key J equal to KeyRef(K) deterministically aliases the v3 identity for K.
	codeSigningPrivacySafeOperationNamespace = uuid.NewSHA1(
		codeSigningLegacyOperationNamespace,
		[]byte("trstctl:codesign-operation:v3"),
	)
)

// CodeSigningOperation is the tenant-scoped read model for one durable signing
// command. SealedCommand is deployment-KEK ciphertext; plaintext identity
// assertions and digests never enter PostgreSQL or the event log.
type CodeSigningOperation struct {
	TenantID             string
	OperationID          string
	IdempotencyKey       string
	Mode                 string
	RequestHash          string
	SealedCommand        []byte
	Status               string
	Response             []byte
	EphemeralHandle      string
	CleanupStatus        string
	CommandOutboxID      int64
	CleanupOutboxID      int64
	LastError            string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	SourceEventID        string
	ApprovalRequestID    string
	ApprovalIntentDigest string
	SemanticDigest       string
	// HistoricalSemanticDigest is a transient compatibility input used only while
	// replaying an approved schema-v2 event projected by an older release. It is
	// never persisted; an exact legacy match is upgraded to SemanticDigest.
	HistoricalSemanticDigest string

	// Approval is a transient projection input. Its immutable request/event/digest
	// identity is persisted above so a later retained event cannot consume another
	// grant while converging on this operation.
	Approval *OperationApprovalUse
}

// CodeSigningIdempotencyKeyDigest is the non-secret approval evidence for an
// API mutation key. V3 rows carry this reference; v1/v2 rows converge on an
// operation-bound legacy storage identity so neither representation serves the
// raw mutation key after projection or privacy erasure.
func CodeSigningIdempotencyKeyDigest(idempotencyKey string) string {
	return codesigningref.IdempotencyKeyDigest(idempotencyKey)
}

// CodeSigningIdempotencyKeyRef is the non-reversible v3 event/read-model key.
// The prefix makes the stored representation self-describing; the digest remains
// domain-separated from every other SHA-256 use in the product.
func CodeSigningIdempotencyKeyRef(idempotencyKey string) string {
	return codeSigningIdempotencyKeyRefPrefix + CodeSigningIdempotencyKeyDigest(idempotencyKey)
}

func codeSigningIdempotencyKeyRefDigest(ref string) (string, bool) {
	if !strings.HasPrefix(ref, codeSigningIdempotencyKeyRefPrefix) {
		return "", false
	}
	digest := strings.TrimPrefix(ref, codeSigningIdempotencyKeyRefPrefix)
	if len(digest) != 64 || strings.ToLower(digest) != digest {
		return "", false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", false
	}
	return digest, true
}

// IsCodeSigningIdempotencyKeyRef reports whether ref is the canonical v3
// one-way representation. It never treats arbitrary 64-byte user input as a
// digest because the explicit prefix is part of the stored contract.
func IsCodeSigningIdempotencyKeyRef(ref string) bool {
	_, ok := codeSigningIdempotencyKeyRefDigest(ref)
	return ok
}

// CodeSigningOperationID derives the v3 operation identity from the one-way key
// reference. A raw key appears only transiently while this function computes the
// reference; it never needs to enter event history or a rebuilt read model.
func CodeSigningOperationID(tenantID, idempotencyKey string) string {
	return CodeSigningOperationIDFromRef(tenantID, CodeSigningIdempotencyKeyRef(idempotencyKey))
}

// CodeSigningOperationIDFromRef repeats the v3 projector derivation.
func CodeSigningOperationIDFromRef(tenantID, keyRef string) string {
	return "codesign-" + uuid.NewSHA1(codeSigningPrivacySafeOperationNamespace,
		[]byte("v3\x00"+tenantID+"\x00"+keyRef)).String()
}

// LegacyCodeSigningOperationID retains the v1/v2 raw-key derivation so old
// source events remain exactly replayable after the v3 privacy-safe cutover.
func LegacyCodeSigningOperationID(tenantID, idempotencyKey string) string {
	return "codesign-" + uuid.NewSHA1(codeSigningLegacyOperationNamespace,
		[]byte(tenantID+"\x00"+idempotencyKey)).String()
}

// LegacyCodeSigningStorageKey is the non-PII SQL/history representation for a
// schema-v1/v2 operation. Its operation ID stays byte-identical to historical
// releases, but the raw API key no longer needs to survive in a rebuilt row.
func LegacyCodeSigningStorageKey(operationID, idempotencyKey string) string {
	return codesigningref.LegacyStorageKeyForRaw(operationID, idempotencyKey)
}

// IsLegacyCodeSigningStorageKey proves that value belongs to this exact legacy
// operation rather than merely sharing the reserved prefix.
func IsLegacyCodeSigningStorageKey(value, operationID string) bool {
	return codesigningref.IsLegacyStorageKeyForOperation(value, operationID)
}

// LegacyCodeSigningStorageKeyDigest returns the one-way raw-key evidence only
// when the privacy mapping belongs to this exact historical operation.
func LegacyCodeSigningStorageKeyDigest(value, operationID string) (string, bool) {
	return codesigningref.LegacyStorageKeyDigest(value, operationID)
}

// CodeSigningApprovalResourceID names exactly one command and one mutation-key
// attempt. A same-key retry therefore finds the same request, while a fresh key
// creates fresh, single-use authority even for byte-identical artifact input.
func CodeSigningApprovalResourceID(requestHash, idempotencyKey string) string {
	keyDigest := CodeSigningIdempotencyKeyDigest(idempotencyKey)
	return "codesign:" + crypto.SHA256Hex([]byte("trstctl:codesign-approval:v1\x00"+requestHash+"\x00"+keyDigest))
}

// CodeSigningApprovalResourceIDFromRef reproduces the existing approval resource
// from a v3 one-way key. The resulting value is byte-identical to the legacy
// raw-key helper, so approvals created before command publication keep the exact
// same first-command binding.
func CodeSigningApprovalResourceIDFromRef(requestHash, keyRef string) (string, error) {
	digest, ok := codeSigningIdempotencyKeyRefDigest(keyRef)
	if !ok {
		return "", errors.New("store: code-signing idempotency key reference is invalid")
	}
	return "codesign:" + crypto.SHA256Hex([]byte(
		"trstctl:codesign-approval:v1\x00"+requestHash+"\x00"+digest,
	)), nil
}

// CodeSigningApprovalResourceIDForOperation selects the legacy or v3 binding
// without trusting a prefix alone. A legacy user key may itself begin with
// "sha256:"; only a reference that also derives this operation ID is v3.
func CodeSigningApprovalResourceIDForOperation(
	tenantID, operationID, requestHash, storedIdempotencyKey string,
	boundResourceIDs ...string,
) (string, error) {
	if IsCodeSigningIdempotencyKeyRef(storedIdempotencyKey) &&
		CodeSigningOperationIDFromRef(tenantID, storedIdempotencyKey) == operationID {
		resourceID, err := CodeSigningApprovalResourceIDFromRef(requestHash, storedIdempotencyKey)
		if err != nil {
			return "", err
		}
		if len(boundResourceIDs) == 1 && boundResourceIDs[0] != resourceID {
			return "", fmt.Errorf("%w: privacy-safe code-signing approval resource differs", ErrApprovalDrifted)
		}
		return resourceID, nil
	}
	if LegacyCodeSigningOperationID(tenantID, storedIdempotencyKey) == operationID {
		resourceID := CodeSigningApprovalResourceID(requestHash, storedIdempotencyKey)
		if len(boundResourceIDs) == 1 && boundResourceIDs[0] != resourceID {
			return "", fmt.Errorf("%w: legacy code-signing approval resource differs", ErrApprovalDrifted)
		}
		return resourceID, nil
	}
	if keyDigest, ok := codesigningref.LegacyStorageKeyDigest(storedIdempotencyKey, operationID); ok {
		expectedResource := codeSigningApprovalResourceIDFromDigest(requestHash, keyDigest)
		if len(boundResourceIDs) == 1 && boundResourceIDs[0] != expectedResource {
			return "", fmt.Errorf("%w: legacy code-signing approval resource differs", ErrApprovalDrifted)
		}
		return expectedResource, nil
	}
	return "", fmt.Errorf("%w: code-signing operation/key representation differs", ErrIdempotencyConflict)
}

func codeSigningApprovalResourceIDFromDigest(requestHash, keyDigest string) string {
	return "codesign:" + crypto.SHA256Hex([]byte(
		"trstctl:codesign-approval:v1\x00"+requestHash+"\x00"+keyDigest,
	))
}

// CodeSigningIdentityRow is one signing operation joined to the state of its
// transparency-log publication (B-4). Rekor publication rides the outbox, so
// "was this entry actually published and its receipt verified" is the outbox
// row's terminal state — not a separate flag that could disagree with it.
type CodeSigningIdentityRow struct {
	OperationID string
	Mode        string // "managed" (signer-held key) or "keyless" (Sigstore/Fulcio)
	Status      string
	RequestHash string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastError   string
	// Transparency is the publication state: "verified" once the outbox row
	// delivered (the handler refuses to ack an unverified Rekor receipt),
	// "pending"/"failed" while in flight, and "not-published" when the
	// operation queued no transparency row at all.
	Transparency      string
	TransparencyError string
}

// ListCodeSigningIdentities returns recent signing operations with their
// transparency state, newest first. Tenant-scoped (RLS-enforced); it reads no
// sealed command bytes, so no plaintext identity assertion or digest can leave
// through this path.
func (s *Store) ListCodeSigningIdentities(ctx context.Context, tenantID, destination string, limit int) ([]CodeSigningIdentityRow, error) {
	if limit <= 0 {
		limit = 50
	}
	var out []CodeSigningIdentityRow
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT op.operation_id,
			        CASE op.mode WHEN 'key' THEN 'managed' ELSE op.mode END AS public_mode,
			        op.status, op.request_hash,
			        op.created_at, op.updated_at, COALESCE(op.last_error, ''),
			        COALESCE(ob.status, 'not-published') AS transparency,
			        COALESCE(ob.last_error, '')          AS transparency_error
			   FROM code_signing_operations op
			   LEFT JOIN LATERAL (
			     SELECT status, last_error
			       FROM outbox
			      WHERE tenant_id = op.tenant_id
			        AND destination = $2
			        AND idempotency_key = 'codesign.rekor:' || op.operation_id
			      ORDER BY id DESC
			      LIMIT 1
			   ) ob ON true
			  WHERE op.tenant_id = $1
			  ORDER BY op.created_at DESC, op.operation_id
			  LIMIT $3`, tenantID, destination, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row CodeSigningIdentityRow
			if err := rows.Scan(&row.OperationID, &row.Mode, &row.Status, &row.RequestHash,
				&row.CreatedAt, &row.UpdatedAt, &row.LastError,
				&row.Transparency, &row.TransparencyError); err != nil {
				return err
			}
			// The Rekor handler refuses to acknowledge an entry whose signed
			// receipt does not verify, so a delivered row IS a verified entry.
			if row.Transparency == "delivered" {
				row.Transparency = "verified"
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) CodeSigningOperationByIdempotency(ctx context.Context, tenantID, key string) (CodeSigningOperation, bool, error) {
	var op CodeSigningOperation
	keyRef := CodeSigningIdempotencyKeyRef(key)
	operationID := CodeSigningOperationIDFromRef(tenantID, keyRef)
	legacyOperationID := LegacyCodeSigningOperationID(tenantID, key)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, operation_id, idempotency_key, mode, request_hash,
			        sealed_command, status, response, ephemeral_handle, cleanup_status,
			        command_outbox_id, COALESCE(cleanup_outbox_id, 0), last_error,
			        created_at, updated_at, COALESCE(source_event_id::text, ''),
			        COALESCE(approval_request_id::text, ''), COALESCE(approval_intent_digest, ''),
			        COALESCE(command_semantic_sha256, '')
			   FROM code_signing_operations
			  WHERE tenant_id = $1
			    AND (operation_id = $2 OR operation_id = $3)
			  ORDER BY CASE
			    WHEN operation_id = $3 THEN 0
			    ELSE 1
			  END`, tenantID, operationID, legacyOperationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		found := 0
		for rows.Next() {
			if err := scanCodeSigningOperation(rows, &op); err != nil {
				return err
			}
			found++
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if found == 0 {
			return pgx.ErrNoRows
		}
		if found != 1 {
			return fmt.Errorf("%w: current and legacy code-signing operations both exist", ErrIdempotencyConflict)
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CodeSigningOperation{}, false, nil
	}
	return op, err == nil, err
}

func (s *Store) CodeSigningOperationByID(ctx context.Context, tenantID, operationID string) (CodeSigningOperation, bool, error) {
	var op CodeSigningOperation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCodeSigningOperation(tx.QueryRow(ctx,
			`SELECT tenant_id::text, operation_id, idempotency_key, mode, request_hash,
			        sealed_command, status, response, ephemeral_handle, cleanup_status,
			        command_outbox_id, COALESCE(cleanup_outbox_id, 0), last_error,
				        created_at, updated_at, COALESCE(source_event_id::text, ''),
				        COALESCE(approval_request_id::text, ''), COALESCE(approval_intent_digest, ''),
				        COALESCE(command_semantic_sha256, '')
			   FROM code_signing_operations
			  WHERE tenant_id = $1 AND operation_id = $2`, tenantID, operationID), &op)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return CodeSigningOperation{}, false, nil
	}
	return op, err == nil, err
}

// CodeSigningApprovalConsumed reports whether this exact command event spent
// the exact code-signing capability. The worker uses this read-only guard so a
// legacy/v1 queued command cannot begin signing after dual control is enabled.
func (s *Store) CodeSigningApprovalConsumed(ctx context.Context, tenantID, resourceID, approvalRequestID, intentDigest, eventID string) (bool, error) {
	if tenantID == "" || resourceID == "" || approvalRequestID == "" || intentDigest == "" || eventID == "" {
		return false, errors.New("store: code-signing approval lookup is incomplete")
	}
	var consumed bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
			  SELECT 1 FROM operation_approval_requests
			   WHERE tenant_id = $1 AND id = $3 AND intent_digest = $4
			     AND resource_kind = 'code_signing' AND resource_id = $2
			     AND action = 'sign' AND status = 'consumed'
			     AND consumed_event_id = $5
			)`, tenantID, resourceID, approvalRequestID, intentDigest, eventID).Scan(&consumed)
	})
	return consumed, err
}

type codeSignRowScanner interface{ Scan(...any) error }

func scanCodeSigningOperation(row codeSignRowScanner, op *CodeSigningOperation) error {
	return row.Scan(
		&op.TenantID, &op.OperationID, &op.IdempotencyKey, &op.Mode,
		&op.RequestHash, &op.SealedCommand, &op.Status, &op.Response,
		&op.EphemeralHandle, &op.CleanupStatus, &op.CommandOutboxID,
		&op.CleanupOutboxID, &op.LastError, &op.CreatedAt, &op.UpdatedAt,
		&op.SourceEventID, &op.ApprovalRequestID, &op.ApprovalIntentDigest, &op.SemanticDigest,
	)
}

// ApplyCodeSigningIntentTx projects the immutable command and its worker intent
// in one tenant transaction (AN-2/AN-6). A second event for the same
// Idempotency-Key is a no-op only when every immutable operation and outbox
// identity field is identical. This check lives in the projector too: retained
// conflicting events and cold rebuilds do not pass through the request path.
func (s *Store) ApplyCodeSigningIntentTx(ctx context.Context, tx pgx.Tx, op CodeSigningOperation, commandPayload []byte) error {
	if op.TenantID == "" || op.OperationID == "" || op.IdempotencyKey == "" || op.RequestHash == "" || len(op.SealedCommand) == 0 || len(commandPayload) == 0 {
		return errors.New("store: code-signing intent is incomplete")
	}
	if op.Mode != "key" && op.Mode != "keyless" {
		return fmt.Errorf("store: unsupported code-signing mode %q", op.Mode)
	}
	if op.Approval != nil {
		if op.SourceEventID == "" || len(op.SemanticDigest) != 64 {
			return errors.New("store: approved code-signing intent lacks immutable source identity")
		}
		if op.HistoricalSemanticDigest != "" && len(op.HistoricalSemanticDigest) != 64 {
			return errors.New("store: approved code-signing historical semantic identity is invalid")
		}
		op.ApprovalRequestID = op.Approval.RequestID
		op.ApprovalIntentDigest = op.Approval.IntentDigest
	} else if op.SourceEventID != "" || op.ApprovalRequestID != "" || op.ApprovalIntentDigest != "" ||
		op.SemanticDigest != "" || op.HistoricalSemanticDigest != "" {
		return errors.New("store: unapproved code-signing intent carries approved source identity")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"codesign-intent\x1f"+op.TenantID+"\x1f"+op.IdempotencyKey); err != nil {
		return fmt.Errorf("store: lock code-signing intent: %w", err)
	}
	if err := normalizeLegacyCodeSigningProjectionKeyTx(ctx, tx, op); err != nil {
		return err
	}
	if err := normalizeCollidingLegacyCodeSigningKeyTx(ctx, tx, op); err != nil {
		return err
	}
	var (
		existingOutboxID int64
		exactOperation   bool
		existingSemantic string
	)
	err := tx.QueryRow(ctx,
		`SELECT command_outbox_id,
			        operation_id = $3 AND idempotency_key = $2 AND mode = $4 AND request_hash = $5
			        AND sealed_command = $6 AND created_at = $7
			        AND COALESCE(source_event_id::text, '') = $8
			        AND COALESCE(approval_request_id::text, '') = $9
			        AND COALESCE(approval_intent_digest, '') = $10,
			        COALESCE(command_semantic_sha256, '')
		   FROM code_signing_operations
		  WHERE tenant_id = $1 AND (idempotency_key = $2 OR operation_id = $3)
		  ORDER BY CASE WHEN idempotency_key = $2 THEN 0 ELSE 1 END
		  LIMIT 1`,
		op.TenantID, op.IdempotencyKey, op.OperationID, op.Mode, op.RequestHash,
		op.SealedCommand, op.CreatedAt, op.SourceEventID, op.ApprovalRequestID,
		op.ApprovalIntentDigest).Scan(&existingOutboxID, &exactOperation, &existingSemantic)
	if err == nil {
		if !exactOperation {
			return fmt.Errorf("%w: code-signing idempotency key already binds a different command", ErrIdempotencyConflict)
		}
		if existingSemantic != op.SemanticDigest {
			if op.HistoricalSemanticDigest == "" || existingSemantic != op.HistoricalSemanticDigest {
				return fmt.Errorf("%w: code-signing command semantic identity differs", ErrIdempotencyConflict)
			}
			tag, updateErr := tx.Exec(ctx, `UPDATE code_signing_operations
				SET command_semantic_sha256 = $4
				WHERE tenant_id = $1 AND operation_id = $2
				  AND COALESCE(command_semantic_sha256, '') = $3`,
				op.TenantID, op.OperationID, existingSemantic, op.SemanticDigest)
			if updateErr != nil {
				return updateErr
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("%w: legacy code-signing semantic identity changed during upgrade", ErrIdempotencyConflict)
			}
		}
		commandKey := "codesign.command:" + op.OperationID
		outboxID, ensureErr := ensureCodeSigningOutboxTx(ctx, tx, op.TenantID, CodeSigningCommandDestination,
			codeSigningEffectLane(CodeSigningCommandDestination, op.OperationID), commandKey, commandPayload)
		if ensureErr != nil {
			return ensureErr
		}
		if outboxID != existingOutboxID {
			return fmt.Errorf("%w: code-signing operation/outbox identity mismatch", ErrIdempotencyConflict)
		}
		if err := s.consumeCodeSigningApprovalTx(ctx, tx, op); err != nil {
			return err
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := s.consumeCodeSigningApprovalTx(ctx, tx, op); err != nil {
		return err
	}
	commandKey := "codesign.command:" + op.OperationID
	outboxID, err := ensureCodeSigningOutboxTx(ctx, tx, op.TenantID, CodeSigningCommandDestination,
		codeSigningEffectLane(CodeSigningCommandDestination, op.OperationID), commandKey, commandPayload)
	if err != nil {
		return err
	}
	cleanupStatus := "not_required"
	command, err := tx.Exec(ctx,
		`INSERT INTO code_signing_operations
			        (tenant_id, operation_id, idempotency_key, mode, request_hash,
			         sealed_command, status, cleanup_status, command_outbox_id,
			         created_at, updated_at, source_event_id, approval_request_id,
			         approval_intent_digest, command_semantic_sha256)
			 VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7, $8, $9, $9,
			         NULLIF($10, '')::uuid, NULLIF($11, '')::uuid, NULLIF($12, ''), NULLIF($13, ''))
		 ON CONFLICT DO NOTHING`,
		op.TenantID, op.OperationID, op.IdempotencyKey, op.Mode, op.RequestHash,
		op.SealedCommand, cleanupStatus, outboxID, op.CreatedAt, op.SourceEventID,
		op.ApprovalRequestID, op.ApprovalIntentDigest, op.SemanticDigest)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("%w: code-signing operation identity collision", ErrIdempotencyConflict)
	}
	return nil
}

// normalizeLegacyCodeSigningProjectionKeyTx upgrades an old warm v1/v2 row from
// its raw key to the exact operation-bound form emitted by the current projector.
// Both the historical UUID and the one-way digest must agree, so an arbitrary
// mapping-shaped value cannot rename another operation.
func normalizeLegacyCodeSigningProjectionKeyTx(ctx context.Context, tx pgx.Tx, op CodeSigningOperation) error {
	if !IsLegacyCodeSigningStorageKey(op.IdempotencyKey, op.OperationID) {
		return nil
	}
	var existing string
	err := tx.QueryRow(ctx, `SELECT idempotency_key FROM code_signing_operations
		WHERE tenant_id = $1 AND operation_id = $2 FOR UPDATE`, op.TenantID, op.OperationID).Scan(&existing)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil || existing == op.IdempotencyKey {
		return err
	}
	if LegacyCodeSigningOperationID(op.TenantID, existing) != op.OperationID ||
		LegacyCodeSigningStorageKey(op.OperationID, existing) != op.IdempotencyKey {
		return fmt.Errorf("%w: legacy code-signing projection key differs", ErrIdempotencyConflict)
	}
	tag, err := tx.Exec(ctx, `UPDATE code_signing_operations SET idempotency_key = $3
		WHERE tenant_id = $1 AND operation_id = $2 AND idempotency_key = $4`,
		op.TenantID, op.OperationID, op.IdempotencyKey, existing)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: legacy code-signing projection key changed during upgrade", ErrIdempotencyConflict)
	}
	return nil
}

// normalizeCollidingLegacyCodeSigningKeyTx handles the constructed boundary
// J = Ref(K) during an in-place upgrade. A warm v1/v2 row may still store raw J,
// which would collide with the new v3 row for K even though their operation IDs
// are now domain-separated. Exact historical UUID proof lets this transaction
// move only that legacy row to its non-PII operation-bound representation.
func normalizeCollidingLegacyCodeSigningKeyTx(ctx context.Context, tx pgx.Tx, op CodeSigningOperation) error {
	if !IsCodeSigningIdempotencyKeyRef(op.IdempotencyKey) ||
		CodeSigningOperationIDFromRef(op.TenantID, op.IdempotencyKey) != op.OperationID {
		return nil
	}
	legacyOperationID := LegacyCodeSigningOperationID(op.TenantID, op.IdempotencyKey)
	mapped := LegacyCodeSigningStorageKey(legacyOperationID, op.IdempotencyKey)
	_, err := tx.Exec(ctx, `UPDATE code_signing_operations
		SET idempotency_key = $4, updated_at = now()
		WHERE tenant_id = $1 AND operation_id = $2 AND idempotency_key = $3`,
		op.TenantID, legacyOperationID, op.IdempotencyKey, mapped)
	return err
}

func (s *Store) consumeCodeSigningApprovalTx(ctx context.Context, tx pgx.Tx, op CodeSigningOperation) error {
	if op.Approval == nil {
		return nil
	}
	if op.SourceEventID == "" {
		return errors.New("store: approved code-signing intent has no source event")
	}
	expectedResource, err := CodeSigningApprovalResourceIDForOperation(
		op.TenantID, op.OperationID, op.RequestHash, op.IdempotencyKey, op.Approval.ResourceID,
	)
	if err != nil {
		return err
	}
	if op.Approval.ResourceKind != "code_signing" || op.Approval.ResourceID != expectedResource ||
		op.Approval.Action != "sign" || op.Approval.TargetVersion != 0 {
		return fmt.Errorf("%w: code-signing approval resource binding differs", ErrApprovalDrifted)
	}
	if err := s.ConsumeOperationApprovalTx(ctx, tx, op.TenantID, *op.Approval, op.SourceEventID, op.CreatedAt); err != nil {
		return fmt.Errorf("store: consume code-signing approval: %w", err)
	}
	return nil
}

// ApplyCodeSigningCompletedTx stores the exact API response and, in the same
// projection transaction, creates the Rekor and key-cleanup intents. Thus a
// crash can observe neither a completion without its follow-up work nor follow-up
// work without the immutable completion event.
func (s *Store) ApplyCodeSigningCompletedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, operationID, requestHash string,
	response []byte,
	rekorDestination string,
	rekorPayload []byte,
	ephemeralHandle string,
	at time.Time,
) error {
	if tenantID == "" || operationID == "" || requestHash == "" || len(response) == 0 || rekorDestination == "" || len(rekorPayload) == 0 {
		return errors.New("store: code-signing completion is incomplete")
	}
	if _, err := ensureCodeSigningOutboxTx(ctx, tx, tenantID, rekorDestination,
		codeSigningEffectLane(rekorDestination, operationID), "codesign.rekor:"+operationID, rekorPayload); err != nil {
		return err
	}
	var cleanupID any
	cleanupStatus := "not_required"
	if ephemeralHandle != "" {
		body := []byte(fmt.Sprintf(`{"operation_id":%q}`, operationID))
		id, err := ensureCodeSigningOutboxTx(ctx, tx, tenantID, CodeSigningCleanupDestination,
			codeSigningEffectLane(CodeSigningCleanupDestination, operationID), "codesign.cleanup:"+operationID, body)
		if err != nil {
			return err
		}
		cleanupID = id
		cleanupStatus = "pending"
	}
	tag, err := tx.Exec(ctx,
		`UPDATE code_signing_operations
		    SET status = 'completed', response = $4, ephemeral_handle = $5,
		        cleanup_status = $6, cleanup_outbox_id = $7, last_error = '',
		        updated_at = $8
		  WHERE tenant_id = $1 AND operation_id = $2 AND request_hash = $3
		    AND status IN ('queued', 'completed')`,
		tenantID, operationID, requestHash, response, ephemeralHandle,
		cleanupStatus, cleanupID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ApplyCodeSigningFailedTx(ctx context.Context, tx pgx.Tx, tenantID, operationID, failure, ephemeralHandle string, at time.Time) error {
	if tenantID == "" || operationID == "" || failure == "" {
		return errors.New("store: code-signing failure is incomplete")
	}
	var cleanupID any
	cleanupStatus := "not_required"
	if ephemeralHandle != "" {
		body := []byte(fmt.Sprintf(`{"operation_id":%q}`, operationID))
		id, err := ensureCodeSigningOutboxTx(ctx, tx, tenantID, CodeSigningCleanupDestination,
			codeSigningEffectLane(CodeSigningCleanupDestination, operationID), "codesign.cleanup:"+operationID, body)
		if err != nil {
			return err
		}
		cleanupID = id
		cleanupStatus = "pending"
	}
	tag, err := tx.Exec(ctx,
		`UPDATE code_signing_operations
		    SET status = CASE WHEN status = 'completed' THEN status ELSE 'failed' END,
		        last_error = CASE WHEN status = 'completed' THEN last_error ELSE $3 END,
		        ephemeral_handle = CASE WHEN status = 'completed' THEN ephemeral_handle ELSE $4 END,
		        cleanup_status = CASE WHEN status = 'completed' THEN cleanup_status ELSE $5 END,
		        cleanup_outbox_id = CASE WHEN status = 'completed' THEN cleanup_outbox_id ELSE $6 END,
		        updated_at = GREATEST(updated_at, $7)
		  WHERE tenant_id = $1 AND operation_id = $2`, tenantID, operationID, failure,
		ephemeralHandle, cleanupStatus, cleanupID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ApplyCodeSigningCleanupCompletedTx(ctx context.Context, tx pgx.Tx, tenantID, operationID string, at time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE code_signing_operations
		    SET cleanup_status = 'completed', updated_at = GREATEST(updated_at, $3)
		  WHERE tenant_id = $1 AND operation_id = $2 AND mode = 'keyless'
		    AND cleanup_status IN ('pending', 'completed')`, tenantID, operationID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func codeSigningEffectLane(destination, operationID string) string {
	return destination + ":" + operationID
}

func ensureCodeSigningOutboxTx(ctx context.Context, tx pgx.Tx, tenantID, destination, effectLane, key string, payload []byte) (int64, error) {
	if tenantID == "" || destination == "" || effectLane == "" || key == "" || len(payload) == 0 {
		return 0, errors.New("store: code-signing outbox identity is incomplete")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"codesign-outbox\x1f"+tenantID+"\x1f"+key); err != nil {
		return 0, err
	}
	var id int64
	var foundDestination string
	var foundEffectLane string
	var foundPayload []byte
	err := tx.QueryRow(ctx,
		`SELECT id, destination, effect_lane, payload FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id LIMIT 1`, tenantID, key).Scan(&id, &foundDestination, &foundEffectLane, &foundPayload)
	if err == nil {
		if foundDestination != destination || (foundEffectLane != "" && foundEffectLane != effectLane) || !bytes.Equal(foundPayload, payload) {
			return 0, fmt.Errorf("%w: code-signing outbox idempotency collision for %q", ErrIdempotencyConflict, key)
		}
		if foundEffectLane == "" {
			if _, err := tx.Exec(ctx,
				`UPDATE outbox SET effect_lane = $3
				  WHERE tenant_id = $1 AND id = $2 AND effect_lane = ''`, tenantID, id, effectLane); err != nil {
				return 0, err
			}
		}
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	err = tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		tenantID, destination, effectLane, payload, key).Scan(&id)
	return id, err
}
