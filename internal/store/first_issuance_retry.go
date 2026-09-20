// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

var ErrIssuanceRetryUnavailable = errors.New("store: first issuance is not eligible for retry")

// HasCompletedIdempotencyResult reads only existence. The receiver still opens
// and checks the exact protected binding before any signing operation.
func (s *Store) HasCompletedIdempotencyResult(ctx context.Context, tenantID, key string) (bool, error) {
	var found bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM idempotency_keys
			WHERE tenant_id=$1 AND key=$2 AND status='completed' AND request_binding<>'' AND octet_length(result)>0)`, tenantID, key).Scan(&found)
	})
	return found, err
}

// FirstIssuanceRetryCommand is internal receiver evidence. Payload never leaves
// the service through the public retry response.
type FirstIssuanceRetryCommand struct {
	Identity        Identity
	IdentityVersion uint64
	RequestKey      string
	OutboxID        int64
	OutboxKey       string
	Payload         []byte
	Status          string
	Attempts        int
}

// FirstIssuanceRetryReceipt is one immutable, bounded retry grant. An attempt
// consumes it by incrementing the ORIGINAL row's cumulative counter. Rebuilding
// this event cannot refund that attempt or change the receiver's command key.
type FirstIssuanceRetryReceipt struct {
	EventID               string    `json:"event_id"`
	IdentityID            string    `json:"identity_id"`
	RequestKey            string    `json:"request_key"`
	OutboxID              int64     `json:"outbox_id"`
	OriginalPayloadSHA256 string    `json:"original_payload_sha256"`
	Attempts              int       `json:"attempts"`
	ProofKind             string    `json:"proof_kind"`
	Reason                string    `json:"reason"`
	RequestedAt           time.Time `json:"requested_at"`
}

// Lock order matches lifecycle commands: identity first, then its outbox row.
func (s *Store) FirstIssuanceRetryCommandTx(ctx context.Context, tx pgx.Tx, tenantID, identityID, requestKey string, lock bool) (FirstIssuanceRetryCommand, error) {
	var command FirstIssuanceRetryCommand
	requestKey = strings.TrimSpace(requestKey)
	if requestKey == "" || len(requestKey) > 256 {
		return command, ErrIssuanceRetryUnavailable
	}
	identity, version, err := s.IdentityApprovalTargetTx(ctx, tx, tenantID, identityID, lock)
	if err != nil {
		return command, err
	}
	command.Identity, command.IdentityVersion, command.RequestKey = identity, version, requestKey
	var transitions int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_transitions
		WHERE tenant_id=$1 AND identity_id=$2 AND idempotency_key=$3
		AND event_type='identity.issued' AND from_state='requested' AND to_state='issued'`, tenantID, identityID, requestKey).Scan(&transitions); err != nil {
		return command, err
	}
	if transitions != 1 {
		return command, ErrIssuanceRetryUnavailable
	}
	query := `SELECT id,idempotency_key,payload,status,attempts FROM outbox
		WHERE tenant_id=$1 AND idempotency_key=$2 AND destination='ca.issue'`
	if lock {
		query += ` FOR UPDATE`
	}
	if err := tx.QueryRow(ctx, query, tenantID, "transition:"+requestKey).Scan(&command.OutboxID, &command.OutboxKey, &command.Payload, &command.Status, &command.Attempts); err != nil {
		return command, err
	}
	var body struct {
		IdentityID string `json:"identity_id"`
		To         string `json:"to"`
	}
	if json.Unmarshal(command.Payload, &body) != nil || body.IdentityID != identityID || body.To != "issued" {
		return command, ErrIdempotencyConflict
	}
	return command, nil
}

// ApplyFirstIssuanceRetryRequestedTx changes only bookkeeping for the exact
// retained command. Failed rows that have since consumed the grant, active
// leases, completed work, and retained-history rows already pruned are untouched.
func (s *Store) ApplyFirstIssuanceRetryRequestedTx(ctx context.Context, tx pgx.Tx, tenantID string, receipt FirstIssuanceRetryReceipt) error {
	if receipt.EventID == "" || receipt.IdentityID == "" || receipt.RequestKey == "" || receipt.OutboxID <= 0 || receipt.Attempts < 1 || receipt.Attempts >= 2147483647 ||
		len(receipt.OriginalPayloadSHA256) != 64 || receipt.ProofKind == "" || receipt.RequestedAt.IsZero() {
		return fmt.Errorf("store: invalid first-issuance retry receipt")
	}
	switch receipt.ProofKind {
	case "recorded_certificate", "prepared_signing_operation", "external_issuer_result":
	default:
		return fmt.Errorf("store: unknown first-issuance recovery proof")
	}
	var payload []byte
	err := tx.QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id=$1 AND id=$2
		AND idempotency_key=$3 AND destination='ca.issue' FOR UPDATE`, tenantID, receipt.OutboxID, "transition:"+receipt.RequestKey).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if crypto.SHA256Hex(payload) != receipt.OriginalPayloadSHA256 {
		return ErrIdempotencyConflict
	}
	var command struct {
		IdentityID string `json:"identity_id"`
		To         string `json:"to"`
	}
	if json.Unmarshal(payload, &command) != nil || command.IdentityID != receipt.IdentityID || command.To != "issued" {
		return ErrIdempotencyConflict
	}
	_, err = tx.Exec(ctx, `UPDATE outbox SET status='pending',next_attempt_at=$4,worker_id=NULL,lease_until=NULL,retry_attempt_limit=$3+1
		WHERE tenant_id=$1 AND id=$2 AND attempts=$3 AND status='failed'`, tenantID, receipt.OutboxID, receipt.Attempts, receipt.RequestedAt)
	return err
}
