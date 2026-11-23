// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EventIngressProducerCommitment is the versioned, tenant-bound MAC of one
// normalized producer view. The caller computes MAC through internal/crypto
// with a key that stays outside PostgreSQL; this record never stores Data or
// Actor, including their unkeyed digest.
type EventIngressProducerCommitment struct {
	TenantScope, EventID, EventType, KeyID string
	MAC                                    []byte
	ExplicitTime                           bool
}

// StageEventIngressProducer commits the producer commitment before the
// admission callback can publish. The active ingress token and exact event
// scope/type bind this one-use journal row to the already reserved operation.
func (s *Store) StageEventIngressProducer(ctx context.Context, commitment EventIngressProducerCommitment) error {
	if s == nil || commitment.TenantScope == "" || commitment.EventID == "" ||
		commitment.EventType == "" || commitment.KeyID == "" || len(commitment.MAC) != 32 {
		return ErrRestoreAdmissionLost
	}
	token, ok := ctx.Value(restoreActivityTokenContextKey{}).(*restoreActivityToken)
	if !ok || token == nil || token.origin != s || token.lease == nil ||
		!token.active.Load() || !token.lease.active.Load() || token.kind != "ingress" ||
		token.lane != "event-append" || token.eventID != commitment.EventID ||
		ctx.Value(restoreIngressEventTypeContextKey{}) != commitment.EventType ||
		ctx.Value(restoreIngressTenantScopeContextKey{}) != commitment.TenantScope {
		return ErrRestoreAdmissionLost
	}
	activityTenant := commitment.TenantScope
	if _, err := uuid.Parse(activityTenant); err != nil {
		activityTenant = RestoreControlTenantID
	}
	if token.tenantID != activityTenant {
		return ErrRestoreAdmissionLost
	}
	token.lease.mu.Lock()
	defer token.lease.mu.Unlock()
	if !token.active.Load() || !token.lease.active.Load() {
		return ErrRestoreAdmissionLost
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, restoreAdmissionCommitKey); err != nil {
		return err
	}
	if err := s.SetTenantGUCTx(ctx, tx, activityTenant); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO trstctl_recovery.event_ingress_journal
		(tenant_id,operation_id,event_id,event_type,producer_tenant_scope,
		producer_key_id,producer_mac,explicit_time)
		SELECT a.tenant_id,a.operation_id,a.event_id,$3,$4,$5,$6,$7
		FROM trstctl_recovery.restore_activity_tokens AS a
		WHERE a.tenant_id=$1 AND a.operation_id=$2 AND a.event_id=$8
		AND a.activity_kind='ingress' AND a.lane='event-append' AND a.phase='started'`,
		activityTenant, token.operationID, commitment.EventType, commitment.TenantScope,
		commitment.KeyID, commitment.MAC, commitment.ExplicitTime, commitment.EventID)
	if err != nil {
		return fmt.Errorf("%w: stage exact ingress producer commitment: %v", ErrRestoreActivityUnresolved, err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("store: ingress producer commitment has no active start")
	}
	if _, err := token.lease.conn.Exec(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreAdmissionLost, err)
	}
	return tx.Commit(ctx)
}

func (s *Store) withActiveEventIngressJournalTx(ctx context.Context,
	fn func(context.Context, pgx.Tx, *restoreActivityToken) error,
) error {
	if s == nil || fn == nil {
		return ErrRestoreAdmissionLost
	}
	token, ok := ctx.Value(restoreActivityTokenContextKey{}).(*restoreActivityToken)
	if !ok || token == nil || token.origin != s || token.lease == nil ||
		!token.active.Load() || !token.lease.active.Load() || token.kind != "ingress" ||
		token.lane != "event-append" || token.eventID == "" {
		return ErrRestoreAdmissionLost
	}
	token.lease.mu.Lock()
	defer token.lease.mu.Unlock()
	if !token.active.Load() || !token.lease.active.Load() {
		return ErrRestoreAdmissionLost
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, restoreAdmissionCommitKey); err != nil {
		return err
	}
	if err := s.SetTenantGUCTx(ctx, tx, token.tenantID); err != nil {
		return err
	}
	if err := fn(ctx, tx, token); err != nil {
		return err
	}
	if _, err := token.lease.conn.Exec(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%w: %v", ErrRestoreAdmissionLost, err)
	}
	return tx.Commit(ctx)
}

// StageEventIngressCandidateWire commits the exact serialized wire hash before
// NATS is called. A later ambiguous ACK leaves this phase pending for keyed
// canonical reconciliation; a process/session loss cannot turn it terminal.
func (s *Store) StageEventIngressCandidateWire(ctx context.Context, wireSHA256 string) error {
	if !restoreArtifactDigest.MatchString(wireSHA256) {
		return ErrRestoreActivityUnresolved
	}
	return s.withActiveEventIngressJournalTx(ctx, func(ctx context.Context, tx pgx.Tx, token *restoreActivityToken) error {
		tag, err := tx.Exec(ctx, `UPDATE trstctl_recovery.event_ingress_journal
			SET attempted_wire_sha256=$3,phase='candidate_staged'
			WHERE tenant_id=$1 AND operation_id=$2 AND event_id=$4 AND phase='started'`,
			token.tenantID, token.operationID, wireSHA256, token.eventID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrRestoreActivityUnresolved
		}
		return nil
	})
}

// VerifyEventIngressNoPublication settles a producer whose admitted callback
// ended before any candidate wire was staged. The publication boundary must
// stage that wire before its first broker call, so a staged candidate remains
// ambiguous even when the caller later reports an error or loses its session.
func (s *Store) VerifyEventIngressNoPublication(ctx context.Context) error {
	return s.withActiveEventIngressJournalTx(ctx, func(ctx context.Context, tx pgx.Tx, token *restoreActivityToken) error {
		tag, err := tx.Exec(ctx, `UPDATE trstctl_recovery.event_ingress_journal
			SET phase='no_publication_verified',verified_at=now()
			WHERE tenant_id=$1 AND operation_id=$2 AND event_id=$3
			AND phase='started' AND attempted_wire_sha256 IS NULL`,
			token.tenantID, token.operationID, token.eventID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrRestoreActivityUnresolved
		}
		return nil
	})
}

// VerifyEventIngressCanonical records a broker-verified exact wire hash and
// sequence. A new publication must match its pre-I/O candidate byte-for-byte;
// a duplicate may have no attempted wire or a discarded different candidate.
// The caller must first authenticate the canonical raw NATS envelope and the
// producer-view MAC under the configured journal key.
func (s *Store) VerifyEventIngressCanonical(ctx context.Context, canonicalWireSHA256 string,
	sequence uint64, duplicate bool,
) error {
	if !restoreArtifactDigest.MatchString(canonicalWireSHA256) || sequence == 0 || sequence > uint64(^uint64(0)>>1) {
		return ErrRestoreActivityUnresolved
	}
	return s.withActiveEventIngressJournalTx(ctx, func(ctx context.Context, tx pgx.Tx, token *restoreActivityToken) error {
		phase := "published_verified"
		if duplicate {
			phase = "duplicate_verified"
		}
		tag, err := tx.Exec(ctx, `UPDATE trstctl_recovery.event_ingress_journal
			SET canonical_wire_sha256=$3,canonical_sequence=$4,phase=$5,verified_at=now()
			WHERE tenant_id=$1 AND operation_id=$2 AND event_id=$6
			AND (($7=false AND phase='candidate_staged' AND attempted_wire_sha256=$3)
			  OR ($7=true AND phase IN ('started','candidate_staged')))`,
			token.tenantID, token.operationID, canonicalWireSHA256,
			// #nosec G115 -- sequence was bounded to MaxInt64 before the transaction
			int64(sequence), phase, token.eventID, duplicate)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrRestoreActivityUnresolved
		}
		return nil
	})
}
