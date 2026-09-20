// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	OwnershipReadinessOwner     = "current_owner_attestation"
	OwnershipReadinessException = "active_exception"
)

var ErrOwnershipNotReady = errors.New("store: ownership is not ready")

// OwnershipNotReadyError is intentionally structured: API callers need a safe
// 409 explanation while scheduler and tests need a closed reason code.
type OwnershipNotReadyError struct {
	IdentityID string
	Reason     string
}

func (e *OwnershipNotReadyError) Error() string {
	if e == nil {
		return ErrOwnershipNotReady.Error()
	}
	return fmt.Sprintf("%s: identity %s: %s", ErrOwnershipNotReady, e.IdentityID, e.Reason)
}

func (e *OwnershipNotReadyError) Unwrap() error { return ErrOwnershipNotReady }

// OwnershipException is the tenant projection of one explicit temporary
// decision to let an identity reach steady state without normal owner authority.
type OwnershipException struct {
	ID               string
	TenantID         string
	IdentityID       string
	Reason           string
	GrantedBy        string
	GrantedAt        time.Time
	ExpiresAt        time.Time
	RevokedBy        string
	RevokedAt        *time.Time
	RevocationReason string
	CreatedEventID   string
	LastEventSeq     uint64
}

func (e OwnershipException) Active(at time.Time) bool {
	return e.RevokedAt == nil && at.UTC().Before(e.ExpiresAt.UTC())
}

// OwnershipReadinessEvidence is copied into identity.deployed/identity.renewed.
// It freezes the exact authority used at command time, so cold replay validates
// the same owner decision or exception at that point in history rather than
// evaluating today's mutable clock.
type OwnershipReadinessEvidence struct {
	Mode               string     `json:"mode"`
	IdentityID         string     `json:"identity_id"`
	OwnerID            string     `json:"owner_id,omitempty"`
	OwnerModelDigest   string     `json:"owner_model_digest,omitempty"`
	AttestedBy         string     `json:"attested_by,omitempty"`
	VerifiedAt         *time.Time `json:"verified_at,omitempty"`
	AttestationDueAt   *time.Time `json:"attestation_due_at,omitempty"`
	ExceptionID        string     `json:"exception_id,omitempty"`
	ExceptionReason    string     `json:"exception_reason,omitempty"`
	ExceptionGrantedBy string     `json:"exception_granted_by,omitempty"`
	ExceptionGrantedAt *time.Time `json:"exception_granted_at,omitempty"`
	ExceptionExpiresAt *time.Time `json:"exception_expires_at,omitempty"`
	EvaluatedAt        time.Time  `json:"evaluated_at"`
}

// ResolveOwnershipReadinessTx locks the identity, its owner, and the chosen
// exception under one tenant transaction. A concurrent edit therefore wins
// either before this proof (and is observed) or after the deployment commit.
func (s *Store) ResolveOwnershipReadinessTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, identityID string,
	at time.Time,
	cadence time.Duration,
) (OwnershipReadinessEvidence, error) {
	if tenantID == "" || identityID == "" || cadence <= 0 {
		return OwnershipReadinessEvidence{}, fmt.Errorf("store: ownership readiness requires tenant, identity, and positive cadence")
	}
	at = at.UTC()
	var owner Owner
	var kind string
	err := tx.QueryRow(ctx, `
		SELECT o.id::text, o.tenant_id::text, o.kind, o.name, o.email, o.created_at,
		       coalesce(o.application_id, ''), coalesce(o.service, ''),
		       coalesce(o.business_unit, ''), coalesce(o.environment, ''),
		       o.escalation_chain, o.ownership_verified_at,
		       coalesce(o.ownership_verified_by, ''), coalesce(o.ownership_model_digest, '')
		  FROM identities AS i
		  JOIN owners AS o ON o.tenant_id = i.tenant_id AND o.id = i.owner_id
		 WHERE i.tenant_id = $1 AND i.id = $2
		 FOR UPDATE OF i, o`, tenantID, identityID).Scan(
		&owner.ID, &owner.TenantID, &kind, &owner.Name, &owner.Email, &owner.CreatedAt,
		&owner.ApplicationID, &owner.Service, &owner.BusinessUnit, &owner.Environment,
		&owner.EscalationChain, &owner.OwnershipVerifiedAt,
		&owner.OwnershipVerifiedBy, &owner.OwnershipModelDigest,
	)
	if err != nil {
		return OwnershipReadinessEvidence{}, err
	}
	owner.Kind = OwnerKind(kind)
	digest, err := OwnerModelDigest(owner)
	if err != nil {
		return OwnershipReadinessEvidence{}, err
	}
	due := owner.OwnershipAttestationDueAt(cadence)
	if owner.OwnershipComplete() && owner.OwnershipVerifiedAt != nil &&
		strings.TrimSpace(owner.OwnershipVerifiedBy) != "" &&
		owner.OwnershipModelDigest == digest && due != nil && at.Before(*due) {
		verified := owner.OwnershipVerifiedAt.UTC()
		dueAt := due.UTC()
		return OwnershipReadinessEvidence{
			Mode: OwnershipReadinessOwner, IdentityID: identityID, OwnerID: owner.ID,
			OwnerModelDigest: digest, AttestedBy: owner.OwnershipVerifiedBy,
			VerifiedAt: &verified, AttestationDueAt: &dueAt, EvaluatedAt: at,
		}, nil
	}

	var exception OwnershipException
	err = tx.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, identity_id::text, reason, granted_by,
		       granted_at, expires_at, coalesce(revoked_by, ''), revoked_at,
		       coalesce(revocation_reason, ''), created_event_id::text, last_event_seq
		  FROM ownership_readiness_exceptions
		 WHERE tenant_id = $1 AND identity_id = $2
		   AND revoked_at IS NULL AND expires_at > $3
		 ORDER BY expires_at DESC, id
		 LIMIT 1
		 FOR UPDATE`, tenantID, identityID, at).Scan(
		&exception.ID, &exception.TenantID, &exception.IdentityID, &exception.Reason,
		&exception.GrantedBy, &exception.GrantedAt, &exception.ExpiresAt,
		&exception.RevokedBy, &exception.RevokedAt, &exception.RevocationReason,
		&exception.CreatedEventID, &exception.LastEventSeq,
	)
	if err == nil {
		grantedAt, expiresAt := exception.GrantedAt.UTC(), exception.ExpiresAt.UTC()
		return OwnershipReadinessEvidence{
			Mode: OwnershipReadinessException, IdentityID: identityID, OwnerID: owner.ID,
			ExceptionID: exception.ID, ExceptionReason: exception.Reason,
			ExceptionGrantedBy: exception.GrantedBy, ExceptionGrantedAt: &grantedAt,
			ExceptionExpiresAt: &expiresAt, EvaluatedAt: at,
		}, nil
	}
	if err != pgx.ErrNoRows {
		return OwnershipReadinessEvidence{}, err
	}
	reason := "ownership_attestation_is_missing_or_stale"
	if !owner.OwnershipComplete() {
		reason = "owner_application_model_is_incomplete"
	} else if owner.OwnershipVerifiedAt != nil && owner.OwnershipModelDigest != digest {
		reason = "owner_application_model_changed_after_attestation"
	}
	return OwnershipReadinessEvidence{}, &OwnershipNotReadyError{IdentityID: identityID, Reason: reason}
}

// ValidateOwnershipReadinessEvidenceTx re-resolves the authority at the
// immutable event time and compares every field. It is called by the projector,
// including during a zero-state replay.
func (s *Store) ValidateOwnershipReadinessEvidenceTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	evidence OwnershipReadinessEvidence,
	cadence time.Duration,
) error {
	current, err := s.ResolveOwnershipReadinessTx(ctx, tx, tenantID, evidence.IdentityID, evidence.EvaluatedAt, cadence)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, evidence) {
		return fmt.Errorf("store: immutable ownership-readiness evidence drifted")
	}
	return nil
}

func (s *Store) ApplyOwnershipExceptionGrantedTx(ctx context.Context, tx pgx.Tx, exception OwnershipException) error {
	tag, err := tx.Exec(ctx, `
		INSERT INTO ownership_readiness_exceptions
		       (tenant_id, id, identity_id, reason, granted_by, granted_at, expires_at,
		        created_event_id, last_event_seq)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, id) DO UPDATE
		   SET last_event_seq = greatest(ownership_readiness_exceptions.last_event_seq, EXCLUDED.last_event_seq)
		 WHERE ownership_readiness_exceptions.identity_id = EXCLUDED.identity_id
		   AND ownership_readiness_exceptions.reason = EXCLUDED.reason
		   AND ownership_readiness_exceptions.granted_by = EXCLUDED.granted_by
		   AND ownership_readiness_exceptions.granted_at = EXCLUDED.granted_at
		   AND ownership_readiness_exceptions.expires_at = EXCLUDED.expires_at
		   AND ownership_readiness_exceptions.created_event_id = EXCLUDED.created_event_id`,
		exception.TenantID, exception.ID, exception.IdentityID, exception.Reason,
		exception.GrantedBy, exception.GrantedAt, exception.ExpiresAt,
		exception.CreatedEventID, int64(exception.LastEventSeq)) // #nosec G115 -- event sequences fit PostgreSQL bigint
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("store: ownership exception %s collides with different immutable grant evidence", exception.ID)
	}
	return nil
}

func (s *Store) ApplyOwnershipExceptionRevokedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, id, revokedBy, reason string,
	at time.Time,
	sequence uint64,
) error {
	tag, err := tx.Exec(ctx, `
		UPDATE ownership_readiness_exceptions
		   SET revoked_by = $3, revoked_at = $4, revocation_reason = $5, last_event_seq = $6
		 WHERE tenant_id = $1 AND id = $2 AND last_event_seq < $6`,
		tenantID, id, revokedBy, at, reason, int64(sequence)) // #nosec G115 -- event sequences fit PostgreSQL bigint
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("store: ownership exception %s cannot be revoked before its grant projection", id)
	}
	return nil
}

func (s *Store) GetOwnershipException(ctx context.Context, tenantID, id string) (OwnershipException, error) {
	var out OwnershipException
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanOwnershipException(tx.QueryRow(ctx, `
			SELECT id::text, tenant_id::text, identity_id::text, reason, granted_by,
			       granted_at, expires_at, coalesce(revoked_by, ''), revoked_at,
			       coalesce(revocation_reason, ''), created_event_id::text, last_event_seq
			  FROM ownership_readiness_exceptions
			 WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

func (s *Store) ListOwnershipExceptions(ctx context.Context, tenantID, identityID string) ([]OwnershipException, error) {
	var out []OwnershipException
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id::text, tenant_id::text, identity_id::text, reason, granted_by,
			       granted_at, expires_at, coalesce(revoked_by, ''), revoked_at,
			       coalesce(revocation_reason, ''), created_event_id::text, last_event_seq
			  FROM ownership_readiness_exceptions
			 WHERE tenant_id = $1 AND identity_id = $2
			 ORDER BY granted_at DESC, id`, tenantID, identityID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var exception OwnershipException
			if err := scanOwnershipException(rows, &exception); err != nil {
				return err
			}
			out = append(out, exception)
		}
		return rows.Err()
	})
	return out, err
}

type ownershipExceptionScanner interface {
	Scan(...any) error
}

func scanOwnershipException(row ownershipExceptionScanner, out *OwnershipException) error {
	var seq int64
	if err := row.Scan(&out.ID, &out.TenantID, &out.IdentityID, &out.Reason, &out.GrantedBy,
		&out.GrantedAt, &out.ExpiresAt, &out.RevokedBy, &out.RevokedAt,
		&out.RevocationReason, &out.CreatedEventID, &seq); err != nil {
		return err
	}
	out.LastEventSeq = uint64(seq) // #nosec G115 -- database constraint/event writer keeps sequence non-negative
	return nil
}

// ListOwnershipReattestationCandidates returns bounded owner work for one
// tenant. Never-attested complete owners get one initial request; previously
// attested owners get one request per stale verification edge.
func (s *Store) ListOwnershipReattestationCandidates(
	ctx context.Context,
	tenantID string,
	now time.Time,
	cadence time.Duration,
	limit int,
) ([]Owner, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []Owner
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT o.id::text, o.tenant_id::text, o.kind, o.name, o.email, o.created_at,
			       coalesce(o.application_id, ''), coalesce(o.service, ''),
			       coalesce(o.business_unit, ''), coalesce(o.environment, ''),
			       o.escalation_chain, o.ownership_verified_at,
			       coalesce(o.ownership_verified_by, ''), coalesce(o.ownership_model_digest, ''),
			       o.ownership_reattestation_requested_at, o.ownership_reattestation_requested_for
			  FROM owners AS o
			 WHERE o.tenant_id = $1
			   AND coalesce(o.application_id, '') <> '' AND coalesce(o.environment, '') <> ''
			   AND EXISTS (
			       SELECT 1 FROM identities AS i
			        WHERE i.tenant_id = o.tenant_id AND i.owner_id = o.id AND i.status <> 'retired')
			   AND ((o.ownership_verified_at IS NULL AND o.ownership_reattestation_requested_at IS NULL)
			        OR (o.ownership_verified_at IS NOT NULL
			            AND (coalesce(o.ownership_verified_by, '') = ''
			                 OR coalesce(o.ownership_model_digest, '') = ''
			                 OR o.ownership_verified_at + make_interval(secs => $3) <= $2)
			            AND o.ownership_reattestation_requested_for IS DISTINCT FROM o.ownership_verified_at))
			 ORDER BY o.ownership_verified_at NULLS FIRST, o.id
			 LIMIT $4`, tenantID, now.UTC(), int(cadence/time.Second), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var owner Owner
			var kind string
			if err := rows.Scan(&owner.ID, &owner.TenantID, &kind, &owner.Name, &owner.Email, &owner.CreatedAt,
				&owner.ApplicationID, &owner.Service, &owner.BusinessUnit, &owner.Environment,
				&owner.EscalationChain, &owner.OwnershipVerifiedAt,
				&owner.OwnershipVerifiedBy, &owner.OwnershipModelDigest,
				&owner.OwnershipReattestationRequestedAt, &owner.OwnershipReattestationRequestedFor); err != nil {
				return err
			}
			owner.Kind = OwnerKind(kind)
			out = append(out, owner)
		}
		return rows.Err()
	})
	return out, err
}

// ClaimOwnershipReattestationCandidateTx repeats the due predicate while holding
// the owner row lock. Two leaders may list the same owner, but only one can turn
// that verification edge into an event/outbox pair.
func (s *Store) ClaimOwnershipReattestationCandidateTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, ownerID string,
	now time.Time,
	cadence time.Duration,
) (Owner, bool, error) {
	var owner Owner
	var kind string
	err := tx.QueryRow(ctx, `
		SELECT o.id::text, o.tenant_id::text, o.kind, o.name, o.email, o.created_at,
		       coalesce(o.application_id, ''), coalesce(o.service, ''),
		       coalesce(o.business_unit, ''), coalesce(o.environment, ''),
		       o.escalation_chain, o.ownership_verified_at,
		       coalesce(o.ownership_verified_by, ''), coalesce(o.ownership_model_digest, ''),
		       o.ownership_reattestation_requested_at, o.ownership_reattestation_requested_for
		  FROM owners AS o
		 WHERE o.tenant_id = $1 AND o.id = $2
		   AND coalesce(o.application_id, '') <> '' AND coalesce(o.environment, '') <> ''
		   AND EXISTS (SELECT 1 FROM identities AS i WHERE i.tenant_id = o.tenant_id AND i.owner_id = o.id AND i.status <> 'retired')
		   AND ((o.ownership_verified_at IS NULL AND o.ownership_reattestation_requested_at IS NULL)
		        OR (o.ownership_verified_at IS NOT NULL
		            AND (coalesce(o.ownership_verified_by, '') = ''
		                 OR coalesce(o.ownership_model_digest, '') = ''
		                 OR o.ownership_verified_at + make_interval(secs => $4) <= $3)
		            AND o.ownership_reattestation_requested_for IS DISTINCT FROM o.ownership_verified_at))
		 FOR UPDATE`, tenantID, ownerID, now.UTC(), int(cadence/time.Second)).Scan(
		&owner.ID, &owner.TenantID, &kind, &owner.Name, &owner.Email, &owner.CreatedAt,
		&owner.ApplicationID, &owner.Service, &owner.BusinessUnit, &owner.Environment,
		&owner.EscalationChain, &owner.OwnershipVerifiedAt,
		&owner.OwnershipVerifiedBy, &owner.OwnershipModelDigest,
		&owner.OwnershipReattestationRequestedAt, &owner.OwnershipReattestationRequestedFor,
	)
	if err == pgx.ErrNoRows {
		return Owner{}, false, nil
	}
	if err != nil {
		return Owner{}, false, err
	}
	owner.Kind = OwnerKind(kind)
	return owner, true, nil
}

func (s *Store) TenantsWithOwnershipReattestationCandidates(
	ctx context.Context,
	now time.Time,
	cadence time.Duration,
) ([]string, error) {
	//trstctl:system-query — scheduler tenant enumeration is intentionally cross-tenant; each returned tenant is processed through WithTenant and FORCE RLS.
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT o.tenant_id::text
		  FROM owners AS o
		 WHERE coalesce(o.application_id, '') <> '' AND coalesce(o.environment, '') <> ''
		   AND EXISTS (SELECT 1 FROM identities AS i WHERE i.tenant_id = o.tenant_id AND i.owner_id = o.id AND i.status <> 'retired')
		   AND ((o.ownership_verified_at IS NULL AND o.ownership_reattestation_requested_at IS NULL)
		        OR (o.ownership_verified_at IS NOT NULL
		            AND (coalesce(o.ownership_verified_by, '') = ''
		                 OR coalesce(o.ownership_model_digest, '') = ''
		                 OR o.ownership_verified_at + make_interval(secs => $2) <= $1)
		            AND o.ownership_reattestation_requested_for IS DISTINCT FROM o.ownership_verified_at))
		 ORDER BY 1`, now.UTC(), int(cadence/time.Second))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}
