// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// EndpointRecoveryCheck is the latest recovery check of a contained host
// target (A210): who asked, and once the host answered, what its signed
// report said.
type EndpointRecoveryCheck struct {
	TenantID           string
	TargetID           string
	CheckID            string
	TargetRevision     string
	AgentID            string
	RequestedBy        string
	RequestedAt        time.Time
	RequestSequence    uint64
	Status             string
	Recovery           string
	RecoveryAction     string
	ExecutableSHA256   string
	ArgvSHA256         string
	Listener           string
	ServingFingerprint string
	Failure            string
	JobID              *int64
	EvidenceDigest     string
	CheckedAt          *time.Time
	EventSequence      uint64
}

// Recovery check statuses.
const (
	EndpointRecoveryCheckQueued  = "queued"
	EndpointRecoveryCheckChecked = "checked"
	EndpointRecoveryCheckFailed  = "failed"
)

const endpointRecoveryCheckColumns = `tenant_id::text, target_id::text, check_id::text, target_revision, agent_id::text,
	requested_by, requested_at, request_sequence, status, recovery, recovery_action, executable_sha256, argv_sha256,
	listener, serving_fingerprint, failure, job_id, evidence_digest, checked_at, event_sequence`

// ApplyEndpointRecoveryCheckRequestedTx makes a newer request the target's
// current check; its answer is empty until the host reports.
func (s *Store) ApplyEndpointRecoveryCheckRequestedTx(ctx context.Context, tx pgx.Tx, c EndpointRecoveryCheck) error {
	seq := int64(c.EventSequence) // #nosec G115 -- event sequences fit int64 (CWE-190)
	_, err := tx.Exec(ctx,
		`INSERT INTO endpoint_recovery_checks (tenant_id, target_id, check_id, target_revision, agent_id, requested_by,
		        requested_at, request_sequence, status, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'queued', $8)
		 ON CONFLICT (tenant_id, target_id) DO UPDATE
		    SET check_id = EXCLUDED.check_id, target_revision = EXCLUDED.target_revision,
		        agent_id = EXCLUDED.agent_id, requested_by = EXCLUDED.requested_by,
		        requested_at = EXCLUDED.requested_at, request_sequence = EXCLUDED.request_sequence,
		        status = 'queued', recovery = '', recovery_action = '', executable_sha256 = '', argv_sha256 = '',
		        listener = '', serving_fingerprint = '', failure = '', job_id = NULL, evidence_digest = '',
		        checked_at = NULL, event_sequence = EXCLUDED.event_sequence
		  WHERE endpoint_recovery_checks.event_sequence < EXCLUDED.event_sequence`,
		c.TenantID, c.TargetID, c.CheckID, c.TargetRevision, c.AgentID, c.RequestedBy, c.RequestedAt, seq)
	return err
}

// ApplyEndpointRecoveryCheckAnsweredTx records the host's signed answer, or
// its failure, on the request it answers. An answer to a request a newer one
// replaced changes nothing.
func (s *Store) ApplyEndpointRecoveryCheckAnsweredTx(ctx context.Context, tx pgx.Tx, c EndpointRecoveryCheck) error {
	if c.Status != EndpointRecoveryCheckChecked && c.Status != EndpointRecoveryCheckFailed {
		return errors.New("store: a recovery check answer is checked or failed")
	}
	_, err := tx.Exec(ctx,
		`UPDATE endpoint_recovery_checks
		    SET status = $4, recovery = $5, recovery_action = $6, executable_sha256 = $7, argv_sha256 = $8,
		        listener = $9, serving_fingerprint = $10, failure = $11, job_id = $12, evidence_digest = $13,
		        checked_at = $14, event_sequence = $15
		  WHERE tenant_id = $1 AND target_id = $2 AND check_id = $3 AND event_sequence < $15`,
		c.TenantID, c.TargetID, c.CheckID, c.Status, c.Recovery, c.RecoveryAction, c.ExecutableSHA256,
		c.ArgvSHA256, c.Listener, c.ServingFingerprint, c.Failure, c.JobID, c.EvidenceDigest, c.CheckedAt,
		int64(c.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// GetEndpointRecoveryCheck returns the target's latest recovery check.
func (s *Store) GetEndpointRecoveryCheck(ctx context.Context, tenantID, targetID string) (EndpointRecoveryCheck, bool, error) {
	var c EndpointRecoveryCheck
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var requestSeq, seq int64
		if err := tx.QueryRow(ctx, `SELECT `+endpointRecoveryCheckColumns+`
			   FROM endpoint_recovery_checks WHERE tenant_id = $1 AND target_id = $2`, tenantID, targetID).
			Scan(&c.TenantID, &c.TargetID, &c.CheckID, &c.TargetRevision, &c.AgentID, &c.RequestedBy,
				&c.RequestedAt, &requestSeq, &c.Status, &c.Recovery, &c.RecoveryAction, &c.ExecutableSHA256,
				&c.ArgvSHA256, &c.Listener, &c.ServingFingerprint, &c.Failure, &c.JobID, &c.EvidenceDigest,
				&c.CheckedAt, &seq); err != nil {
			return err
		}
		c.RequestSequence = uint64(requestSeq) // #nosec G115 -- positive by constraint (CWE-190)
		c.EventSequence = uint64(seq)          // #nosec G115 -- positive by constraint (CWE-190)
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return EndpointRecoveryCheck{}, false, nil
	}
	return c, err == nil, err
}

// EndpointContainmentReceipt is one containment command's receipt for an
// identity: enough to tell which target it stopped and when.
type EndpointContainmentReceipt struct {
	ID             string
	IdempotencyKey string
	Status         string
	Fingerprint    string
	UpdatedAt      time.Time
	EventSequence  uint64
}

// EndpointContainmentReceipts lists an identity's newest containment receipts
// (A210). A receipt's id is derived from its target id and request key, so a
// caller can tell which target each one stopped without the outbox row, which
// is reclaimed after delivery.
func (s *Store) EndpointContainmentReceipts(ctx context.Context, tenantID, identityID string, limit int) ([]EndpointContainmentReceipt, error) {
	var out []EndpointContainmentReceipt
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, idempotency_key, status, fingerprint, updated_at, coalesce(latest_event_sequence, 0)
			   FROM connector_delivery_receipts
			  WHERE tenant_id = $1 AND identity_id = $2 AND destination = 'endpoint.contain'
			  ORDER BY updated_at DESC, id DESC
			  LIMIT $3`, tenantID, identityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r EndpointContainmentReceipt
			var seq int64
			if err := rows.Scan(&r.ID, &r.IdempotencyKey, &r.Status, &r.Fingerprint, &r.UpdatedAt, &seq); err != nil {
				return err
			}
			r.EventSequence = uint64(seq) // #nosec G115 -- a projected event sequence (CWE-190)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
