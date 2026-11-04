// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrPAMRecordingNotFound means the session has no recording.
var ErrPAMRecordingNotFound = errors.New("store: PAM session recording not found")

// PAMRecording indexes one gateway session's recording (A255).
type PAMRecording struct {
	TenantID, SessionID, GatewayAgentID string
	Status                              string // recording, sealed
	Chunks                              int
	Bytes                               int64
	ChainHead                           string
	StartedAt, LastChunkAt              time.Time
	SealedAt                            *time.Time
	FinalReceived                       bool
	ManifestRef, ManifestSHA256         string
	ManifestSignature                   string
	// LegalHold keeps a sealed recording past retention (A255);
	// DeletedAt marks one whose objects retention removed.
	LegalHold       bool
	LegalHoldReason string
	DeletedAt       *time.Time
}

// PAMRecordingChunk is one stored chunk, in storage order (Ord).
type PAMRecordingChunk struct {
	TenantID, SessionID         string
	Ord, Attempt, Seq           int
	ObjectRef                   string
	SHA256, SealedSHA256, Chain string
	Size                        int
	StoredAt                    time.Time
}

// ApplyPAMRecordingChunkStoredTx projects pam.session.recording_chunk_stored:
// the chunk row, and the recording row it extends (created by the first
// chunk). Replays are idempotent on the chunk's place.
func (s *Store) ApplyPAMRecordingChunkStoredTx(ctx context.Context, tx pgx.Tx, c PAMRecordingChunk, gatewayAgentID string, final bool) error {
	tag, err := tx.Exec(ctx, `INSERT INTO pam_session_recording_chunks
	        (tenant_id, session_id, ord, attempt, seq, object_ref, sha256, sealed_sha256, chain, size, stored_at)
	 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	 ON CONFLICT DO NOTHING`,
		c.TenantID, c.SessionID, c.Ord, c.Attempt, c.Seq, c.ObjectRef, c.SHA256, c.SealedSHA256, c.Chain, c.Size, c.StoredAt)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO pam_session_recordings
	        (tenant_id, session_id, gateway_agent_id, status, chunks, bytes, chain_head, started_at, last_chunk_at, final_received)
	 VALUES ($1::uuid, $2::uuid, $3::uuid, 'recording', 1, $4, $5, $6, $6, $7)
	 ON CONFLICT (tenant_id, session_id) DO UPDATE
	    SET chunks = pam_session_recordings.chunks + 1,
	        bytes = pam_session_recordings.bytes + EXCLUDED.bytes,
	        chain_head = EXCLUDED.chain_head,
	        last_chunk_at = EXCLUDED.last_chunk_at,
	        final_received = pam_session_recordings.final_received OR EXCLUDED.final_received
	  WHERE pam_session_recordings.status = 'recording'`,
		c.TenantID, c.SessionID, gatewayAgentID, c.Size, c.Chain, c.StoredAt, final)
	return err
}

// ApplyPAMRecordingSealedTx projects pam.session.recording_sealed.
func (s *Store) ApplyPAMRecordingSealedTx(ctx context.Context, tx pgx.Tx, r PAMRecording) error {
	_, err := tx.Exec(ctx, `UPDATE pam_session_recordings
	    SET status = 'sealed', sealed_at = $3, manifest_ref = $4, manifest_sha256 = $5, manifest_signature = $6
	  WHERE tenant_id = $1::uuid AND session_id = $2::uuid AND status = 'recording'`,
		r.TenantID, r.SessionID, r.SealedAt, r.ManifestRef, r.ManifestSHA256, r.ManifestSignature)
	return err
}

const pamRecordingColumns = `tenant_id::text, session_id::text, gateway_agent_id::text, status, chunks, bytes,
    chain_head, started_at, last_chunk_at, sealed_at, final_received, manifest_ref, manifest_sha256, manifest_signature,
    legal_hold, legal_hold_reason, deleted_at`

func scanPAMRecording(row pgx.Row) (PAMRecording, error) {
	var r PAMRecording
	err := row.Scan(&r.TenantID, &r.SessionID, &r.GatewayAgentID, &r.Status, &r.Chunks, &r.Bytes, &r.ChainHead,
		&r.StartedAt, &r.LastChunkAt, &r.SealedAt, &r.FinalReceived, &r.ManifestRef, &r.ManifestSHA256, &r.ManifestSignature,
		&r.LegalHold, &r.LegalHoldReason, &r.DeletedAt)
	return r, err
}

// GetPAMRecording returns one session's recording index.
func (s *Store) GetPAMRecording(ctx context.Context, tenantID, sessionID string) (PAMRecording, error) {
	var out PAMRecording
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var scanErr error
		out, scanErr = scanPAMRecording(tx.QueryRow(ctx,
			`SELECT `+pamRecordingColumns+` FROM pam_session_recordings WHERE tenant_id = $1::uuid AND session_id = $2::uuid`,
			tenantID, sessionID))
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMRecording{}, ErrPAMRecordingNotFound
	}
	return out, err
}

// ListPAMRecordingChunks returns a recording's chunks in storage order from
// ord, at most limit.
func (s *Store) ListPAMRecordingChunks(ctx context.Context, tenantID, sessionID string, fromOrd, limit int) ([]PAMRecordingChunk, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	var out []PAMRecordingChunk
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id::text, session_id::text, ord, attempt, seq, object_ref, sha256,
		        sealed_sha256, chain, size, stored_at
		   FROM pam_session_recording_chunks
		  WHERE tenant_id = $1::uuid AND session_id = $2::uuid AND ord >= $3
		  ORDER BY ord LIMIT $4`, tenantID, sessionID, fromOrd, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c PAMRecordingChunk
			if err := rows.Scan(&c.TenantID, &c.SessionID, &c.Ord, &c.Attempt, &c.Seq, &c.ObjectRef, &c.SHA256,
				&c.SealedSHA256, &c.Chain, &c.Size, &c.StoredAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ListOpenPAMRecordings lists recordings still open whose last chunk is
// older than before, across tenants, for the worker that seals recordings
// whose gateway never sent its final chunk.
func (s *Store) ListOpenPAMRecordings(ctx context.Context, before time.Time, limit int) ([]PAMRecording, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant system worker: the PAM expiry worker finds recordings left open past their session; it reads index metadata only, and each seal is decided and recorded under the owning tenant's RLS context.
		`SELECT `+pamRecordingColumns+` FROM pam_session_recordings
		  WHERE status = 'recording' AND last_chunk_at < $1
		  ORDER BY last_chunk_at, tenant_id, session_id LIMIT $2`, before.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMRecording
	for rows.Next() {
		r, err := scanPAMRecording(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetGatewayJobForRecording returns a gateway session job this agent claimed
// at this attempt and has not reported. A recalled or lapsed claim still
// qualifies: its gateway flushes the session's last recording chunks before it
// reports. A newer claim (another attempt) does not.
func (s *Store) GetGatewayJobForRecording(ctx context.Context, tenantID, agentID string, jobID int64, attempt int, destination string) (AgentJobForRedemption, bool, error) {
	var out AgentJobForRedemption
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx,
			`SELECT destination, idempotency_key, payload, claim_attempts, COALESCE(required_agent_id::text, '')
			   FROM outbox
			  WHERE tenant_id = $1 AND id = $2
			    AND claimed_by_agent_id = $3::uuid
			    AND claim_attempts = $4
			    AND destination = $5
			    AND claim_completed_at IS NULL`,
			tenantID, jobID, agentID, attempt, destination).
			Scan(&out.Destination, &out.IdempotencyKey, &out.Payload, &out.ClaimAttempts, &out.RequiredAgentID)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	return out, found, err
}

// ApplyPAMRecordingLegalHoldTx projects pam.session.recording_legal_hold.
func (s *Store) ApplyPAMRecordingLegalHoldTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, hold bool, reason string) error {
	_, err := tx.Exec(ctx, `UPDATE pam_session_recordings SET legal_hold = $3, legal_hold_reason = $4
	  WHERE tenant_id = $1::uuid AND session_id = $2::uuid AND status <> 'deleted'`, tenantID, sessionID, hold, reason)
	return err
}

// ApplyPAMRecordingDeletedTx projects pam.session.recording_deleted: the
// objects are gone, the index (with its manifest digest) stays.
func (s *Store) ApplyPAMRecordingDeletedTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE pam_session_recordings SET status = 'deleted', deleted_at = coalesce(deleted_at, $3)
	  WHERE tenant_id = $1::uuid AND session_id = $2::uuid AND status = 'sealed' AND NOT legal_hold`, tenantID, sessionID, at)
	return err
}

// ListExpiredPAMRecordings lists sealed recordings sealed before cutoff and
// not on legal hold, across tenants, for the retention worker.
func (s *Store) ListExpiredPAMRecordings(ctx context.Context, cutoff time.Time, limit int) ([]PAMRecording, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant system worker: recording retention finds sealed recordings past their window; it reads index metadata only, and each deletion is decided and recorded under the owning tenant's RLS context.
		`SELECT `+pamRecordingColumns+` FROM pam_session_recordings
		  WHERE status = 'sealed' AND NOT legal_hold AND sealed_at < $1
		  ORDER BY sealed_at, tenant_id, session_id LIMIT $2`, cutoff.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMRecording
	for rows.Next() {
		r, err := scanPAMRecording(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
