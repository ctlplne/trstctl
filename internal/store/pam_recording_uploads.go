// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// A278 part 3: recording chunks are staged, with their outbox entry, in one
// transaction; the outbox worker writes each sealed object in order and
// removes the staged row once the chunk's stored event is projected.

// ErrPAMRecordingUploadNotFound is a staged chunk that was already stored (or
// never staged).
var ErrPAMRecordingUploadNotFound = errors.New("store: PAM recording upload not found")

// PAMRecordingUpload is one accepted, not yet stored, recording chunk: its
// place (ord), its chain value and its sealed bytes.
type PAMRecordingUpload struct {
	TenantID, SessionID         string
	Attempt, Seq, Ord           int
	GatewayAgentID              string
	SHA256, SealedSHA256, Chain string
	Size                        int
	Final                       bool
	Sealed                      []byte
	StagedAt                    time.Time
}

// LockPAMRecordingSessionTx serializes one session's chunk acceptance, so its
// places and chain are assigned in order.
func LockPAMRecordingSessionTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "pam-recording-upload\x1f"+tenantID+"\x1f"+sessionID)
	return err
}

// ListPAMRecordingChunksTx is ListPAMRecordingChunks inside the caller's
// tenant transaction.
func (s *Store) ListPAMRecordingChunksTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) ([]PAMRecordingChunk, error) {
	rows, err := tx.Query(ctx, `SELECT tenant_id::text, session_id::text, ord, attempt, seq, object_ref, sha256,
	        sealed_sha256, chain, size, stored_at
	   FROM pam_session_recording_chunks
	  WHERE tenant_id = $1::uuid AND session_id = $2::uuid ORDER BY ord`, tenantID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMRecordingChunk
	for rows.Next() {
		var c PAMRecordingChunk
		if err := rows.Scan(&c.TenantID, &c.SessionID, &c.Ord, &c.Attempt, &c.Seq, &c.ObjectRef, &c.SHA256,
			&c.SealedSHA256, &c.Chain, &c.Size, &c.StoredAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const pamRecordingUploadMeta = `tenant_id::text, session_id::text, attempt, seq, ord, gateway_agent_id::text, sha256, sealed_sha256, chain, size, final, staged_at`

func scanPAMRecordingUploadMeta(row pgx.Row) (PAMRecordingUpload, error) {
	var u PAMRecordingUpload
	err := row.Scan(&u.TenantID, &u.SessionID, &u.Attempt, &u.Seq, &u.Ord, &u.GatewayAgentID, &u.SHA256, &u.SealedSHA256, &u.Chain, &u.Size, &u.Final, &u.StagedAt)
	return u, err
}

// ListPAMRecordingUploadsTx lists a session's staged chunks by place, without
// their sealed bytes.
func (s *Store) ListPAMRecordingUploadsTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) ([]PAMRecordingUpload, error) {
	rows, err := tx.Query(ctx, `SELECT `+pamRecordingUploadMeta+` FROM pam_recording_uploads
		WHERE tenant_id = $1::uuid AND session_id = $2::uuid ORDER BY ord`, tenantID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMRecordingUpload
	for rows.Next() {
		u, err := scanPAMRecordingUploadMeta(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PAMRecordingStagedBytesTx is how many sealed bytes wait for the object
// store, for one session and for its whole tenant.
func (s *Store) PAMRecordingStagedBytesTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID string) (session, tenant int64, err error) {
	err = tx.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(sealed)) FILTER (WHERE session_id = $2::uuid), 0),
	        COALESCE(sum(octet_length(sealed)), 0)
	   FROM pam_recording_uploads WHERE tenant_id = $1::uuid`, tenantID, sessionID).Scan(&session, &tenant)
	return session, tenant, err
}

// InsertPAMRecordingUploadTx stages one accepted chunk.
func (s *Store) InsertPAMRecordingUploadTx(ctx context.Context, tx pgx.Tx, u PAMRecordingUpload) error {
	_, err := tx.Exec(ctx, `INSERT INTO pam_recording_uploads
	        (tenant_id, session_id, attempt, seq, ord, gateway_agent_id, sha256, sealed_sha256, chain, size, final, sealed, staged_at)
	 VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7, $8, $9, $10, $11, $12, $13)`,
		u.TenantID, u.SessionID, u.Attempt, u.Seq, u.Ord, u.GatewayAgentID, u.SHA256, u.SealedSHA256, u.Chain, u.Size, u.Final, u.Sealed, u.StagedAt.UTC())
	return err
}

// GetPAMRecordingUpload returns one staged chunk with its sealed bytes.
func (s *Store) GetPAMRecordingUpload(ctx context.Context, tenantID, sessionID string, attempt, seq int) (PAMRecordingUpload, error) {
	var u PAMRecordingUpload
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+pamRecordingUploadMeta+`, sealed FROM pam_recording_uploads
			WHERE tenant_id = $1::uuid AND session_id = $2::uuid AND attempt = $3 AND seq = $4`, tenantID, sessionID, attempt, seq)
		return row.Scan(&u.TenantID, &u.SessionID, &u.Attempt, &u.Seq, &u.Ord, &u.GatewayAgentID, &u.SHA256, &u.SealedSHA256, &u.Chain, &u.Size, &u.Final, &u.StagedAt, &u.Sealed)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMRecordingUpload{}, ErrPAMRecordingUploadNotFound
	}
	return u, err
}

// LowestPAMRecordingUploadOrd is the place of a session's earliest staged
// chunk, which must be stored before any later one.
func (s *Store) LowestPAMRecordingUploadOrd(ctx context.Context, tenantID, sessionID string) (int, bool, error) {
	var ord *int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT min(ord) FROM pam_recording_uploads WHERE tenant_id = $1::uuid AND session_id = $2::uuid`,
			tenantID, sessionID).Scan(&ord)
	})
	if err != nil || ord == nil {
		return 0, false, err
	}
	return *ord, true, nil
}

// DeletePAMRecordingUpload removes a stored chunk's staged row.
func (s *Store) DeletePAMRecordingUpload(ctx context.Context, tenantID, sessionID string, attempt, seq int) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM pam_recording_uploads WHERE tenant_id = $1::uuid AND session_id = $2::uuid AND attempt = $3 AND seq = $4`,
			tenantID, sessionID, attempt, seq)
		return err
	})
}

// HasPAMRecordingUploads reports whether a session still has chunks waiting
// for the object store; its recording is not sealed until it has none.
func (s *Store) HasPAMRecordingUploads(ctx context.Context, tenantID, sessionID string) (bool, error) {
	var staged bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pam_recording_uploads WHERE tenant_id = $1::uuid AND session_id = $2::uuid)`,
			tenantID, sessionID).Scan(&staged)
	})
	return staged, err
}

// CountPAMRecordingUploads is how many of a session's chunks wait for the
// object store.
func (s *Store) CountPAMRecordingUploads(ctx context.Context, tenantID, sessionID string) (int, error) {
	var n int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pam_recording_uploads WHERE tenant_id = $1::uuid AND session_id = $2::uuid`,
			tenantID, sessionID).Scan(&n)
	})
	return n, err
}
