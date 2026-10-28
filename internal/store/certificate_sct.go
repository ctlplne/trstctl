// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// CertificateSCT is what one CT log answered for one submission (A213): its
// SCT, whether that verified against the log key the request named, and
// whether the log has proven the entry is in its tree.
type CertificateSCT struct {
	TenantID             string
	SubmissionID         string
	LeafFingerprint      string
	LogURL               string
	LogID                string
	EntryType            string
	SCTTimestamp         time.Time
	SCTStatus            string
	SCTReason            string
	LeafHash             string
	LogPublicKey         []byte
	AllowPrivateEndpoint bool
	PrivateEgressCIDRs   []string
	InclusionStatus      string
	InclusionReason      string
	LeafIndex            *int64
	TreeSize             *int64
	RootHash             string
	InclusionCheckedAt   *time.Time
	RecordedAt           time.Time
	EventSequence        uint64
}

// SCT and inclusion states.
const (
	SCTVerified          = "verified"
	SCTInvalid           = "invalid"
	SCTUnverified        = "unverified"
	InclusionPending     = "pending"
	InclusionVerified    = "verified"
	InclusionNotIncluded = "not_included"
	InclusionProofBad    = "proof_invalid"
	InclusionNotChecked  = "not_checked"
)

const certificateSCTColumns = `tenant_id::text, submission_id::text, leaf_fingerprint, log_url, log_id, entry_type,
	sct_timestamp, sct_status, sct_reason, leaf_hash, log_public_key, allow_private_endpoint, private_egress_cidrs,
	inclusion_status, inclusion_reason, leaf_index, tree_size, root_hash, inclusion_checked_at, recorded_at, event_sequence`

func scanCertificateSCT(row pgx.Row, c *CertificateSCT) error {
	var seq int64
	if err := row.Scan(&c.TenantID, &c.SubmissionID, &c.LeafFingerprint, &c.LogURL, &c.LogID, &c.EntryType,
		&c.SCTTimestamp, &c.SCTStatus, &c.SCTReason, &c.LeafHash, &c.LogPublicKey, &c.AllowPrivateEndpoint,
		&c.PrivateEgressCIDRs, &c.InclusionStatus, &c.InclusionReason, &c.LeafIndex, &c.TreeSize, &c.RootHash,
		&c.InclusionCheckedAt, &c.RecordedAt, &seq); err != nil {
		return err
	}
	c.EventSequence = uint64(seq) // #nosec G115 -- positive by constraint (CWE-190)
	return nil
}

// ApplyCertificateSCTRecordedTx keeps a submission's newest SCT; a replayed or
// older one changes nothing.
func (s *Store) ApplyCertificateSCTRecordedTx(ctx context.Context, tx pgx.Tx, c CertificateSCT) error {
	cidrs := c.PrivateEgressCIDRs
	if cidrs == nil {
		cidrs = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO certificate_scts (tenant_id, submission_id, leaf_fingerprint, log_url, log_id, entry_type,
		        sct_timestamp, sct_status, sct_reason, leaf_hash, log_public_key, allow_private_endpoint,
		        private_egress_cidrs, inclusion_status, recorded_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		 ON CONFLICT (tenant_id, submission_id) DO UPDATE
		    SET leaf_fingerprint = EXCLUDED.leaf_fingerprint, log_url = EXCLUDED.log_url, log_id = EXCLUDED.log_id,
		        entry_type = EXCLUDED.entry_type, sct_timestamp = EXCLUDED.sct_timestamp,
		        sct_status = EXCLUDED.sct_status, sct_reason = EXCLUDED.sct_reason, leaf_hash = EXCLUDED.leaf_hash,
		        log_public_key = EXCLUDED.log_public_key, allow_private_endpoint = EXCLUDED.allow_private_endpoint,
		        private_egress_cidrs = EXCLUDED.private_egress_cidrs, inclusion_status = EXCLUDED.inclusion_status,
		        inclusion_reason = '', leaf_index = NULL, tree_size = NULL, root_hash = '',
		        inclusion_checked_at = NULL, recorded_at = EXCLUDED.recorded_at,
		        event_sequence = EXCLUDED.event_sequence
		  WHERE certificate_scts.event_sequence < EXCLUDED.event_sequence`,
		c.TenantID, c.SubmissionID, c.LeafFingerprint, c.LogURL, c.LogID, c.EntryType, c.SCTTimestamp,
		c.SCTStatus, c.SCTReason, c.LeafHash, c.LogPublicKey, c.AllowPrivateEndpoint, cidrs, c.InclusionStatus,
		c.RecordedAt, int64(c.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// ApplyCertificateSCTInclusionTx records what an inclusion check found for a
// submission's SCT; an older or replayed result changes nothing.
func (s *Store) ApplyCertificateSCTInclusionTx(ctx context.Context, tx pgx.Tx, c CertificateSCT) error {
	_, err := tx.Exec(ctx,
		`UPDATE certificate_scts
		    SET inclusion_status = $3, inclusion_reason = $4, leaf_index = $5, tree_size = $6, root_hash = $7,
		        inclusion_checked_at = $8, event_sequence = $9
		  WHERE tenant_id = $1 AND submission_id = $2 AND event_sequence < $9`,
		c.TenantID, c.SubmissionID, c.InclusionStatus, c.InclusionReason, c.LeafIndex, c.TreeSize, c.RootHash,
		c.InclusionCheckedAt, int64(c.EventSequence)) // #nosec G115 -- event sequences fit int64 (CWE-190)
	return err
}

// CertificateSCTs returns the SCTs recorded for a certificate, newest first.
func (s *Store) CertificateSCTs(ctx context.Context, tenantID, leafFingerprint string) ([]CertificateSCT, error) {
	var out []CertificateSCT
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+certificateSCTColumns+` FROM certificate_scts
			  WHERE tenant_id = $1 AND leaf_fingerprint = $2 ORDER BY sct_timestamp DESC, submission_id LIMIT 32`,
			tenantID, leafFingerprint)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CertificateSCT
			if err := scanCertificateSCT(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// PendingCertificateSCTInclusions returns verified SCTs whose inclusion is not
// yet proven, oldest first and bounded.
func (s *Store) PendingCertificateSCTInclusions(ctx context.Context, tenantID string, limit int) ([]CertificateSCT, error) {
	var out []CertificateSCT
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+certificateSCTColumns+` FROM certificate_scts
			  WHERE tenant_id = $1 AND inclusion_status = 'pending' ORDER BY sct_timestamp, submission_id LIMIT $2`,
			tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CertificateSCT
			if err := scanCertificateSCT(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// TenantsWithPendingCTInclusions is the leader-only cross-tenant enumerator
// for the inclusion poll. Every row read after it re-enters tenant RLS.
func (s *Store) TenantsWithPendingCTInclusions(ctx context.Context) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — this cross-tenant system leader enumerates only tenant IDs with an SCT awaiting its inclusion proof; the poll re-enters tenant RLS before reading any SCT.
		`SELECT DISTINCT tenant_id::text FROM certificate_scts WHERE inclusion_status = 'pending' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	return tenants, rows.Err()
}
