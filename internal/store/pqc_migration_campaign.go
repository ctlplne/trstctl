// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrPQCCampaignClosed   = errors.New("pqc migration campaign is closed")
	ErrPQCCampaignExists   = errors.New("pqc migration campaign already exists")
	ErrPQCCampaignNotReady = errors.New("pqc migration campaign is not ready to close")
)

// PQCMigrationCampaign is the tenant-scoped read model projected from immutable
// pqc.migration_campaign.* events. The licensed migration engine is deliberately
// absent: this core record tracks work performed by any means.
type PQCMigrationCampaign struct {
	ID                    string
	TenantID              string
	Name                  string
	OwnerRef              string
	Deadline              time.Time
	Wave                  string
	ReadinessCriteria     []string
	ReadinessStatus       string
	ReadinessEvidenceRefs []string
	Status                string
	FindingCount          int
	PendingCount          int
	RemediatedCount       int
	ExceptedCount         int
	ClosureJWS            string
	ClosureJWKS           json.RawMessage
	ClosedBy              string
	CreatedAt             time.Time
	UpdatedAt             time.Time
	ClosedAt              *time.Time
	Findings              []PQCMigrationCampaignFinding
}

// PQCMigrationCampaignFinding is the immutable CBOM fact snapshot placed in a
// campaign plus the latest event-derived disposition and redacted evidence refs.
type PQCMigrationCampaignFinding struct {
	TenantID          string
	CampaignID        string
	FindingID         string
	FindingDigest     string
	Kind              string
	Location          string
	Algorithm         string
	KeyBits           int
	Protocol          string
	Cipher            string
	Disposition       string
	RemediationMethod string
	DispositionReason string
	EvidenceRefs      []string
	EvidenceDigests   []string
	DispositionedAt   *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type PQCMigrationCampaignUpdate struct {
	CampaignID            string
	OwnerRef              string
	Deadline              time.Time
	Wave                  string
	ReadinessCriteria     []string
	ReadinessStatus       string
	ReadinessEvidenceRefs []string
	UpdatedAt             time.Time
}

type PQCMigrationFindingDisposition struct {
	CampaignID        string
	FindingID         string
	Disposition       string
	RemediationMethod string
	Reason            string
	EvidenceRefs      []string
	EvidenceDigests   []string
	DispositionedAt   time.Time
}

type PQCMigrationCampaignClosure struct {
	CampaignID string
	SignedJWS  string
	PublicJWKS json.RawMessage
	ClosedBy   string
	ClosedAt   time.Time
}

func (s *Store) ApplyPQCMigrationCampaignStartedTx(ctx context.Context, tx pgx.Tx, campaign PQCMigrationCampaign, findings []PQCMigrationCampaignFinding) error {
	criteria := nonNilStrings(campaign.ReadinessCriteria)
	_, err := tx.Exec(ctx,
		`INSERT INTO pqc_migration_campaigns
		        (tenant_id, id, name, owner_ref, deadline, wave, readiness_criteria,
		         readiness_status, status, finding_count, pending_count,
		         remediated_count, excepted_count, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', 'open',
		         $8, $8, 0, 0, $9, $9)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		campaign.TenantID, campaign.ID, campaign.Name, campaign.OwnerRef,
		campaign.Deadline, campaign.Wave, criteria, len(findings), campaign.CreatedAt)
	if err != nil {
		return err
	}
	for _, finding := range findings {
		if _, err := tx.Exec(ctx,
			`INSERT INTO pqc_migration_campaign_findings
			        (tenant_id, campaign_id, finding_id, finding_digest, kind, location,
			         algorithm, key_bits, protocol, cipher, disposition, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', $11, $11)
			 ON CONFLICT (tenant_id, campaign_id, finding_id) DO NOTHING`,
			finding.TenantID, finding.CampaignID, finding.FindingID, finding.FindingDigest,
			finding.Kind, finding.Location, finding.Algorithm, finding.KeyBits,
			finding.Protocol, finding.Cipher, campaign.CreatedAt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ApplyPQCMigrationCampaignUpdatedTx(ctx context.Context, tx pgx.Tx, tenantID string, update PQCMigrationCampaignUpdate) error {
	tag, err := tx.Exec(ctx,
		`UPDATE pqc_migration_campaigns
		    SET owner_ref = $3,
		        deadline = $4,
		        wave = $5,
		        readiness_criteria = $6,
		        readiness_status = $7,
		        readiness_evidence_refs = $8,
		        updated_at = $9
		  WHERE tenant_id = $1
		    AND id = $2
		    AND status = 'open'`,
		tenantID, update.CampaignID, update.OwnerRef, update.Deadline, update.Wave,
		nonNilStrings(update.ReadinessCriteria), update.ReadinessStatus,
		nonNilStrings(update.ReadinessEvidenceRefs), update.UpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPQCCampaignClosed
	}
	return nil
}

func (s *Store) ApplyPQCMigrationFindingDispositionedTx(ctx context.Context, tx pgx.Tx, tenantID string, disposition PQCMigrationFindingDisposition) error {
	tag, err := tx.Exec(ctx,
		`UPDATE pqc_migration_campaign_findings f
		    SET disposition = $4,
		        remediation_method = $5,
		        disposition_reason = $6,
		        evidence_refs = $7,
		        evidence_digests = $8,
		        dispositioned_at = $9,
		        updated_at = $9
		   FROM pqc_migration_campaigns c
		  WHERE f.tenant_id = $1
		    AND f.campaign_id = $2
		    AND f.finding_id = $3
		    AND c.tenant_id = f.tenant_id
		    AND c.id = f.campaign_id
		    AND c.status = 'open'`,
		tenantID, disposition.CampaignID, disposition.FindingID, disposition.Disposition,
		disposition.RemediationMethod, disposition.Reason, nonNilStrings(disposition.EvidenceRefs),
		nonNilStrings(disposition.EvidenceDigests), disposition.DispositionedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	_, err = tx.Exec(ctx,
		`WITH counts AS (
		    SELECT count(*)::integer AS finding_count,
		           count(*) FILTER (WHERE disposition = 'pending')::integer AS pending_count,
		           count(*) FILTER (WHERE disposition = 'remediated')::integer AS remediated_count,
		           count(*) FILTER (WHERE disposition = 'excepted')::integer AS excepted_count
		      FROM pqc_migration_campaign_findings
		     WHERE tenant_id = $1
		       AND campaign_id = $2
		)
		UPDATE pqc_migration_campaigns c
		   SET finding_count = counts.finding_count,
		       pending_count = counts.pending_count,
		       remediated_count = counts.remediated_count,
		       excepted_count = counts.excepted_count,
		       updated_at = $3
		  FROM counts
		 WHERE c.tenant_id = $1
		   AND c.id = $2`,
		tenantID, disposition.CampaignID, disposition.DispositionedAt)
	return err
}

func (s *Store) ApplyPQCMigrationCampaignClosedTx(ctx context.Context, tx pgx.Tx, tenantID string, closure PQCMigrationCampaignClosure) error {
	tag, err := tx.Exec(ctx,
		`UPDATE pqc_migration_campaigns
		    SET status = 'closed',
		        closure_jws = $3,
		        closure_jwks = $4,
		        closed_by = $5,
		        closed_at = $6,
		        updated_at = $6
		  WHERE tenant_id = $1
		    AND id = $2
		    AND status = 'open'
		    AND readiness_status = 'passed'
		    AND pending_count = 0`,
		tenantID, closure.CampaignID, closure.SignedJWS, closure.PublicJWKS,
		closure.ClosedBy, closure.ClosedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 0 {
		return nil
	}
	var status, signed string
	var readiness string
	var pending int
	err = tx.QueryRow(ctx,
		`SELECT status, readiness_status, pending_count, closure_jws
		   FROM pqc_migration_campaigns
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, closure.CampaignID).Scan(&status, &readiness, &pending, &signed)
	if err != nil {
		return err
	}
	if status == "closed" && signed == closure.SignedJWS {
		return nil
	}
	if status == "closed" {
		return ErrPQCCampaignClosed
	}
	return fmt.Errorf("%w: readiness=%s pending=%d", ErrPQCCampaignNotReady, readiness, pending)
}

func (s *Store) GetPQCMigrationCampaign(ctx context.Context, tenantID, id string) (PQCMigrationCampaign, error) {
	var out PQCMigrationCampaign
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.GetPQCMigrationCampaignTx(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}

// LockPQCMigrationCampaignTx serializes one campaign's command-side
// read/normalize/append/project sequence. The lock identity includes tenant_id,
// so equal campaign UUIDs in different tenants never block one another.
//
// The lock must be taken before reading the campaign that will be signed or
// mutated. Holding it until the tenant transaction commits makes JetStream append
// order match projection order for this campaign and prevents a signed closure
// from describing state that a concurrent update changes before close commits.
func (s *Store) LockPQCMigrationCampaignTx(ctx context.Context, tx pgx.Tx, tenantID, campaignID string) error {
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"pqc-migration-campaign\x1f"+tenantID+"\x1f"+campaignID); err != nil {
		return fmt.Errorf("store: lock PQC migration campaign: %w", err)
	}
	return nil
}

// GetPQCMigrationCampaignTx reads a complete campaign using the caller's
// tenant-scoped transaction. Command paths use it after
// LockPQCMigrationCampaignTx so validation and signed evidence observe the exact
// state that the following event mutates.
func (s *Store) GetPQCMigrationCampaignTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (PQCMigrationCampaign, error) {
	campaign, err := scanPQCMigrationCampaign(tx.QueryRow(ctx,
		`SELECT tenant_id::text, id::text, name, owner_ref, deadline, wave,
		        readiness_criteria, readiness_status, readiness_evidence_refs, status,
		        finding_count, pending_count, remediated_count, excepted_count,
		        closure_jws, closure_jwks, closed_by, created_at, updated_at, closed_at
		   FROM pqc_migration_campaigns
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id))
	if err != nil {
		return PQCMigrationCampaign{}, err
	}
	findings, err := listPQCMigrationCampaignFindingsTx(ctx, tx, tenantID, id)
	if err != nil {
		return PQCMigrationCampaign{}, err
	}
	campaign.Findings = findings
	return campaign, nil
}

func (s *Store) ListPQCMigrationCampaignsPage(ctx context.Context, tenantID, after string, limit int) ([]PQCMigrationCampaign, error) {
	if after == "" {
		after = ZeroUUID
	}
	var out []PQCMigrationCampaign
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id::text, name, owner_ref, deadline, wave,
			        readiness_criteria, readiness_status, readiness_evidence_refs, status,
			        finding_count, pending_count, remediated_count, excepted_count,
			        closure_jws, closure_jwks, closed_by, created_at, updated_at, closed_at
			   FROM pqc_migration_campaigns
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id
			  LIMIT $3`,
			tenantID, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			campaign, err := scanPQCMigrationCampaign(rows)
			if err != nil {
				return err
			}
			out = append(out, campaign)
		}
		return rows.Err()
	})
	return out, err
}

func scanPQCMigrationCampaign(row pgx.Row) (PQCMigrationCampaign, error) {
	var campaign PQCMigrationCampaign
	var jwks []byte
	err := row.Scan(&campaign.TenantID, &campaign.ID, &campaign.Name, &campaign.OwnerRef,
		&campaign.Deadline, &campaign.Wave, &campaign.ReadinessCriteria,
		&campaign.ReadinessStatus, &campaign.ReadinessEvidenceRefs, &campaign.Status,
		&campaign.FindingCount, &campaign.PendingCount, &campaign.RemediatedCount,
		&campaign.ExceptedCount, &campaign.ClosureJWS, &jwks, &campaign.ClosedBy,
		&campaign.CreatedAt, &campaign.UpdatedAt, &campaign.ClosedAt)
	if len(jwks) > 0 && !bytes.Equal(jwks, []byte("null")) {
		campaign.ClosureJWKS = append(json.RawMessage(nil), jwks...)
	}
	return campaign, err
}

func listPQCMigrationCampaignFindingsTx(ctx context.Context, tx pgx.Tx, tenantID, campaignID string) ([]PQCMigrationCampaignFinding, error) {
	rows, err := tx.Query(ctx,
		`SELECT tenant_id::text, campaign_id::text, finding_id::text, finding_digest,
		        kind, location, algorithm, key_bits, protocol, cipher, disposition,
		        remediation_method, disposition_reason, evidence_refs, evidence_digests,
		        dispositioned_at, created_at, updated_at
		   FROM pqc_migration_campaign_findings
		  WHERE tenant_id = $1 AND campaign_id = $2
		  ORDER BY created_at, finding_id`,
		tenantID, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PQCMigrationCampaignFinding
	for rows.Next() {
		var finding PQCMigrationCampaignFinding
		if err := rows.Scan(&finding.TenantID, &finding.CampaignID, &finding.FindingID,
			&finding.FindingDigest, &finding.Kind, &finding.Location, &finding.Algorithm,
			&finding.KeyBits, &finding.Protocol, &finding.Cipher, &finding.Disposition,
			&finding.RemediationMethod, &finding.DispositionReason, &finding.EvidenceRefs,
			&finding.EvidenceDigests, &finding.DispositionedAt, &finding.CreatedAt,
			&finding.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, finding)
	}
	return out, rows.Err()
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
