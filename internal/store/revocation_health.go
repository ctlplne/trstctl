// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// RevocationEndpointHealth is one replayable CRL or OCSP endpoint verdict.
// Certificate and issuer material is public context; private key material never
// enters this model.
type RevocationEndpointHealth struct {
	TenantID               string
	TargetKey              string
	Protocol               string
	Endpoint               string
	IssuerSubject          string
	IssuerFingerprint      string
	CertificateID          string
	CertificateSubject     string
	CertificateFingerprint string
	CertificateSerial      string
	Status                 string
	DetailCode             string
	LatencyMS              int64
	ThisUpdate             *time.Time
	NextUpdate             *time.Time
	SignatureVerified      bool
	RevokedCount           int
	ResponseStatus         string
	ResponderSubject       string
	ProbeID                string
	Bucket                 string
	BatchIndex             int
	BatchCount             int
	ObservedByAgentID      string
	ObservedByAgentName    string
	EvidenceDigest         string
	ObservedAt             time.Time
}

// TenantsWithRevocationProbeCandidates is the leader-only cross-tenant
// enumerator. Every row read after this point re-enters tenant RLS.
func (s *Store) TenantsWithRevocationProbeCandidates(ctx context.Context) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — this cross-tenant system leader enumerates only tenant IDs with active public certificate DER; the scheduler re-enters tenant RLS before reading certificate context.
		`SELECT DISTINCT tenant_id::text
		   FROM certificates
		  WHERE status = 'active' AND octet_length(certificate_der) > 0
		  ORDER BY 1`)
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

// DatabaseTime returns the PostgreSQL authority clock used to make one stable
// scheduling bucket across replicas.
func (s *Store) DatabaseTime(ctx context.Context) (time.Time, error) {
	var now time.Time
	err := s.SystemPool().QueryRow(ctx,
		//trstctl:system-query — this cross-tenant system clock query reads PostgreSQL time only and exposes no tenant data or payload.
		`SELECT clock_timestamp()`).Scan(&now)
	return now.UTC(), err
}

// ApplyRevocationEndpointHealthObservedTx is the projector-only writer for a
// verified immutable observation. There is deliberately no direct wrapper.
func (s *Store) ApplyRevocationEndpointHealthObservedTx(ctx context.Context, tx pgx.Tx, rows []RevocationEndpointHealth) error {
	for _, row := range rows {
		_, err := tx.Exec(ctx,
			`INSERT INTO revocation_endpoint_health
			        (tenant_id, target_key, protocol, endpoint, issuer_subject, issuer_fingerprint,
			         certificate_id, certificate_subject, certificate_fingerprint, certificate_serial,
			         status, detail_code, latency_ms, this_update, next_update, signature_verified,
			         revoked_count, response_status, responder_subject, probe_id, bucket,
			         batch_index, batch_count, observed_by_agent_id, observed_by_agent_name,
			         evidence_digest, observed_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
			 ON CONFLICT (tenant_id, target_key) DO UPDATE SET
			     protocol=EXCLUDED.protocol, endpoint=EXCLUDED.endpoint,
			     issuer_subject=EXCLUDED.issuer_subject, issuer_fingerprint=EXCLUDED.issuer_fingerprint,
			     certificate_id=EXCLUDED.certificate_id, certificate_subject=EXCLUDED.certificate_subject,
			     certificate_fingerprint=EXCLUDED.certificate_fingerprint, certificate_serial=EXCLUDED.certificate_serial,
			     status=EXCLUDED.status, detail_code=EXCLUDED.detail_code, latency_ms=EXCLUDED.latency_ms,
			     this_update=EXCLUDED.this_update, next_update=EXCLUDED.next_update,
			     signature_verified=EXCLUDED.signature_verified, revoked_count=EXCLUDED.revoked_count,
			     response_status=EXCLUDED.response_status, responder_subject=EXCLUDED.responder_subject,
			     probe_id=EXCLUDED.probe_id, bucket=EXCLUDED.bucket, batch_index=EXCLUDED.batch_index,
			     batch_count=EXCLUDED.batch_count, observed_by_agent_id=EXCLUDED.observed_by_agent_id,
			     observed_by_agent_name=EXCLUDED.observed_by_agent_name,
			     evidence_digest=EXCLUDED.evidence_digest, observed_at=EXCLUDED.observed_at
			 WHERE revocation_endpoint_health.observed_at <= EXCLUDED.observed_at`,
			row.TenantID, row.TargetKey, row.Protocol, row.Endpoint, row.IssuerSubject, row.IssuerFingerprint,
			row.CertificateID, row.CertificateSubject, row.CertificateFingerprint, row.CertificateSerial,
			row.Status, row.DetailCode, row.LatencyMS, row.ThisUpdate, row.NextUpdate, row.SignatureVerified,
			row.RevokedCount, row.ResponseStatus, row.ResponderSubject, row.ProbeID, row.Bucket,
			row.BatchIndex, row.BatchCount, row.ObservedByAgentID, row.ObservedByAgentName,
			row.EvidenceDigest, row.ObservedAt.UTC())
		if err != nil {
			return err
		}
	}
	return nil
}

// ListRevocationEndpointHealth returns the tenant's latest endpoint verdicts,
// failures first and then most recently observed.
func (s *Store) ListRevocationEndpointHealth(ctx context.Context, tenantID string, limit int) ([]RevocationEndpointHealth, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	var out []RevocationEndpointHealth
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, target_key, protocol, endpoint, issuer_subject, issuer_fingerprint,
			        certificate_id::text, certificate_subject, certificate_fingerprint, certificate_serial,
			        status, detail_code, latency_ms, this_update, next_update, signature_verified,
			        revoked_count, response_status, responder_subject, probe_id::text, bucket,
			        batch_index, batch_count, observed_by_agent_id::text, observed_by_agent_name,
			        evidence_digest, observed_at
			   FROM revocation_endpoint_health
			  WHERE tenant_id = $1
			  ORDER BY CASE status WHEN 'stale' THEN 0 WHEN 'unparseable' THEN 1 WHEN 'unreachable' THEN 2 WHEN 'expiring' THEN 3 ELSE 4 END,
			           observed_at DESC, target_key
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row RevocationEndpointHealth
			if err := rows.Scan(&row.TenantID, &row.TargetKey, &row.Protocol, &row.Endpoint,
				&row.IssuerSubject, &row.IssuerFingerprint, &row.CertificateID,
				&row.CertificateSubject, &row.CertificateFingerprint, &row.CertificateSerial,
				&row.Status, &row.DetailCode, &row.LatencyMS, &row.ThisUpdate, &row.NextUpdate,
				&row.SignatureVerified, &row.RevokedCount, &row.ResponseStatus,
				&row.ResponderSubject, &row.ProbeID, &row.Bucket, &row.BatchIndex,
				&row.BatchCount, &row.ObservedByAgentID, &row.ObservedByAgentName,
				&row.EvidenceDigest, &row.ObservedAt); err != nil {
				return err
			}
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}
