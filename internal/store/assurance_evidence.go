// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// assuranceEvidenceLimit bounds each list in one credential's evidence.
const assuranceEvidenceLimit = 200

// CredentialEvidence is everything the tenant's store holds about one
// certificate's lifecycle, read in one tenant transaction for its assurance
// record (A179).
type CredentialEvidence struct {
	Certificate Certificate
	Owner       *Owner
	// Discoveries are the scans that found this exact certificate.
	Discoveries []DiscoveryObservation
	// Deliveries are the connector receipts for this certificate, deploy and
	// rollback alike, verification receipts included.
	Deliveries []DeliveryEvidence
	// Endpoints are the latest observations, per listener and vantage, that
	// expected or saw this certificate: what was actually being served.
	Endpoints []EndpointVerification
	// ExternalObservations are what external observers saw at endpoints that
	// served or were expected to serve this certificate (A180).
	ExternalObservations []ExternalObservation
	// Rotations are the renewal runs this certificate entered or left.
	Rotations []RotationRun
	// Predecessor is the certificate this one replaced; Successors replaced it.
	Predecessor *CertificateLink
	Successors  []CertificateLink
	// Truncated names any list that hit its bound.
	Truncated []string
}

// DiscoveryObservation is one discovery finding of a certificate.
type DiscoveryObservation struct {
	FindingID    string
	SourceID     string
	SourceName   string
	SourceKind   string
	RunID        string
	Kind         string
	Ref          string
	Provenance   string
	DiscoveredAt time.Time
}

// DeliveryEvidence is one connector receipt and, for a verification receipt,
// the agent's signed job receipt that reported it when the server verified that
// signature.
type DeliveryEvidence struct {
	Receipt ConnectorDeliveryReceipt
	// SignedBy names the agent or relay whose signed receipt reported this
	// verification; empty when no signature-verified receipt backs it.
	SignedBy          string
	SignerFingerprint string
	SignedObservedAt  *time.Time
	AgentJobID        int64
}

// CertificateLink identifies a related certificate.
type CertificateLink struct {
	ID          string
	Fingerprint string
	Status      string
	NotAfter    *time.Time
}

// CredentialEvidence reads one certificate's lifecycle evidence. It returns a
// not-found error for an id outside the tenant.
func (s *Store) CredentialEvidence(ctx context.Context, tenantID, certificateID string) (CredentialEvidence, error) {
	var out CredentialEvidence
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := scanCertificate(tx.QueryRow(ctx,
			`SELECT `+certificateColumns+` FROM certificates WHERE tenant_id = $1 AND id = $2`,
			tenantID, certificateID), &out.Certificate); err != nil {
			return err
		}
		cert := out.Certificate
		if cert.OwnerID != nil && *cert.OwnerID != "" {
			var owner Owner
			err := tx.QueryRow(ctx,
				`SELECT id::text, tenant_id::text, kind, name, email FROM owners WHERE tenant_id = $1 AND id = $2`,
				tenantID, *cert.OwnerID).Scan(&owner.ID, &owner.TenantID, &owner.Kind, &owner.Name, &owner.Email)
			switch {
			case err == nil:
				out.Owner = &owner
			case err != pgx.ErrNoRows:
				return err
			}
		}
		if err := out.readDiscoveries(ctx, tx, tenantID, cert.Fingerprint); err != nil {
			return err
		}
		if err := out.readDeliveries(ctx, tx, tenantID, cert.Fingerprint); err != nil {
			return err
		}
		if err := out.readEndpoints(ctx, tx, tenantID, cert.Fingerprint); err != nil {
			return err
		}
		if err := out.readExternalObservations(ctx, tx, tenantID, cert.Fingerprint); err != nil {
			return err
		}
		if err := out.readRotations(ctx, tx, tenantID, cert.Fingerprint); err != nil {
			return err
		}
		return out.readLinks(ctx, tx, tenantID, cert)
	})
	return out, err
}

func (e *CredentialEvidence) readDiscoveries(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) error {
	rows, err := tx.Query(ctx,
		`SELECT f.id::text, f.source_id::text, coalesce(src.name, ''), coalesce(src.kind, ''), f.run_id::text,
		        f.kind, f.ref, f.provenance, f.discovered_at
		   FROM discovery_findings f
		   LEFT JOIN discovery_sources src ON src.tenant_id = f.tenant_id AND src.id = f.source_id
		  WHERE f.tenant_id = $1 AND f.fingerprint = $2 AND f.fingerprint <> ''
		  ORDER BY f.discovered_at DESC, f.id
		  LIMIT $3`, tenantID, fingerprint, assuranceEvidenceLimit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d DiscoveryObservation
		if err := rows.Scan(&d.FindingID, &d.SourceID, &d.SourceName, &d.SourceKind, &d.RunID,
			&d.Kind, &d.Ref, &d.Provenance, &d.DiscoveredAt); err != nil {
			return err
		}
		e.Discoveries = append(e.Discoveries, d)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(e.Discoveries) > assuranceEvidenceLimit {
		e.Discoveries = e.Discoveries[:assuranceEvidenceLimit]
		e.Truncated = append(e.Truncated, "discovery")
	}
	return nil
}

func (e *CredentialEvidence) readDeliveries(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) error {
	rows, err := tx.Query(ctx,
		`SELECT c.id::text, c.tenant_id::text, c.outbox_id, c.identity_id::text, c.destination,
		        c.connector, c.target, c.fingerprint, c.status, c.attempts, c.reason, c.detail,
		        c.rollback_ref, c.idempotency_key, c.created_at, c.updated_at, c.adopted_predecessor_fingerprint,
		        coalesce(signed.agent, ''), coalesce(signed.signer_fingerprint, ''), signed.observed_at,
		        coalesce(signed.job_id, 0)
		   FROM connector_delivery_receipts c
		   LEFT JOIN LATERAL (
		        SELECT a.agent, a.signer_fingerprint, a.observed_at, a.job_id
		          FROM outbox o
		          JOIN agent_job_receipts a ON a.tenant_id = o.tenant_id AND a.job_id = o.id AND a.state = 'verified'
		         WHERE o.tenant_id = c.tenant_id AND c.idempotency_key = o.idempotency_key || ':verified'
		           AND c.status IN ('verified', 'verify_failed')
		         ORDER BY a.observed_at DESC, a.attempt DESC
		         LIMIT 1
		   ) AS signed ON true
		  WHERE c.tenant_id = $1 AND c.fingerprint = $2
		  ORDER BY coalesce(c.latest_event_sequence, 0), c.created_at, c.id
		  LIMIT $3`, tenantID, fingerprint, assuranceEvidenceLimit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			d          DeliveryEvidence
			outboxID   sql.NullInt64
			identityID sql.NullString
			observedAt sql.NullTime
		)
		r := &d.Receipt
		if err := rows.Scan(&r.ID, &r.TenantID, &outboxID, &identityID, &r.Destination, &r.Connector,
			&r.Target, &r.Fingerprint, &r.Status, &r.Attempts, &r.Reason, &r.Detail,
			&r.RollbackRef, &r.IdempotencyKey, &r.CreatedAt, &r.UpdatedAt, &r.AdoptedPredecessor,
			&d.SignedBy, &d.SignerFingerprint, &observedAt, &d.AgentJobID); err != nil {
			return err
		}
		if outboxID.Valid {
			r.OutboxID = &outboxID.Int64
		}
		if identityID.Valid {
			r.IdentityID = &identityID.String
		}
		if observedAt.Valid {
			at := observedAt.Time
			d.SignedObservedAt = &at
		}
		e.Deliveries = append(e.Deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(e.Deliveries) > assuranceEvidenceLimit {
		e.Deliveries = e.Deliveries[:assuranceEvidenceLimit]
		e.Truncated = append(e.Truncated, "deliveries")
	}
	return nil
}

func (e *CredentialEvidence) readEndpoints(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) error {
	rows, err := tx.Query(ctx,
		`SELECT tenant_id::text, endpoint_id, address, vantage, reached, mismatch,
		        expected_fingerprint, observed_fingerprint, checked_sans, checked_chain,
		        not_before, not_after, detail, evidence_digest, agent_common_name,
		        last_checked_at, last_good_at, event_sequence
		   FROM endpoint_verifications
		  WHERE tenant_id = $1 AND $2 <> '' AND (expected_fingerprint = $2 OR observed_fingerprint = $2)
		  ORDER BY last_checked_at DESC, endpoint_id, vantage
		  LIMIT $3`, tenantID, fingerprint, assuranceEvidenceLimit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			rec                           EndpointVerification
			notBefore, notAfter, lastGood *time.Time
			seq                           int64
		)
		if err := rows.Scan(&rec.TenantID, &rec.EndpointID, &rec.Address, &rec.Vantage,
			&rec.Reached, &rec.Mismatch, &rec.ExpectedFingerprint, &rec.ObservedFingerprint,
			&rec.CheckedSANs, &rec.CheckedChain, &notBefore, &notAfter, &rec.Detail,
			&rec.EvidenceDigest, &rec.AgentCommonName, &rec.LastCheckedAt, &lastGood,
			&seq); err != nil {
			return err
		}
		if notBefore != nil {
			rec.NotBefore = *notBefore
		}
		if notAfter != nil {
			rec.NotAfter = *notAfter
		}
		if lastGood != nil {
			rec.LastGoodAt = *lastGood
		}
		rec.EventSequence = uint64(seq) // #nosec G115 -- non-negative by construction (CWE-190)
		e.Endpoints = append(e.Endpoints, rec)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(e.Endpoints) > assuranceEvidenceLimit {
		e.Endpoints = e.Endpoints[:assuranceEvidenceLimit]
		e.Truncated = append(e.Truncated, "endpoints")
	}
	return nil
}

func (e *CredentialEvidence) readExternalObservations(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) error {
	rows, err := tx.Query(ctx,
		`SELECT `+externalObservationColumns+`
		   FROM external_observations o
		   LEFT JOIN external_observers obs ON obs.tenant_id = o.tenant_id AND obs.id = o.observer_id
		  WHERE o.tenant_id = $1 AND $2 <> '' AND (o.served_fingerprint = $2 OR o.expected_fingerprint = $2)
		  ORDER BY o.observed_at DESC, o.id
		  LIMIT $3`, tenantID, fingerprint, assuranceEvidenceLimit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var o ExternalObservation
		if err := scanExternalObservation(rows, &o); err != nil {
			return err
		}
		e.ExternalObservations = append(e.ExternalObservations, o)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(e.ExternalObservations) > assuranceEvidenceLimit {
		e.ExternalObservations = e.ExternalObservations[:assuranceEvidenceLimit]
		e.Truncated = append(e.Truncated, "external_observations")
	}
	return nil
}

func (e *CredentialEvidence) readRotations(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string) error {
	rows, err := tx.Query(ctx,
		`SELECT id::text, tenant_id::text, identity_id::text, outbox_id, status, trigger, reason,
		        predecessor_fingerprint, successor_fingerprint, rollback_ref, error,
		        idempotency_key, created_at, updated_at, completed_at,
		        first_event_sequence, latest_event_sequence, legacy_predecessor_binding
		   FROM lifecycle_rotation_runs
		  WHERE tenant_id = $1 AND $2 <> '' AND (predecessor_fingerprint = $2 OR successor_fingerprint = $2)
		  ORDER BY created_at, id
		  LIMIT $3`, tenantID, fingerprint, assuranceEvidenceLimit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r RotationRun
		if err := scanRotationRun(rows, &r); err != nil {
			return err
		}
		e.Rotations = append(e.Rotations, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(e.Rotations) > assuranceEvidenceLimit {
		e.Rotations = e.Rotations[:assuranceEvidenceLimit]
		e.Truncated = append(e.Truncated, "renewals")
	}
	return nil
}

func (e *CredentialEvidence) readLinks(ctx context.Context, tx pgx.Tx, tenantID string, cert Certificate) error {
	if cert.ReplacesID != nil && *cert.ReplacesID != "" {
		var link CertificateLink
		err := tx.QueryRow(ctx,
			`SELECT id::text, fingerprint, status, not_after FROM certificates WHERE tenant_id = $1 AND id = $2`,
			tenantID, *cert.ReplacesID).Scan(&link.ID, &link.Fingerprint, &link.Status, &link.NotAfter)
		switch {
		case err == nil:
			e.Predecessor = &link
		case err != pgx.ErrNoRows:
			return err
		}
	}
	rows, err := tx.Query(ctx,
		`SELECT id::text, fingerprint, status, not_after FROM certificates
		  WHERE tenant_id = $1 AND replaces_id = $2
		  ORDER BY created_at, id LIMIT $3`, tenantID, cert.ID, assuranceEvidenceLimit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var link CertificateLink
		if err := rows.Scan(&link.ID, &link.Fingerprint, &link.Status, &link.NotAfter); err != nil {
			return err
		}
		e.Successors = append(e.Successors, link)
	}
	return rows.Err()
}

// IdentityTransitionForIssuance resolves the lifecycle transition a
// certificate's issuance key names: "issue:transition:<key>" for an initial
// issuance, "renew:transition:<key>" for a renewal. Other keys name none.
func (s *Store) IdentityTransitionForIssuance(ctx context.Context, tenantID, issuanceKey string) (IdentityTransition, bool, error) {
	var eventType, key string
	switch {
	case strings.HasPrefix(issuanceKey, "issue:transition:"):
		eventType, key = "identity.issued", strings.TrimPrefix(issuanceKey, "issue:transition:")
	case strings.HasPrefix(issuanceKey, "renew:transition:"):
		eventType, key = "identity.renewing", strings.TrimPrefix(issuanceKey, "renew:transition:")
	default:
		return IdentityTransition{}, false, nil
	}
	if key == "" {
		return IdentityTransition{}, false, nil
	}
	var out []IdentityTransition
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT identity_id::text, seq, event_type, idempotency_key FROM identity_transitions
			  WHERE tenant_id = $1 AND event_type = $2 AND idempotency_key = $3
			  ORDER BY seq LIMIT 2`, tenantID, eventType, key)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t IdentityTransition
			if err := rows.Scan(&t.IdentityID, &t.Seq, &t.EventType, &t.IdempotencyKey); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err != nil {
		return IdentityTransition{}, false, err
	}
	if len(out) > 1 {
		return IdentityTransition{}, false, fmt.Errorf("store: issuance key %q names more than one transition", issuanceKey)
	}
	if len(out) == 0 {
		return IdentityTransition{}, false, nil
	}
	return out[0], true, nil
}

// ListAssuranceSubjects returns the certificates whose lifecycle changed in
// [from, through] — a connector receipt, an endpoint observation or a renewal
// run updated, or a revocation — newest change first, at most limit, and
// whether there were more. Evidence packs carry their assurance records.
func (s *Store) ListAssuranceSubjects(ctx context.Context, tenantID string, from, through time.Time, limit int) ([]string, bool, error) {
	if limit <= 0 {
		return nil, false, nil
	}
	var out []string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`WITH changed AS (
			     SELECT c.fingerprint, max(c.updated_at) AS at FROM connector_delivery_receipts c
			      WHERE c.tenant_id = $1 AND c.updated_at BETWEEN $2 AND $3 GROUP BY c.fingerprint
			     UNION ALL
			     SELECT v.observed_fingerprint, max(v.last_checked_at) FROM endpoint_verifications v
			      WHERE v.tenant_id = $1 AND v.last_checked_at BETWEEN $2 AND $3 AND v.observed_fingerprint <> ''
			      GROUP BY v.observed_fingerprint
			     UNION ALL
			     SELECT r.successor_fingerprint, max(r.updated_at) FROM lifecycle_rotation_runs r
			      WHERE r.tenant_id = $1 AND r.updated_at BETWEEN $2 AND $3 AND r.successor_fingerprint <> ''
			      GROUP BY r.successor_fingerprint
			     UNION ALL
			     SELECT r.predecessor_fingerprint, max(r.updated_at) FROM lifecycle_rotation_runs r
			      WHERE r.tenant_id = $1 AND r.updated_at BETWEEN $2 AND $3 AND r.predecessor_fingerprint <> ''
			      GROUP BY r.predecessor_fingerprint
			     UNION ALL
			     SELECT c.fingerprint, c.revoked_at FROM certificates c
			      WHERE c.tenant_id = $1 AND c.revoked_at BETWEEN $2 AND $3
			 )
			 SELECT cert.id::text
			   FROM certificates cert
			   JOIN (SELECT fingerprint, max(at) AS at FROM changed GROUP BY fingerprint) latest
			     ON latest.fingerprint = cert.fingerprint
			  WHERE cert.tenant_id = $1
			  ORDER BY latest.at DESC, cert.id
			  LIMIT $4`, tenantID, from, through, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}
