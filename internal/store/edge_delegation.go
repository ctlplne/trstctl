// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// Constrained edge sub-CA read models (epic B6). All three tables are
// projections of edge.* events (AN-2): the projector applies each event on its
// transaction with the event sequence as the monotonic guard, so direct
// projection plus tail replay converge on the same rows.

// EdgeSegmentPolicy is a segment's opt-in to delegated edge CAs: OFF unless a
// row says otherwise, and one declaration carries both the attestation roots
// that may vouch for the segment's hosts and the DNS identifiers every
// delegation minted for it is constrained to.
type EdgeSegmentPolicy struct {
	TenantID            string
	SegmentID           string
	Enabled             bool
	AttestationRootsPEM []string
	PermittedDNSDomains []string
	ExcludedDNSDomains  []string
	AllowedKeyProviders []string
	UpdatedAt           time.Time
}

// EdgeDelegation is one delegated CA the isolated signer minted.
type EdgeDelegation struct {
	TenantID              string
	ID                    string
	SegmentID             string
	CAID                  string
	Host                  string
	CommonName            string
	Serial                string
	CertificatePEM        string
	PermittedDNSDomains   []string
	ExcludedDNSDomains    []string
	AttestedKeySHA256     string
	AttestationCertSHA256 string
	CSRKeySHA256          string
	KeyProvider           string
	KeyStorage            string
	KeyExportable         bool
	CustodyAssurance      string
	Status                string // 'active' | 'revoked'
	NotBefore             time.Time
	NotAfter              time.Time
	RevokedAt             *time.Time
	RevokeReason          string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// Expired reports whether the delegation's certificate validity has passed —
// the auto-expiry bound. Expiry is derived from not_after rather than stored
// as a status so a delegation cannot appear live merely because no process ran.
func (d EdgeDelegation) Expired(now time.Time) bool { return now.After(d.NotAfter) }

// EdgeIssuance is one locally-issued leaf that reconciled back to the brain.
type EdgeIssuance struct {
	TenantID          string
	DelegationID      string
	Serial            string
	Subject           string
	DNSNames          []string
	NotBefore         time.Time
	NotAfter          time.Time
	IssuedAt          time.Time
	ReconciledAt      time.Time
	WithinConstraints bool
	Violation         string
}

// ApplyEdgeSegmentPolicyTx projects edge.segment.policy_set.
func (s *Store) ApplyEdgeSegmentPolicyTx(ctx context.Context, tx pgx.Tx, p EdgeSegmentPolicy, eventSequence uint64) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO edge_segment_policies
		        (tenant_id, segment_id, enabled, attestation_roots_pem,
		         permitted_dns_domains, excluded_dns_domains, allowed_key_providers,
		         updated_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, segment_id) DO UPDATE
		    SET enabled = EXCLUDED.enabled,
		        attestation_roots_pem = EXCLUDED.attestation_roots_pem,
		        permitted_dns_domains = EXCLUDED.permitted_dns_domains,
		        excluded_dns_domains = EXCLUDED.excluded_dns_domains,
		        allowed_key_providers = EXCLUDED.allowed_key_providers,
		        updated_at = EXCLUDED.updated_at,
		        event_sequence = EXCLUDED.event_sequence
		  WHERE edge_segment_policies.event_sequence <= EXCLUDED.event_sequence`,
		p.TenantID, p.SegmentID, p.Enabled, textArray(p.AttestationRootsPEM),
		textArray(p.PermittedDNSDomains), textArray(p.ExcludedDNSDomains),
		textArray(edgeAllowedProvidersOrDefault(p.AllowedKeyProviders)), p.UpdatedAt.UTC(), eventSequence)
	return err
}

// ApplyEdgeDelegationIssuedTx projects edge.delegation.issued.
func (s *Store) ApplyEdgeDelegationIssuedTx(ctx context.Context, tx pgx.Tx, d EdgeDelegation, eventSequence uint64) error {
	if err := lockUpsertArbiterTx(ctx, tx, "edge_delegations", d.TenantID, d.ID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO edge_delegations
		        (tenant_id, id, segment_id, ca_id, host, common_name, serial,
		         certificate_pem, permitted_dns_domains, excluded_dns_domains,
		         attested_key_sha256, attestation_cert_sha256, csr_key_sha256,
		         key_provider, key_storage, key_exportable, custody_assurance, status,
		         not_before, not_after, revoked_at, revoke_reason,
		         created_at, updated_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
		         $14, $15, $16, $17, 'active', $18, $19, NULL, '', $20, $20, $21)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		d.TenantID, d.ID, d.SegmentID, d.CAID, d.Host, d.CommonName, d.Serial,
		d.CertificatePEM, textArray(d.PermittedDNSDomains), textArray(d.ExcludedDNSDomains),
		d.AttestedKeySHA256, d.AttestationCertSHA256, edgeCSRKeyDigestOrLegacy(d),
		edgeProviderOrDefault(d.KeyProvider), edgeStorageOrDefault(d.KeyStorage), d.KeyExportable,
		edgeAssuranceOrDefault(d.CustodyAssurance), d.NotBefore.UTC(), d.NotAfter.UTC(), d.CreatedAt.UTC(), eventSequence)
	return err
}

// ApplyEdgeDelegationRevokedTx projects edge.delegation.revoked. Keeps the
// first revocation on replay.
func (s *Store) ApplyEdgeDelegationRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, id, reason string, at time.Time, eventSequence uint64) error {
	_, err := tx.Exec(ctx,
		`UPDATE edge_delegations
		    SET status = 'revoked', revoked_at = $3, revoke_reason = $4,
		        updated_at = $3, event_sequence = $5
		  WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		tenantID, id, at.UTC(), reason, eventSequence)
	return err
}

// ApplyEdgeIssuanceReconciledTx projects edge.issuance.reconciled. One row per
// (delegation, serial) however many times the host re-reports its journal.
func (s *Store) ApplyEdgeIssuanceReconciledTx(ctx context.Context, tx pgx.Tx, i EdgeIssuance, eventSequence uint64) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO edge_issuances
		        (tenant_id, delegation_id, serial, subject, dns_names,
		         not_before, not_after, issued_at, reconciled_at,
		         within_constraints, violation, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (tenant_id, delegation_id, serial) DO NOTHING`,
		i.TenantID, i.DelegationID, i.Serial, i.Subject, textArray(i.DNSNames),
		i.NotBefore.UTC(), i.NotAfter.UTC(), i.IssuedAt.UTC(), i.ReconciledAt.UTC(),
		i.WithinConstraints, i.Violation, eventSequence)
	return err
}

// GetEdgeSegmentPolicy returns the segment's policy; ok=false means the
// segment never opted in, which the callers treat as OFF.
func (s *Store) GetEdgeSegmentPolicy(ctx context.Context, tenantID, segmentID string) (EdgeSegmentPolicy, bool, error) {
	var p EdgeSegmentPolicy
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT tenant_id::text, segment_id::text, enabled, attestation_roots_pem,
			        permitted_dns_domains, excluded_dns_domains, allowed_key_providers, updated_at
			   FROM edge_segment_policies
			  WHERE tenant_id = $1 AND segment_id = $2`,
			tenantID, segmentID)
		err := row.Scan(&p.TenantID, &p.SegmentID, &p.Enabled, &p.AttestationRootsPEM,
			&p.PermittedDNSDomains, &p.ExcludedDNSDomains, &p.AllowedKeyProviders, &p.UpdatedAt)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err == nil {
			found = true
		}
		return err
	})
	return p, found, err
}

// ListEdgeSegmentPolicies returns every segment policy for the tenant.
func (s *Store) ListEdgeSegmentPolicies(ctx context.Context, tenantID string) ([]EdgeSegmentPolicy, error) {
	var out []EdgeSegmentPolicy
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, segment_id::text, enabled, attestation_roots_pem,
			        permitted_dns_domains, excluded_dns_domains, allowed_key_providers, updated_at
			   FROM edge_segment_policies
			  WHERE tenant_id = $1
			  ORDER BY segment_id`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p EdgeSegmentPolicy
			if err := rows.Scan(&p.TenantID, &p.SegmentID, &p.Enabled, &p.AttestationRootsPEM,
				&p.PermittedDNSDomains, &p.ExcludedDNSDomains, &p.AllowedKeyProviders, &p.UpdatedAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

const edgeDelegationCols = `tenant_id::text, id::text, segment_id::text, ca_id::text, host,
	common_name, serial, certificate_pem, permitted_dns_domains, excluded_dns_domains,
	attested_key_sha256, attestation_cert_sha256, csr_key_sha256,
	key_provider, key_storage, key_exportable, custody_assurance, status, not_before, not_after,
	revoked_at, revoke_reason, created_at, updated_at`

func scanEdgeDelegation(row pgx.Row) (EdgeDelegation, error) {
	var d EdgeDelegation
	err := row.Scan(&d.TenantID, &d.ID, &d.SegmentID, &d.CAID, &d.Host,
		&d.CommonName, &d.Serial, &d.CertificatePEM, &d.PermittedDNSDomains, &d.ExcludedDNSDomains,
		&d.AttestedKeySHA256, &d.AttestationCertSHA256, &d.CSRKeySHA256,
		&d.KeyProvider, &d.KeyStorage, &d.KeyExportable, &d.CustodyAssurance,
		&d.Status, &d.NotBefore, &d.NotAfter,
		&d.RevokedAt, &d.RevokeReason, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

func edgeAllowedProvidersOrDefault(in []string) []string {
	if len(in) == 0 {
		return []string{"tpm2"}
	}
	return in
}

func edgeProviderOrDefault(in string) string {
	if in == "" {
		return "tpm2"
	}
	return in
}

func edgeStorageOrDefault(in string) string {
	if in == "" {
		return "device_bound"
	}
	return in
}

func edgeAssuranceOrDefault(in string) string {
	if in == "" {
		return "hardware_key_attested"
	}
	return in
}

func edgeCSRKeyDigestOrLegacy(d EdgeDelegation) string {
	if d.CSRKeySHA256 != "" {
		return d.CSRKeySHA256
	}
	return d.AttestedKeySHA256
}

// GetEdgeDelegation loads one delegation.
func (s *Store) GetEdgeDelegation(ctx context.Context, tenantID, id string) (EdgeDelegation, bool, error) {
	var d EdgeDelegation
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+edgeDelegationCols+` FROM edge_delegations
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id)
		var err error
		d, err = scanEdgeDelegation(row)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err == nil {
			found = true
		}
		return err
	})
	return d, found, err
}

// ListEdgeDelegations returns the tenant's delegations, live-first.
func (s *Store) ListEdgeDelegations(ctx context.Context, tenantID string) ([]EdgeDelegation, error) {
	var out []EdgeDelegation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+edgeDelegationCols+` FROM edge_delegations
			  WHERE tenant_id = $1
			  ORDER BY status, not_after DESC, id`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanEdgeDelegation(rows)
			if err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// ListEdgeIssuances returns a delegation's reconciled issuances, newest first.
func (s *Store) ListEdgeIssuances(ctx context.Context, tenantID, delegationID string, limit int) ([]EdgeIssuance, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []EdgeIssuance
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, delegation_id::text, serial, subject, dns_names,
			        not_before, not_after, issued_at, reconciled_at, within_constraints, violation
			   FROM edge_issuances
			  WHERE tenant_id = $1 AND delegation_id = $2
			  ORDER BY reconciled_at DESC, serial
			  LIMIT $3`,
			tenantID, delegationID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i EdgeIssuance
			if err := rows.Scan(&i.TenantID, &i.DelegationID, &i.Serial, &i.Subject, &i.DNSNames,
				&i.NotBefore, &i.NotAfter, &i.IssuedAt, &i.ReconciledAt, &i.WithinConstraints, &i.Violation); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	return out, err
}

// EdgeIssuanceExists reports whether (delegation, serial) already reconciled —
// the idempotency read the reconcile handler uses before emitting.
func (s *Store) EdgeIssuanceExists(ctx context.Context, tenantID, delegationID, serial string) (bool, error) {
	exists := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM edge_issuances
			  WHERE tenant_id = $1 AND delegation_id = $2 AND serial = $3)`,
			tenantID, delegationID, serial).Scan(&exists)
	})
	return exists, err
}

func textArray(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
