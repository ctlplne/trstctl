package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
)

// PrivacyErasureSelectors names the read-model rows that must be pseudonymized
// for one subject erasure. It carries stable identifiers, not the erased subject.
type PrivacyErasureSelectors struct {
	OwnerIDs                []string `json:"owner_ids,omitempty"`
	IdentityIDs             []string `json:"identity_ids,omitempty"`
	CertificateFingerprints []string `json:"certificate_fingerprints,omitempty"`
	SSHKeyIDs               []string `json:"ssh_key_ids,omitempty"`
	AttestationIDs          []string `json:"attestation_ids,omitempty"`
}

// PrivacySubjectErasure is the projected evidence for one subject erasure.
type PrivacySubjectErasure struct {
	TenantID       string
	SubjectRef     string
	RequestedByRef string
	Reason         string
	Selectors      PrivacyErasureSelectors
	Counts         map[string]int
	ErasedAt       time.Time
}

// PRIVACY-004: a data-subject ACCESS/PORTABILITY export. Erasure already enumerates
// the rows tied to a subject (SelectPrivacySubjectErasure → selectors), but an
// operator answering a subject-access request also needs the actual record CONTENT
// the subject can see — the inverse capability. SelectPrivacySubjectExport collects
// every subject-linked record across the privacy catalog (owners, identities,
// certificates, SSH keys, attestations, tenant members, API tokens, dual-control
// approvals) for one tenant under RLS (AN-1). It is a pure READ: it carries no
// secret material (API-token hashes are never selected; only the principal subject
// and non-secret metadata), so the result is safe to hand to the subject or an
// auditor. It is the served basis for export; rectify/erase reuse the existing
// event-sourced erasure/retention machinery.

// PrivacyOwnerRecord is one owner row linked to the subject.
type PrivacyOwnerRecord struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// PrivacyIdentityRecord is one identity row linked to the subject (by name or an
// attribute value).
type PrivacyIdentityRecord struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Attributes string    `json:"attributes"`
	CreatedAt  time.Time `json:"created_at"`
}

// PrivacyCertificateRecord is one certificate row whose subject/SAN matches.
type PrivacyCertificateRecord struct {
	Fingerprint        string    `json:"fingerprint"`
	Subject            string    `json:"subject"`
	SANs               []string  `json:"sans"`
	Serial             string    `json:"serial"`
	Issuer             string    `json:"issuer"`
	DeploymentLocation string    `json:"deployment_location"`
	Source             string    `json:"source"`
	CreatedAt          time.Time `json:"created_at"`
}

// PrivacySSHKeyRecord is one SSH key row whose comment/location matches.
type PrivacySSHKeyRecord struct {
	ID          string    `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	KeyType     string    `json:"key_type"`
	Comment     string    `json:"comment"`
	Location    string    `json:"location"`
	CreatedAt   time.Time `json:"created_at"`
}

// PrivacyAttestationRecord is one attestation row whose evidence references the
// subject. Evidence is the free-form JSON payload (already tenant-scoped).
type PrivacyAttestationRecord struct {
	ID        string    `json:"id"`
	Evidence  string    `json:"evidence"`
	CreatedAt time.Time `json:"created_at"`
}

// PrivacyMemberRecord is one tenant_members row for the subject (RBAC membership).
type PrivacyMemberRecord struct {
	Subject     string   `json:"subject"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Status      string   `json:"status"`
}

// PrivacyTokenRecord is one api_tokens row for the subject. The token hash is NEVER
// included — only the principal subject, scopes, and lifecycle timestamps.
type PrivacyTokenRecord struct {
	ID        string     `json:"id"`
	Subject   string     `json:"subject"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// PrivacyApprovalRecord is one dual-control approval/request actor tie to the
// subject (requester or approver).
type PrivacyApprovalRecord struct {
	Resource string    `json:"resource"`
	Action   string    `json:"action"`
	Role     string    `json:"role"` // "requester" | "approver"
	At       time.Time `json:"at"`
}

// PrivacySubjectExport is the assembled data-subject access/portability view for one
// subject in one tenant. Counts mirrors the per-category record totals so a caller
// can verify completeness at a glance. It contains no secret material.
type PrivacySubjectExport struct {
	TenantID     string                     `json:"tenant_id"`
	Subject      string                     `json:"subject"`
	SubjectRef   string                     `json:"subject_ref"`
	Owners       []PrivacyOwnerRecord       `json:"owners"`
	Identities   []PrivacyIdentityRecord    `json:"identities"`
	Certificates []PrivacyCertificateRecord `json:"certificates"`
	SSHKeys      []PrivacySSHKeyRecord      `json:"ssh_keys"`
	Attestations []PrivacyAttestationRecord `json:"attestations"`
	Members      []PrivacyMemberRecord      `json:"tenant_members"`
	Tokens       []PrivacyTokenRecord       `json:"api_tokens"`
	Approvals    []PrivacyApprovalRecord    `json:"approvals"`
	Counts       map[string]int             `json:"counts"`
	GeneratedAt  time.Time                  `json:"generated_at"`
}

// SelectPrivacySubjectExport gathers every subject-linked record across the privacy
// catalog for one tenant (PRIVACY-004 data-subject access/portability). It is
// tenant-scoped under RLS (AN-1) and read-only — no event is emitted for an export,
// and no secret material (e.g. api_tokens.token_hash) is read. The subject is
// matched the same way erasure matches it: owner email/name, identity name/attribute,
// certificate subject/SAN, SSH comment/location, attestation evidence, and the
// tenant-bound subject_ref for members/tokens/approvals.
func (s *Store) SelectPrivacySubjectExport(ctx context.Context, tenantID, subject string) (PrivacySubjectExport, error) {
	if tenantID == "" {
		return PrivacySubjectExport{}, fmt.Errorf("store: privacy export requires a tenant id (AN-1)")
	}
	if subject == "" {
		return PrivacySubjectExport{}, fmt.Errorf("store: privacy export requires a subject")
	}
	out := PrivacySubjectExport{
		TenantID:    tenantID,
		Subject:     subject,
		SubjectRef:  privacy.SubjectRef(tenantID, subject),
		Counts:      map[string]int{},
		GeneratedAt: time.Now().UTC(),
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Owners (matched by email or name).
		rows, err := tx.Query(ctx,
			`SELECT id::text, kind, name, email, created_at
			   FROM owners
			  WHERE tenant_id = $1 AND (email = $2 OR name = $2)
			  ORDER BY id`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyOwnerRecord
			if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.Email, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Owners = append(out.Owners, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Identities (matched by name or an attribute value).
		rows, err = tx.Query(ctx,
			`SELECT id::text, kind, name, status, attributes::text, created_at
			   FROM identities
			  WHERE tenant_id = $1 AND (name = $2 OR position($2 in attributes::text) > 0)
			  ORDER BY id`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyIdentityRecord
			if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.Status, &r.Attributes, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Identities = append(out.Identities, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Certificates (matched by subject or SAN).
		rows, err = tx.Query(ctx,
			`SELECT fingerprint, subject, sans, serial, issuer, deployment_location, source, created_at
			   FROM certificates
			  WHERE tenant_id = $1 AND (subject = $2 OR $2 = ANY(sans))
			  ORDER BY fingerprint`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyCertificateRecord
			if err := rows.Scan(&r.Fingerprint, &r.Subject, &r.SANs, &r.Serial, &r.Issuer, &r.DeploymentLocation, &r.Source, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Certificates = append(out.Certificates, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// SSH keys (matched by comment or location).
		rows, err = tx.Query(ctx,
			`SELECT id::text, fingerprint, key_type, comment, location, created_at
			   FROM ssh_keys
			  WHERE tenant_id = $1 AND (comment = $2 OR location = $2)
			  ORDER BY id`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacySSHKeyRecord
			if err := rows.Scan(&r.ID, &r.Fingerprint, &r.KeyType, &r.Comment, &r.Location, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.SSHKeys = append(out.SSHKeys, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Attestations (evidence references the subject).
		rows, err = tx.Query(ctx,
			`SELECT id::text, evidence::text, created_at
			   FROM attestations
			  WHERE tenant_id = $1 AND position($2 in evidence::text) > 0
			  ORDER BY id`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyAttestationRecord
			if err := rows.Scan(&r.ID, &r.Evidence, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Attestations = append(out.Attestations, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Tenant members (matched by subject_ref).
		rows, err = tx.Query(ctx,
			`SELECT subject, display_name, email, roles, status
			   FROM tenant_members
			  WHERE tenant_id = $1 AND subject_ref = $2
			  ORDER BY subject`, tenantID, out.SubjectRef)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyMemberRecord
			if err := rows.Scan(&r.Subject, &r.DisplayName, &r.Email, &r.Roles, &r.Status); err != nil {
				rows.Close()
				return err
			}
			out.Members = append(out.Members, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// API tokens (matched by subject_ref). token_hash is deliberately NOT selected.
		rows, err = tx.Query(ctx,
			`SELECT id::text, subject, scopes, expires_at, created_at
			   FROM api_tokens
			  WHERE tenant_id = $1 AND subject_ref = $2
			  ORDER BY id`, tenantID, out.SubjectRef)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyTokenRecord
			if err := rows.Scan(&r.ID, &r.Subject, &r.Scopes, &r.ExpiresAt, &r.CreatedAt); err != nil {
				rows.Close()
				return err
			}
			out.Tokens = append(out.Tokens, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Dual-control approvals: requester ties and approver ties.
		rows, err = tx.Query(ctx,
			`SELECT resource, action, 'requester' AS role, created_at AS at
			   FROM issuance_approval_requests
			  WHERE tenant_id = $1 AND requester = $2
			  UNION ALL
			 SELECT resource, action, 'approver' AS role, approved_at AS at
			   FROM issuance_approvals
			  WHERE tenant_id = $1 AND approver = $2
			  ORDER BY at`, tenantID, subject)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r PrivacyApprovalRecord
			if err := rows.Scan(&r.Resource, &r.Action, &r.Role, &r.At); err != nil {
				rows.Close()
				return err
			}
			out.Approvals = append(out.Approvals, r)
		}
		rows.Close()
		return rows.Err()
	})
	if err != nil {
		return PrivacySubjectExport{}, err
	}
	out.Counts = map[string]int{
		"owners":         len(out.Owners),
		"identities":     len(out.Identities),
		"certificates":   len(out.Certificates),
		"ssh_keys":       len(out.SSHKeys),
		"attestations":   len(out.Attestations),
		"tenant_members": len(out.Members),
		"api_tokens":     len(out.Tokens),
		"approvals":      len(out.Approvals),
	}
	return out, nil
}

// PrivacyRetentionCutoffs is the non-PII payload that makes a retention run
// replayable. The event carries time boundaries, not the raw subjects/approvers
// being anonymized.
type PrivacyRetentionCutoffs struct {
	OwnerInactiveBefore       time.Time `json:"owner_inactive_before"`
	IdentityTerminalBefore    time.Time `json:"identity_terminal_before"`
	CertificateTerminalBefore time.Time `json:"certificate_terminal_before"`
	SSHStaleBefore            time.Time `json:"ssh_stale_before"`
	AccessTerminalBefore      time.Time `json:"access_terminal_before"`
	ApprovalActorBefore       time.Time `json:"approval_actor_before"`
	ProfileActorBefore        time.Time `json:"profile_actor_before"`
	AttestationEvidenceBefore time.Time `json:"attestation_evidence_before"`
	AgentStaleBefore          time.Time `json:"agent_stale_before"`
}

// PrivacyRetentionRun is projected evidence for one non-audit PII retention pass.
type PrivacyRetentionRun struct {
	TenantID       string
	RunID          string
	RequestedByRef string
	Cutoffs        PrivacyRetentionCutoffs
	Counts         map[string]int
	EnforcedAt     time.Time
}

// Total reports the number of rows selected for anonymization.
func (r PrivacyRetentionRun) Total() int {
	var n int
	for _, c := range r.Counts {
		n += c
	}
	return n
}

// SelectPrivacySubjectErasure resolves a raw subject into non-PII selectors that
// can be recorded in the privacy.subject.erased event.
func (s *Store) SelectPrivacySubjectErasure(ctx context.Context, tenantID, subject string) (PrivacySubjectErasure, error) {
	if tenantID == "" {
		return PrivacySubjectErasure{}, fmt.Errorf("store: privacy erasure requires a tenant id (AN-1)")
	}
	if subject == "" {
		return PrivacySubjectErasure{}, fmt.Errorf("store: privacy erasure requires a subject")
	}
	out := PrivacySubjectErasure{
		TenantID:   tenantID,
		SubjectRef: privacy.SubjectRef(tenantID, subject),
		Counts:     map[string]int{},
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		if out.Selectors.OwnerIDs, err = selectStrings(ctx, tx,
			`SELECT id::text FROM owners
			  WHERE tenant_id = $1 AND (email = $2 OR name = $2)
			  ORDER BY id`, tenantID, subject); err != nil {
			return err
		}
		if out.Selectors.IdentityIDs, err = selectStrings(ctx, tx,
			`SELECT id::text FROM identities
			  WHERE tenant_id = $1 AND (name = $2 OR position($2 in attributes::text) > 0)
			  ORDER BY id`, tenantID, subject); err != nil {
			return err
		}
		if out.Selectors.CertificateFingerprints, err = selectStrings(ctx, tx,
			`SELECT fingerprint FROM certificates
			  WHERE tenant_id = $1 AND (subject = $2 OR $2 = ANY(sans))
			  ORDER BY fingerprint`, tenantID, subject); err != nil {
			return err
		}
		if out.Selectors.SSHKeyIDs, err = selectStrings(ctx, tx,
			`SELECT id::text FROM ssh_keys
			  WHERE tenant_id = $1 AND (comment = $2 OR location = $2)
			  ORDER BY id`, tenantID, subject); err != nil {
			return err
		}
		if out.Selectors.AttestationIDs, err = selectStrings(ctx, tx,
			`SELECT id::text FROM attestations
			  WHERE tenant_id = $1 AND position($2 in evidence::text) > 0
			  ORDER BY id`, tenantID, subject); err != nil {
			return err
		}
		memberCount, err := selectCount(ctx, tx,
			`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND subject_ref = $2`,
			tenantID, out.SubjectRef)
		if err != nil {
			return err
		}
		tokenCount, err := selectCount(ctx, tx,
			`SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject_ref = $2`,
			tenantID, out.SubjectRef)
		if err != nil {
			return err
		}
		out.Counts["tenant_members"] = memberCount
		out.Counts["api_tokens"] = tokenCount
		return nil
	})
	if err != nil {
		return PrivacySubjectErasure{}, err
	}
	for k, v := range countsForPrivacySelectors(out.Selectors) {
		if _, ok := out.Counts[k]; !ok {
			out.Counts[k] = v
		}
	}
	return out, nil
}

// SelectPrivacyRetention counts terminal/stale personal-data rows for one tenant.
// It returns only class cutoffs and aggregate counts, so the subsequent event can
// prove enforcement without storing the personal values being removed.
func (s *Store) SelectPrivacyRetention(ctx context.Context, tenantID, runID string, policy privacy.RetentionPolicy, now time.Time) (PrivacyRetentionRun, error) {
	if tenantID == "" {
		return PrivacyRetentionRun{}, fmt.Errorf("store: privacy retention requires a tenant id (AN-1)")
	}
	if runID == "" {
		return PrivacyRetentionRun{}, fmt.Errorf("store: privacy retention requires a run id")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	policy = policy.WithDefaults()
	run := PrivacyRetentionRun{
		TenantID: tenantID,
		RunID:    runID,
		Cutoffs: PrivacyRetentionCutoffs{
			OwnerInactiveBefore:       now.Add(-policy.OwnerInactiveAfter),
			IdentityTerminalBefore:    now.Add(-policy.IdentityTerminalAfter),
			CertificateTerminalBefore: now.Add(-policy.CertificateTerminalAfter),
			SSHStaleBefore:            now.Add(-policy.SSHStaleAfter),
			AccessTerminalBefore:      now.Add(-policy.AccessTerminalAfter),
			ApprovalActorBefore:       now.Add(-policy.ApprovalActorAfter),
			ProfileActorBefore:        now.Add(-policy.ProfileActorAfter),
			AttestationEvidenceBefore: now.Add(-policy.AttestationEvidenceAfter),
			AgentStaleBefore:          now.Add(-policy.AgentStaleAfter),
		},
		Counts: map[string]int{},
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		counts, err := countPrivacyRetentionRows(ctx, tx, tenantID, run.Cutoffs)
		if err != nil {
			return err
		}
		run.Counts = counts
		return nil
	})
	if err != nil {
		return PrivacyRetentionRun{}, err
	}
	return run, nil
}

// ApplyPrivacySubjectErasedTx projects a privacy.subject.erased event. The event
// is the source of truth; this method only derives the tenant read model from its
// subject_ref and stable selectors.
func (s *Store) ApplyPrivacySubjectErasedTx(ctx context.Context, tx pgx.Tx, e PrivacySubjectErasure) error {
	if e.ErasedAt.IsZero() {
		e.ErasedAt = time.Now().UTC()
	}
	if e.Counts == nil {
		e.Counts = countsForPrivacySelectors(e.Selectors)
	}
	selectors, err := json.Marshal(e.Selectors)
	if err != nil {
		return err
	}
	counts, err := json.Marshal(e.Counts)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO privacy_subject_erasures
		        (tenant_id, subject_ref, requested_by_ref, reason, selectors, counts, erased_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7)
		 ON CONFLICT (tenant_id, subject_ref) DO UPDATE
		    SET requested_by_ref = EXCLUDED.requested_by_ref,
		        reason = EXCLUDED.reason,
		        selectors = EXCLUDED.selectors,
		        counts = EXCLUDED.counts,
		        erased_at = EXCLUDED.erased_at`,
		e.TenantID, e.SubjectRef, e.RequestedByRef, e.Reason, selectors, counts, e.ErasedAt); err != nil {
		return err
	}
	placeholder := privacy.Placeholder(e.SubjectRef)
	if _, err := tx.Exec(ctx,
		`UPDATE tenant_members
		    SET subject = $3,
		        display_name = '',
		        email = '',
		        status = 'offboarded',
		        updated_at = $4,
		        offboarded_at = COALESCE(offboarded_at, $4),
		        offboarded_by = 'privacy-erasure',
		        offboard_reason = CASE WHEN offboard_reason = '' THEN $5 ELSE offboard_reason END
		  WHERE tenant_id = $1 AND subject_ref = $2 AND subject <> $3`,
		e.TenantID, e.SubjectRef, placeholder, e.ErasedAt, e.Reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE api_tokens
		    SET subject = $3,
		        revoked_at = COALESCE(revoked_at, $4),
		        revoked_by = CASE WHEN revoked_by = '' THEN 'privacy-erasure' ELSE revoked_by END,
		        revocation_reason = CASE WHEN revocation_reason = '' THEN $5 ELSE revocation_reason END
		  WHERE tenant_id = $1 AND subject_ref = $2`,
		e.TenantID, e.SubjectRef, placeholder, e.ErasedAt, e.Reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE owners
		    SET name = 'erased:' || left(id::text, 12), email = ''
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.OwnerIDs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE identities
		    SET name = 'erased:' || left(id::text, 12), attributes = '{}'::jsonb
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.IdentityIDs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET subject = 'erased:' || left(fingerprint, 12), sans = '{}'::text[]
		  WHERE tenant_id = $1 AND fingerprint = ANY($2::text[])`,
		e.TenantID, e.Selectors.CertificateFingerprints); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE ssh_keys
		    SET comment = '', location = ''
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.SSHKeyIDs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE attestations
		    SET evidence = '{}'::jsonb
		  WHERE tenant_id = $1 AND id::text = ANY($2::text[])`,
		e.TenantID, e.Selectors.AttestationIDs); err != nil {
		return err
	}
	return nil
}

// ApplyPrivacyRetentionEnforcedTx projects a privacy.retention.enforced event. It
// pseudonymizes terminal/stale operational PII while preserving row identifiers
// and security evidence needed for audit, incident, and lifecycle reconstruction.
func (s *Store) ApplyPrivacyRetentionEnforcedTx(ctx context.Context, tx pgx.Tx, r PrivacyRetentionRun) error {
	if r.EnforcedAt.IsZero() {
		r.EnforcedAt = time.Now().UTC()
	}
	if r.Counts == nil {
		r.Counts = map[string]int{}
	}
	cutoffs, err := json.Marshal(r.Cutoffs)
	if err != nil {
		return err
	}
	counts, err := json.Marshal(r.Counts)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO privacy_retention_runs
		        (tenant_id, run_id, requested_by_ref, cutoffs, counts, enforced_at)
		 VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)
		 ON CONFLICT (tenant_id, run_id) DO UPDATE
		    SET requested_by_ref = EXCLUDED.requested_by_ref,
		        cutoffs = EXCLUDED.cutoffs,
		        counts = EXCLUDED.counts,
		        enforced_at = EXCLUDED.enforced_at`,
		r.TenantID, r.RunID, r.RequestedByRef, cutoffs, counts, r.EnforcedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE owners
		    SET name = 'retained:' || left(id::text, 12),
		        email = ''
		  WHERE tenant_id = $1
		    AND created_at < $2
		    AND (email <> '' OR name NOT LIKE 'retained:%')
		    AND NOT EXISTS (
		          SELECT 1 FROM identities
		           WHERE tenant_id = $1 AND owner_id = owners.id
		        )`,
		r.TenantID, r.Cutoffs.OwnerInactiveBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE identities
		    SET name = 'retained:' || left(id::text, 12),
		        attributes = '{}'::jsonb
		  WHERE tenant_id = $1
		    AND (name NOT LIKE 'retained:%' OR attributes <> '{}'::jsonb)
		    AND (
		          (status IN ('revoked', 'retired') AND created_at < $2)
		       OR (not_after IS NOT NULL AND not_after < $2)
		    )`,
		r.TenantID, r.Cutoffs.IdentityTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET subject = 'retained:' || left(fingerprint, 12),
		        sans = '{}'::text[],
		        deployment_location = '',
		        source = ''
		  WHERE tenant_id = $1
		    AND (subject NOT LIKE 'retained:%' OR cardinality(sans) > 0 OR deployment_location <> '' OR source <> '')
		    AND (
		          (status IN ('revoked', 'superseded')
		           AND COALESCE(revoked_at, renewed_at, not_after, created_at) < $2)
		       OR (not_after IS NOT NULL AND not_after < $2)
		    )`,
		r.TenantID, r.Cutoffs.CertificateTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE ssh_keys
		    SET comment = '',
		        location = ''
		  WHERE tenant_id = $1
		    AND orphaned = true
		    AND created_at < $2
		    AND (comment <> '' OR location <> '')`,
		r.TenantID, r.Cutoffs.SSHStaleBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE attestations
		    SET evidence = '{}'::jsonb
		  WHERE tenant_id = $1
		    AND created_at < $2
		    AND evidence <> '{}'::jsonb`,
		r.TenantID, r.Cutoffs.AttestationEvidenceBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE issuance_approval_requests
		    SET requester = 'retained:' || left(md5($1::text || ':' || requester), 12)
		  WHERE tenant_id = $1
		    AND created_at < $2
		    AND requester <> ''
		    AND requester NOT LIKE 'retained:%'`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE issuance_approvals
		    SET approver = 'retained:' || left(md5($1::text || ':' || approver), 12)
		  WHERE tenant_id = $1
		    AND approved_at < $2
		    AND approver <> ''
		    AND approver NOT LIKE 'retained:%'`,
		r.TenantID, r.Cutoffs.ApprovalActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE certificate_profiles
		    SET created_by = 'retained:' || left(id::text, 12)
		  WHERE tenant_id = $1
		    AND created_at < $2
		    AND created_by <> ''
		    AND created_by NOT LIKE 'retained:%'`,
		r.TenantID, r.Cutoffs.ProfileActorBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE api_tokens
		    SET subject = 'erased:' || left(subject_ref, 12)
		  WHERE tenant_id = $1
		    AND subject_ref <> ''
		    AND subject NOT LIKE 'erased:%'
		    AND (
		          (revoked_at IS NOT NULL AND revoked_at < $2)
		       OR (expires_at IS NOT NULL AND expires_at < $2)
		    )`,
		r.TenantID, r.Cutoffs.AccessTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE tenant_members
		    SET subject = 'erased:' || left(subject_ref, 12),
		        display_name = '',
		        email = ''
		  WHERE tenant_id = $1
		    AND subject_ref <> ''
		    AND status = 'offboarded'
		    AND offboarded_at IS NOT NULL
		    AND offboarded_at < $2
		    AND (subject NOT LIKE 'erased:%' OR display_name <> '' OR email <> '')`,
		r.TenantID, r.Cutoffs.AccessTerminalBefore); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agents
		    SET name = 'retained:' || left(id::text, 12)
		  WHERE tenant_id = $1
		    AND name NOT LIKE 'retained:%'
		    AND (
		          (last_seen_at IS NOT NULL AND last_seen_at < $2)
		       OR (last_seen_at IS NULL AND created_at < $2)
		    )`,
		r.TenantID, r.Cutoffs.AgentStaleBefore); err != nil {
		return err
	}
	return nil
}

// ListPrivacySubjectErasuresPage returns erasure evidence in newest-first order.
func (s *Store) ListPrivacySubjectErasuresPage(ctx context.Context, tenantID, afterRef string, limit int) ([]PrivacySubjectErasure, error) {
	var out []PrivacySubjectErasure
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, subject_ref, requested_by_ref, reason, selectors, counts, erased_at
			   FROM privacy_subject_erasures
			  WHERE tenant_id = $1 AND ($2 = '' OR subject_ref > $2)
			  ORDER BY subject_ref LIMIT $3`,
			tenantID, afterRef, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPrivacySubjectErasure(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListPrivacyRetentionRunsPage returns projected retention evidence.
func (s *Store) ListPrivacyRetentionRunsPage(ctx context.Context, tenantID, afterRunID string, limit int) ([]PrivacyRetentionRun, error) {
	var out []PrivacyRetentionRun
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, run_id::text, requested_by_ref, cutoffs, counts, enforced_at
			   FROM privacy_retention_runs
			  WHERE tenant_id = $1 AND ($2 = '' OR run_id::text > $2)
			  ORDER BY run_id LIMIT $3`,
			tenantID, afterRunID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanPrivacyRetentionRun(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListPrivacyErasureRefs returns the tenant's erased subject refs for audit
// redaction. The values are non-PII hashes and the query is tenant-scoped.
func (s *Store) ListPrivacyErasureRefs(ctx context.Context, tenantID string) (map[string]struct{}, error) {
	refs := map[string]struct{}{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT subject_ref FROM privacy_subject_erasures WHERE tenant_id = $1`,
			tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ref string
			if err := rows.Scan(&ref); err != nil {
				return err
			}
			refs[ref] = struct{}{}
		}
		return rows.Err()
	})
	return refs, err
}

func scanPrivacySubjectErasure(row pgx.Row) (PrivacySubjectErasure, error) {
	var (
		r             PrivacySubjectErasure
		selectorsJSON []byte
		countsJSON    []byte
	)
	if err := row.Scan(&r.TenantID, &r.SubjectRef, &r.RequestedByRef, &r.Reason, &selectorsJSON, &countsJSON, &r.ErasedAt); err != nil {
		return PrivacySubjectErasure{}, err
	}
	if len(selectorsJSON) > 0 {
		if err := json.Unmarshal(selectorsJSON, &r.Selectors); err != nil {
			return PrivacySubjectErasure{}, err
		}
	}
	if len(countsJSON) > 0 {
		if err := json.Unmarshal(countsJSON, &r.Counts); err != nil {
			return PrivacySubjectErasure{}, err
		}
	}
	return r, nil
}

func scanPrivacyRetentionRun(row pgx.Row) (PrivacyRetentionRun, error) {
	var (
		r           PrivacyRetentionRun
		cutoffsJSON []byte
		countsJSON  []byte
	)
	if err := row.Scan(&r.TenantID, &r.RunID, &r.RequestedByRef, &cutoffsJSON, &countsJSON, &r.EnforcedAt); err != nil {
		return PrivacyRetentionRun{}, err
	}
	if len(cutoffsJSON) > 0 {
		if err := json.Unmarshal(cutoffsJSON, &r.Cutoffs); err != nil {
			return PrivacyRetentionRun{}, err
		}
	}
	if len(countsJSON) > 0 {
		if err := json.Unmarshal(countsJSON, &r.Counts); err != nil {
			return PrivacyRetentionRun{}, err
		}
	}
	return r, nil
}

func selectStrings(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func countPrivacyRetentionRows(ctx context.Context, tx pgx.Tx, tenantID string, c PrivacyRetentionCutoffs) (map[string]int, error) {
	queries := map[string]struct {
		sql  string
		args []any
	}{
		"owners": {
			sql: `SELECT count(*) FROM owners
			       WHERE tenant_id = $1
			         AND created_at < $2
			         AND (email <> '' OR name NOT LIKE 'retained:%')
			         AND NOT EXISTS (
			               SELECT 1 FROM identities
			                WHERE tenant_id = $1 AND owner_id = owners.id
			             )`,
			args: []any{tenantID, c.OwnerInactiveBefore},
		},
		"identities": {
			sql: `SELECT count(*) FROM identities
			       WHERE tenant_id = $1
			         AND (name NOT LIKE 'retained:%' OR attributes <> '{}'::jsonb)
			         AND (
			               (status IN ('revoked', 'retired') AND created_at < $2)
			            OR (not_after IS NOT NULL AND not_after < $2)
			         )`,
			args: []any{tenantID, c.IdentityTerminalBefore},
		},
		"certificates": {
			sql: `SELECT count(*) FROM certificates
			       WHERE tenant_id = $1
			         AND (subject NOT LIKE 'retained:%' OR cardinality(sans) > 0 OR deployment_location <> '' OR source <> '')
			         AND (
			               (status IN ('revoked', 'superseded')
			                AND COALESCE(revoked_at, renewed_at, not_after, created_at) < $2)
			            OR (not_after IS NOT NULL AND not_after < $2)
			         )`,
			args: []any{tenantID, c.CertificateTerminalBefore},
		},
		"ssh_keys": {
			sql: `SELECT count(*) FROM ssh_keys
			       WHERE tenant_id = $1
			         AND orphaned = true
			         AND created_at < $2
			         AND (comment <> '' OR location <> '')`,
			args: []any{tenantID, c.SSHStaleBefore},
		},
		"attestations": {
			sql: `SELECT count(*) FROM attestations
			       WHERE tenant_id = $1
			         AND created_at < $2
			         AND evidence <> '{}'::jsonb`,
			args: []any{tenantID, c.AttestationEvidenceBefore},
		},
		"approval_requests": {
			sql: `SELECT count(*) FROM issuance_approval_requests
			       WHERE tenant_id = $1
			         AND created_at < $2
			         AND requester <> ''
			         AND requester NOT LIKE 'retained:%'`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"approvals": {
			sql: `SELECT count(*) FROM issuance_approvals
			       WHERE tenant_id = $1
			         AND approved_at < $2
			         AND approver <> ''
			         AND approver NOT LIKE 'retained:%'`,
			args: []any{tenantID, c.ApprovalActorBefore},
		},
		"profiles": {
			sql: `SELECT count(*) FROM certificate_profiles
			       WHERE tenant_id = $1
			         AND created_at < $2
			         AND created_by <> ''
			         AND created_by NOT LIKE 'retained:%'`,
			args: []any{tenantID, c.ProfileActorBefore},
		},
		"api_tokens": {
			sql: `SELECT count(*) FROM api_tokens
			       WHERE tenant_id = $1
			         AND subject_ref <> ''
			         AND subject NOT LIKE 'erased:%'
			         AND (
			               (revoked_at IS NOT NULL AND revoked_at < $2)
			            OR (expires_at IS NOT NULL AND expires_at < $2)
			         )`,
			args: []any{tenantID, c.AccessTerminalBefore},
		},
		"tenant_members": {
			sql: `SELECT count(*) FROM tenant_members
			       WHERE tenant_id = $1
			         AND subject_ref <> ''
			         AND status = 'offboarded'
			         AND offboarded_at IS NOT NULL
			         AND offboarded_at < $2
			         AND (subject NOT LIKE 'erased:%' OR display_name <> '' OR email <> '')`,
			args: []any{tenantID, c.AccessTerminalBefore},
		},
		"agents": {
			sql: `SELECT count(*) FROM agents
			       WHERE tenant_id = $1
			         AND name NOT LIKE 'retained:%'
			         AND (
			               (last_seen_at IS NOT NULL AND last_seen_at < $2)
			            OR (last_seen_at IS NULL AND created_at < $2)
			         )`,
			args: []any{tenantID, c.AgentStaleBefore},
		},
	}
	out := make(map[string]int, len(queries))
	for k, q := range queries {
		n, err := selectCount(ctx, tx, q.sql, q.args...)
		if err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, nil
}

func selectCount(ctx context.Context, tx pgx.Tx, sql string, args ...any) (int, error) {
	var out int
	if err := tx.QueryRow(ctx, sql, args...).Scan(&out); err != nil {
		return 0, err
	}
	return out, nil
}

func countsForPrivacySelectors(sel PrivacyErasureSelectors) map[string]int {
	return map[string]int{
		"owners":         len(sel.OwnerIDs),
		"identities":     len(sel.IdentityIDs),
		"certificates":   len(sel.CertificateFingerprints),
		"ssh_keys":       len(sel.SSHKeyIDs),
		"attestations":   len(sel.AttestationIDs),
		"api_tokens":     0, // filled by subject_ref update at projection time; rows are not enumerated in the event.
		"tenant_members": 0,
	}
}
