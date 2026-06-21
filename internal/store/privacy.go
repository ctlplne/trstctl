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
