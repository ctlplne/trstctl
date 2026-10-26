// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// CertificateFilter is a typed certificate inventory question. Every field is
// bound as a query parameter, so a question planner can turn an operator's
// wording into a filter without any of that wording reaching statement text.
// Zero fields do not filter. Expected ephemeral credentials are left out, as on
// the expiry views.
type CertificateFilter struct {
	// Status is "active", "revoked" or "superseded"; empty means any status.
	Status string
	// ExpiresAfter and ExpiresBefore bound not_after, exclusively; nil is open.
	ExpiresAfter, ExpiresBefore *time.Time
	// IssuerContains and NameContains are case-insensitive literal substrings
	// of the issuer, and of the subject or any SAN.
	IssuerContains, NameContains string
	// KeyAlgorithm is a key algorithm family: it matches the recorded algorithm
	// case-insensitively, exactly or as the part before a dash ("ECDSA" matches
	// "ECDSA-P256", "ML-DSA" matches "ML-DSA-65").
	KeyAlgorithm string
	// OwnerName selects certificates whose owner has exactly this name, case
	// aside; Unowned selects certificates with no owner.
	OwnerName string
	Unowned   bool
	// Serial and Fingerprint select one certificate exactly, case aside.
	Serial, Fingerprint string
}

// FilterCertificates returns up to limit certificates matching f, ordered by
// expiry then ID, under the tenant's RLS boundary. Pass one more than the
// rows wanted to learn whether the result is complete.
func (s *Store) FilterCertificates(ctx context.Context, tenantID string, f CertificateFilter, limit int) ([]Certificate, error) {
	where, args, err := f.predicates(tenantID)
	if err != nil {
		return nil, err
	}
	args = append(args, limit)
	var out []Certificate
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The only formatted text is parameter positions; every value is bound.
		rows, err := tx.Query(ctx, `SELECT `+certificateColumns+`
			   FROM certificates
			  WHERE tenant_id = $1`+where+fmt.Sprintf(`
			  ORDER BY not_after NULLS LAST, id LIMIT $%d`, len(args)), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Certificate
			if err := scanCertificate(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// CountCertificates counts the certificates matching f exactly.
func (s *Store) CountCertificates(ctx context.Context, tenantID string, f CertificateFilter) (int, error) {
	where, args, err := f.predicates(tenantID)
	if err != nil {
		return 0, err
	}
	var n int
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM certificates WHERE tenant_id = $1`+where, args...).Scan(&n)
	})
	return n, err
}

// predicates returns the filter's clauses after the tenant predicate, and their
// arguments with the tenant first.
func (f CertificateFilter) predicates(tenantID string) (string, []any, error) {
	var b strings.Builder
	args := []any{tenantID}
	add := func(format string, value any) {
		args = append(args, value)
		fmt.Fprintf(&b, " AND "+format, len(args))
	}
	b.WriteString(" AND issuance_idempotency_key NOT LIKE 'ephemeral-issue:%'")
	switch f.Status {
	case "":
	case "active", "revoked", "superseded":
		add("status = $%d", f.Status)
	default:
		return "", nil, fmt.Errorf("store: unknown certificate status %q", f.Status)
	}
	if f.ExpiresAfter != nil {
		add("not_after > $%d", *f.ExpiresAfter)
	}
	if f.ExpiresBefore != nil {
		add("not_after < $%d", *f.ExpiresBefore)
	}
	if f.IssuerContains != "" {
		add("strpos(lower(issuer), lower($%d)) > 0", f.IssuerContains)
	}
	if f.NameContains != "" {
		add("(strpos(lower(subject), lower($%[1]d)) > 0 OR EXISTS (SELECT 1 FROM unnest(sans) AS name WHERE strpos(lower(name), lower($%[1]d)) > 0))", f.NameContains)
	}
	if f.KeyAlgorithm != "" {
		add("(lower(key_algorithm) = lower($%[1]d) OR strpos(lower(key_algorithm), lower($%[1]d) || '-') = 1)", f.KeyAlgorithm)
	}
	if f.OwnerName != "" && f.Unowned {
		return "", nil, errors.New("store: a certificate cannot have the named owner and no owner")
	}
	if f.OwnerName != "" {
		add("owner_id IN (SELECT id FROM owners WHERE tenant_id = $1 AND lower(name) = lower($%d))", f.OwnerName)
	}
	if f.Unowned {
		b.WriteString(" AND owner_id IS NULL")
	}
	if f.Serial != "" {
		add("lower(serial) = lower($%d)", f.Serial)
	}
	if f.Fingerprint != "" {
		add("lower(fingerprint) = lower($%d)", f.Fingerprint)
	}
	return b.String(), args, nil
}
