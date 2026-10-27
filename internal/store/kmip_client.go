// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// A197: tenant self-service KMIP clients, projected from the kmip.client.*
// events. A registration holds a pending enrollment secret's hash until the
// client's first KMIP request binds its certificate; from then on the
// certificate's fingerprint selects the tenant on the shared listener.

// KMIPClient is one registered KMIP client.
type KMIPClient struct {
	TenantID string
	ID       string
	Name     string
	// EnrollmentHash is the SHA-256 of the pending enrollment secret; empty
	// once a certificate bound with it.
	EnrollmentHash      string
	EnrollmentExpiresAt *time.Time
	// Fingerprint is the SHA-256 of the bound certificate's DER; empty until
	// the client enrolls.
	Fingerprint string
	Subject     string
	NotAfter    *time.Time
	EnrolledAt  *time.Time
	CreatedAt   time.Time
}

// ApplyKMIPClientRegisteredTx projects kmip.client.registered. A replay of
// the same registration changes nothing.
func (s *Store) ApplyKMIPClientRegisteredTx(ctx context.Context, tx pgx.Tx, c KMIPClient) error {
	if c.EnrollmentHash == "" || c.EnrollmentExpiresAt == nil {
		return errors.New("store: a KMIP client registration needs its enrollment")
	}
	// Serialize on the registration's id: the table's other unique keys (the
	// id alone, a bound certificate) would otherwise let a concurrent identical
	// insert raise 23505 instead of reaching ON CONFLICT (OPP-C01).
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "kmip-client\x1f"+c.ID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO kmip_clients
		(tenant_id, id, name, enrollment_hash, enrollment_expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		c.TenantID, c.ID, c.Name, c.EnrollmentHash, c.EnrollmentExpiresAt.UTC(), c.CreatedAt.UTC())
	return err
}

// ApplyKMIPClientEnrollmentIssuedTx projects kmip.client.enrollment_issued: a
// new secret the client's next enrollment binds with. A bound certificate
// keeps serving until a new one enrolls.
func (s *Store) ApplyKMIPClientEnrollmentIssuedTx(ctx context.Context, tx pgx.Tx, tenantID, id, hash string, expiresAt time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE kmip_clients SET enrollment_hash = $3, enrollment_expires_at = $4
		WHERE tenant_id = $1 AND id = $2`, tenantID, id, hash, expiresAt.UTC())
	return err
}

// ApplyKMIPClientEnrolledTx projects kmip.client.enrolled: the certificate
// that presented the secret replaces any earlier one, and the secret is spent.
func (s *Store) ApplyKMIPClientEnrolledTx(ctx context.Context, tx pgx.Tx, tenantID, id, fingerprint, subject string, notAfter, enrolledAt time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE kmip_clients
		   SET fingerprint = $3, subject = $4, not_after = $5, enrolled_at = $6,
		       enrollment_hash = '', enrollment_expires_at = NULL
		 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, fingerprint, subject, notAfter.UTC(), enrolledAt.UTC())
	return err
}

// ApplyKMIPClientRemovedTx projects kmip.client.removed.
func (s *Store) ApplyKMIPClientRemovedTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM kmip_clients WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

const kmipClientColumns = `tenant_id::text, id::text, name, enrollment_hash, enrollment_expires_at,
	coalesce(fingerprint, ''), subject, not_after, enrolled_at, created_at`

func scanKMIPClient(row pgx.Row) (KMIPClient, error) {
	var c KMIPClient
	err := row.Scan(&c.TenantID, &c.ID, &c.Name, &c.EnrollmentHash, &c.EnrollmentExpiresAt,
		&c.Fingerprint, &c.Subject, &c.NotAfter, &c.EnrolledAt, &c.CreatedAt)
	return c, err
}

// KMIPClients lists a tenant's registered KMIP clients, oldest first.
func (s *Store) KMIPClients(ctx context.Context, tenantID string) ([]KMIPClient, error) {
	var out []KMIPClient
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+kmipClientColumns+` FROM kmip_clients
			WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanKMIPClient(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// KMIPClient reads one of a tenant's registered KMIP clients.
func (s *Store) KMIPClient(ctx context.Context, tenantID, id string) (KMIPClient, bool, error) {
	var (
		c     KMIPClient
		found bool
	)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		c, err = scanKMIPClient(tx.QueryRow(ctx, `SELECT `+kmipClientColumns+` FROM kmip_clients
			WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return c, found, err
}

// KMIPClientByFingerprint finds the registration a certificate is bound to,
// in any tenant: the KMIP listener resolves the tenant from the certificate
// before any tenant is known.
func (s *Store) KMIPClientByFingerprint(ctx context.Context, fingerprint string) (KMIPClient, bool, error) {
	c, err := scanKMIPClient(s.pool.QueryRow(ctx,
		//trstctl:system-query — the KMIP listener resolves a client's tenant from its TLS certificate before any tenant is known; the lookup is keyed by the globally unique SHA-256 of a certificate the client proved it holds, and returns the owning tenant. Cross-tenant by design; runs on the pool, not under RLS (AN-1 exemption).
		`SELECT `+kmipClientColumns+` FROM kmip_clients WHERE fingerprint = $1`, fingerprint))
	if errors.Is(err, pgx.ErrNoRows) {
		return KMIPClient{}, false, nil
	}
	return c, err == nil, err
}

// KMIPClientForEnrollment finds a registration by its identifier, in any
// tenant: an enrolling client names it as its KMIP username before any tenant
// is known, and the caller proves the enrollment secret against the hash.
func (s *Store) KMIPClientForEnrollment(ctx context.Context, id string) (KMIPClient, bool, error) {
	c, err := scanKMIPClient(s.pool.QueryRow(ctx,
		//trstctl:system-query — a KMIP client enrolls before any tenant is known, naming its registration (a random UUID) as its KMIP username; the caller compares the presented secret with the stored SHA-256 before anything is bound. Cross-tenant by design; runs on the pool, not under RLS (AN-1 exemption).
		`SELECT `+kmipClientColumns+` FROM kmip_clients WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return KMIPClient{}, false, nil
	}
	return c, err == nil, err
}
