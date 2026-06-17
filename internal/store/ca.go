package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds the private-CA hierarchy repositories (F48, S4.15): the CA
// authorities trstctl operates and the m-of-n key ceremonies that gate CA-key
// creation. Every query is tenant-scoped and runs under row-level security
// (AN-1). The CA's signing key is never stored here — only its certificate
// (public material); key custody is the signer/HSM (AN-4).

// CAAuthority is a root or intermediate CA trstctl operates, with its policy.
type CAAuthority struct {
	ID                string
	TenantID          string
	ParentID          *string
	CommonName        string
	Kind              string // root | intermediate
	Status            string // active | superseded | revoked
	CertificatePEM    string
	Serial            string
	NotAfter          *time.Time
	MaxPathLen        int
	PermittedDNSNames []string
	EKUs              []string
	ReplacesID        *string
	CreatedAt         time.Time
}

// InsertCAAuthority inserts a CA authority with a server-generated id, returning
// it populated with that id and created_at.
func (s *Store) InsertCAAuthority(ctx context.Context, c CAAuthority) (CAAuthority, error) {
	var out CAAuthority
	err := s.WithTenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = s.InsertCAAuthorityTx(ctx, tx, c)
		return err
	})
	return out, err
}

// InsertCAAuthorityTx inserts a CA authority on the caller's transaction (so a
// rotation can insert the successor and supersede the predecessor atomically).
func (s *Store) InsertCAAuthorityTx(ctx context.Context, tx pgx.Tx, c CAAuthority) (CAAuthority, error) {
	dns := c.PermittedDNSNames
	if dns == nil {
		dns = []string{}
	}
	ekus := c.EKUs
	if ekus == nil {
		ekus = []string{}
	}
	status := c.Status
	if status == "" {
		status = "active"
	}
	err := tx.QueryRow(ctx,
		`INSERT INTO ca_authorities
		        (id, tenant_id, parent_id, common_name, kind, status, certificate_pem,
		         serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 RETURNING id::text, created_at`,
		c.TenantID, c.ParentID, c.CommonName, c.Kind, status, c.CertificatePEM,
		c.Serial, c.NotAfter, c.MaxPathLen, dns, ekus, c.ReplacesID).
		Scan(&c.ID, &c.CreatedAt)
	c.Status = status
	c.PermittedDNSNames = dns
	c.EKUs = ekus
	return c, err
}

func scanCAAuthority(row pgx.Row, c *CAAuthority) error {
	return row.Scan(&c.ID, &c.TenantID, &c.ParentID, &c.CommonName, &c.Kind, &c.Status,
		&c.CertificatePEM, &c.Serial, &c.NotAfter, &c.MaxPathLen, &c.PermittedDNSNames, &c.EKUs,
		&c.ReplacesID, &c.CreatedAt)
}

// GetCAAuthority loads a CA authority in its tenant context.
func (s *Store) GetCAAuthority(ctx context.Context, tenantID, id string) (CAAuthority, error) {
	var c CAAuthority
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCAAuthority(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, parent_id::text, common_name, kind, status,
			        certificate_pem, serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id::text, created_at
			   FROM ca_authorities WHERE tenant_id = $1 AND id = $2`, tenantID, id), &c)
	})
	return c, err
}

// ListCAAuthorities returns a tenant's CA authorities, oldest first.
func (s *Store) ListCAAuthorities(ctx context.Context, tenantID string) ([]CAAuthority, error) {
	var out []CAAuthority
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, parent_id::text, common_name, kind, status,
			        certificate_pem, serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id::text, created_at
			   FROM ca_authorities WHERE tenant_id = $1 ORDER BY created_at, id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c CAAuthority
			if err := scanCAAuthority(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// SupersedeCAAuthorityTx marks a CA authority superseded, on the caller's
// transaction (so it commits atomically with inserting its successor).
func (s *Store) SupersedeCAAuthorityTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx,
		`UPDATE ca_authorities SET status = 'superseded' WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	return err
}

// KeyCeremony is an m-of-n CA key-generation ceremony. Approvals is the current
// count of distinct custodian approvals. Opener is the authenticated principal
// who started it (empty when unattributed), used to enforce opener != approver
// separation of duties (PKIGOV-006).
type KeyCeremony struct {
	ID        string
	TenantID  string
	Purpose   string
	Threshold int
	Status    string // pending | completed
	Approvals int
	Opener    string
	CreatedAt time.Time
}

// ErrSelfApproval is returned when a ceremony's opener attempts to approve their
// own ceremony, violating opener != approver separation of duties (PKIGOV-006).
var ErrSelfApproval = errors.New("store: ceremony opener may not approve their own ceremony (separation of duties)")

// ErrAnonymousApproval is returned when a ceremony approval carries no custodian
// identity (PKIGOV-006): a custodian must be a named, authenticated principal, not
// an empty string.
var ErrAnonymousApproval = errors.New("store: ceremony approval requires an authenticated custodian identity")

// ErrKeyCeremonyNotPending is returned when a CA operation tries to consume a
// completed ceremony. Ceremonies are single-use approvals.
var ErrKeyCeremonyNotPending = errors.New("store: key ceremony is not pending")

// ErrKeyCeremonyPurposeMismatch is returned when a CA operation tries to consume
// a ceremony opened for a different operation/resource.
var ErrKeyCeremonyPurposeMismatch = errors.New("store: key ceremony purpose mismatch")

// ErrKeyCeremonyQuorumNotMet is returned when a CA operation tries to consume a
// ceremony before its approval threshold is reached.
var ErrKeyCeremonyQuorumNotMet = errors.New("store: key ceremony quorum not met")

// CreateKeyCeremony starts a ceremony requiring threshold approvals, recording the
// opener (the authenticated principal starting it, for opener != approver SoD),
// and returns its id.
func (s *Store) CreateKeyCeremony(ctx context.Context, tenantID, purpose, opener string, threshold int) (string, error) {
	var id string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO ca_key_ceremonies (id, tenant_id, purpose, opener, threshold)
			 VALUES (gen_random_uuid(), $1, $2, $3, $4)
			 RETURNING id::text`,
			tenantID, purpose, opener, threshold).Scan(&id)
	})
	return id, err
}

// ApproveKeyCeremony records a custodian's approval (idempotent per custodian) and
// returns the resulting distinct-approval count. It enforces PKIGOV-006: the
// custodian must be a named identity (not empty), and the ceremony's opener may not
// approve their own ceremony (opener != approver). Both checks run in the same
// tenant-scoped transaction as the insert, fail closed, and never record a
// disallowed approval.
func (s *Store) ApproveKeyCeremony(ctx context.Context, tenantID, ceremonyID, custodian string) (int, error) {
	if custodian == "" {
		return 0, ErrAnonymousApproval
	}
	var count int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Separation of duties: a ceremony's opener cannot also approve it.
		var opener string
		if err := tx.QueryRow(ctx,
			`SELECT opener FROM ca_key_ceremonies WHERE tenant_id = $1 AND id = $2`,
			tenantID, ceremonyID).Scan(&opener); err != nil {
			return err
		}
		if opener != "" && opener == custodian {
			return ErrSelfApproval
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ca_ceremony_approvals (tenant_id, ceremony_id, custodian)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (tenant_id, ceremony_id, custodian) DO NOTHING`,
			tenantID, ceremonyID, custodian); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM ca_ceremony_approvals WHERE tenant_id = $1 AND ceremony_id = $2`,
			tenantID, ceremonyID).Scan(&count)
	})
	return count, err
}

// GetKeyCeremony loads a ceremony with its current approval count and opener.
func (s *Store) GetKeyCeremony(ctx context.Context, tenantID, id string) (KeyCeremony, error) {
	var c KeyCeremony
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, purpose, threshold, status, opener, created_at,
			        (SELECT count(*) FROM ca_ceremony_approvals a
			          WHERE a.tenant_id = c.tenant_id AND a.ceremony_id = c.id)
			   FROM ca_key_ceremonies c WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&c.ID, &c.TenantID, &c.Purpose, &c.Threshold, &c.Status, &c.Opener, &c.CreatedAt, &c.Approvals)
	})
	return c, err
}

// CompleteKeyCeremony marks a ceremony completed once it has fulfilled its
// purpose (the CA key has been created).
func (s *Store) CompleteKeyCeremony(ctx context.Context, tenantID, id string) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE ca_key_ceremonies SET status = 'completed', completed_at = now()
			   WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`,
			tenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrKeyCeremonyNotPending
		}
		return nil
	})
}

// ConsumeKeyCeremonyTx validates and completes a key ceremony on the caller's
// transaction. This is the atomic governance primitive for CA mutations: the CA
// row write and the ceremony status change commit or roll back together, and a
// completed ceremony cannot be reused.
func (s *Store) ConsumeKeyCeremonyTx(ctx context.Context, tx pgx.Tx, tenantID, id, expectedPurpose string) (KeyCeremony, error) {
	var c KeyCeremony
	if err := tx.QueryRow(ctx,
		`SELECT c.id::text, c.tenant_id::text, c.purpose, c.threshold, c.status, c.opener, c.created_at,
		        (SELECT count(*) FROM ca_ceremony_approvals a
		          WHERE a.tenant_id = c.tenant_id AND a.ceremony_id = c.id)
		   FROM ca_key_ceremonies c
		  WHERE c.tenant_id = $1 AND c.id = $2
		  FOR UPDATE`,
		tenantID, id).
		Scan(&c.ID, &c.TenantID, &c.Purpose, &c.Threshold, &c.Status, &c.Opener, &c.CreatedAt, &c.Approvals); err != nil {
		return c, err
	}
	if c.Status != "pending" {
		return c, ErrKeyCeremonyNotPending
	}
	if c.Purpose != expectedPurpose {
		return c, ErrKeyCeremonyPurposeMismatch
	}
	if c.Approvals < c.Threshold {
		return c, ErrKeyCeremonyQuorumNotMet
	}
	tag, err := tx.Exec(ctx,
		`UPDATE ca_key_ceremonies
		    SET status = 'completed', completed_at = now()
		  WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`,
		tenantID, id)
	if err != nil {
		return c, err
	}
	if tag.RowsAffected() != 1 {
		return c, ErrKeyCeremonyNotPending
	}
	c.Status = "completed"
	return c, nil
}
