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
	SignerHandle      string
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
		         signer_handle, serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id)
		 VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10, $11, $12, $13)
		 RETURNING id::text, created_at`,
		c.TenantID, c.ParentID, c.CommonName, c.Kind, status, c.CertificatePEM,
		c.SignerHandle, c.Serial, c.NotAfter, c.MaxPathLen, dns, ekus, c.ReplacesID).
		Scan(&c.ID, &c.CreatedAt)
	c.Status = status
	c.PermittedDNSNames = dns
	c.EKUs = ekus
	return c, err
}

func scanCAAuthority(row pgx.Row, c *CAAuthority) error {
	return row.Scan(&c.ID, &c.TenantID, &c.ParentID, &c.CommonName, &c.Kind, &c.Status,
		&c.CertificatePEM, &c.SignerHandle, &c.Serial, &c.NotAfter, &c.MaxPathLen, &c.PermittedDNSNames, &c.EKUs,
		&c.ReplacesID, &c.CreatedAt)
}

// GetCAAuthority loads a CA authority in its tenant context.
func (s *Store) GetCAAuthority(ctx context.Context, tenantID, id string) (CAAuthority, error) {
	var c CAAuthority
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCAAuthority(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, parent_id::text, common_name, kind, status,
			        certificate_pem, COALESCE(signer_handle, ''), serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id::text, created_at
			   FROM ca_authorities WHERE tenant_id = $1 AND id = $2`, tenantID, id), &c)
	})
	return c, err
}

// GetCAAuthorityForUpdateTx loads and row-locks a CA authority in the caller's
// tenant transaction. Rotation uses this to make the predecessor/successor state
// transition one atomic decision under PostgreSQL RLS.
func (s *Store) GetCAAuthorityForUpdateTx(ctx context.Context, tx pgx.Tx, tenantID, id string) (CAAuthority, error) {
	var c CAAuthority
	err := scanCAAuthority(tx.QueryRow(ctx,
		`SELECT id::text, tenant_id::text, parent_id::text, common_name, kind, status,
		        certificate_pem, COALESCE(signer_handle, ''), serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id::text, created_at
		   FROM ca_authorities WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id), &c)
	return c, err
}

// ListCAAuthorities returns a tenant's CA authorities, oldest first.
func (s *Store) ListCAAuthorities(ctx context.Context, tenantID string) ([]CAAuthority, error) {
	var out []CAAuthority
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, parent_id::text, common_name, kind, status,
			        certificate_pem, COALESCE(signer_handle, ''), serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id::text, created_at
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

// FindActiveCAAuthoritySuccessor returns the active signer-backed replacement for
// a superseded authority. This is what lets the old issuance URL keep working
// during a zero-downtime rotation window while the actual signer moves forward.
func (s *Store) FindActiveCAAuthoritySuccessor(ctx context.Context, tenantID, replacesID string) (CAAuthority, error) {
	var c CAAuthority
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCAAuthority(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, parent_id::text, common_name, kind, status,
			        certificate_pem, COALESCE(signer_handle, ''), serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id::text, created_at
			   FROM ca_authorities
			  WHERE tenant_id = $1 AND replaces_id = $2 AND status = 'active'
			  ORDER BY created_at DESC, id DESC
			  LIMIT 1`,
			tenantID, replacesID), &c)
	})
	return c, err
}

// SupersedeCAAuthorityTx marks a CA authority superseded, on the caller's
// transaction (so it commits atomically with inserting its successor).
func (s *Store) SupersedeCAAuthorityTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	tag, err := tx.Exec(ctx,
		`UPDATE ca_authorities SET status = 'superseded' WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyCAAuthorityRotatedTx projects a ca.authority.rotated event into the CA
// hierarchy read model. Command handlers append the event; only the projector
// calls this writer, so a rebuild from the event log reproduces the same
// predecessor/successor state (AN-2).
func (s *Store) ApplyCAAuthorityRotatedTx(ctx context.Context, tx pgx.Tx, tenantID, predecessorID, successorID string) error {
	tag, err := tx.Exec(ctx,
		`UPDATE ca_authorities
		    SET status = 'superseded'
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, predecessorID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	tag, err = tx.Exec(ctx,
		`UPDATE ca_authorities
		    SET replaces_id = $2
		  WHERE tenant_id = $1 AND id = $3`,
		tenantID, predecessorID, successorID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplyCAAuthorityRekeyedTx projects a ca.authority.rekeyed event into the CA
// hierarchy read model. The event owns the successor id and public certificate
// bytes, so replay never invents a different CA row for the same re-key ceremony.
func (s *Store) ApplyCAAuthorityRekeyedTx(ctx context.Context, tx pgx.Tx, successor CAAuthority, predecessorID string) error {
	dns := successor.PermittedDNSNames
	if dns == nil {
		dns = []string{}
	}
	ekus := successor.EKUs
	if ekus == nil {
		ekus = []string{}
	}
	status := successor.Status
	if status == "" {
		status = "active"
	}
	if successor.CreatedAt.IsZero() {
		successor.CreatedAt = time.Now().UTC()
	}
	if successor.ReplacesID == nil {
		replacesID := predecessorID
		successor.ReplacesID = &replacesID
	}
	tag, err := tx.Exec(ctx,
		`UPDATE ca_authorities
		    SET status = 'superseded'
		  WHERE tenant_id = $1 AND id = $2`,
		successor.TenantID, predecessorID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	tag, err = tx.Exec(ctx,
		`INSERT INTO ca_authorities
		        (id, tenant_id, parent_id, common_name, kind, status, certificate_pem,
		         signer_handle, serial, not_after, max_path_len, permitted_dns_names, ekus, replaces_id, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (id) DO UPDATE
		    SET parent_id = EXCLUDED.parent_id,
		        common_name = EXCLUDED.common_name,
		        kind = EXCLUDED.kind,
		        status = EXCLUDED.status,
		        certificate_pem = EXCLUDED.certificate_pem,
		        signer_handle = EXCLUDED.signer_handle,
		        serial = EXCLUDED.serial,
		        not_after = EXCLUDED.not_after,
		        max_path_len = EXCLUDED.max_path_len,
		        permitted_dns_names = EXCLUDED.permitted_dns_names,
		        ekus = EXCLUDED.ekus,
		        replaces_id = EXCLUDED.replaces_id,
		        created_at = EXCLUDED.created_at
		  WHERE ca_authorities.tenant_id = EXCLUDED.tenant_id`,
		successor.ID, successor.TenantID, successor.ParentID, successor.CommonName, successor.Kind, status,
		successor.CertificatePEM, successor.SignerHandle, successor.Serial, successor.NotAfter, successor.MaxPathLen,
		dns, ekus, successor.ReplacesID, successor.CreatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
}

// KeyCeremony is an m-of-n CA key-generation ceremony. Approvals is the current
// count of distinct custodian approvals that also have immutable event-log
// evidence. Opener is the authenticated principal who started it (empty when
// unattributed), used to enforce opener != approver separation of duties
// (PKIGOV-006).
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

// ApplyKeyCeremonyStartedTx projects a ca.ceremony.started event into the
// ceremony read model. The event carries the stable ceremony id; created_at comes
// from the event envelope so replay reproduces live state.
func (s *Store) ApplyKeyCeremonyStartedTx(ctx context.Context, tx pgx.Tx, c KeyCeremony) error {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	status := c.Status
	if status == "" {
		status = "pending"
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO ca_key_ceremonies (id, tenant_id, purpose, opener, threshold, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (id) DO NOTHING`,
		c.ID, c.TenantID, c.Purpose, c.Opener, c.Threshold, status, c.CreatedAt)
	return err
}

// KeyCeremonyApprovalEvidenced reports whether custodian already has immutable
// event evidence for this ceremony. It is a read-side idempotency check for the
// command layer; approval rows without evidence do not count toward quorum.
func (s *Store) KeyCeremonyApprovalEvidenced(ctx context.Context, tenantID, ceremonyID, custodian string) (bool, error) {
	var ok bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM ca_ceremony_approvals
				 WHERE tenant_id = $1 AND ceremony_id = $2 AND custodian = $3
				   AND approval_event_id IS NOT NULL
			)`,
			tenantID, ceremonyID, custodian).Scan(&ok)
	})
	return ok, err
}

// ApplyKeyCeremonyApprovedTx projects a ca.ceremony.approved event into the
// evidence-backed approval read model. The event envelope supplies the immutable
// event id and sequence; without those, the approval cannot count toward quorum.
func (s *Store) ApplyKeyCeremonyApprovedTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID, custodian, eventID string, eventSequence uint64, approvedAt time.Time) error {
	if custodian == "" {
		return ErrAnonymousApproval
	}
	if eventID == "" || eventSequence == 0 {
		return errors.New("store: ceremony approval evidence requires event id and sequence")
	}
	if approvedAt.IsZero() {
		approvedAt = time.Now().UTC()
	}
	var opener, status string
	if err := tx.QueryRow(ctx,
		`SELECT opener, status FROM ca_key_ceremonies
		  WHERE tenant_id = $1 AND id = $2
		  FOR UPDATE`,
		tenantID, ceremonyID).Scan(&opener, &status); err != nil {
		return err
	}
	if status != "pending" {
		var existingEventID string
		var existingSequence int64
		err := tx.QueryRow(ctx,
			`SELECT approval_event_id, approval_event_sequence
			   FROM ca_ceremony_approvals
			  WHERE tenant_id = $1 AND ceremony_id = $2 AND custodian = $3
			    AND approval_event_id IS NOT NULL
			    AND approval_event_sequence IS NOT NULL`,
			tenantID, ceremonyID, custodian).Scan(&existingEventID, &existingSequence)
		if err == nil && existingEventID == eventID && existingSequence >= 0 && uint64(existingSequence) == eventSequence {
			return nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return ErrKeyCeremonyNotPending
	}
	if opener != "" && opener == custodian {
		return ErrSelfApproval
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO ca_ceremony_approvals
		        (tenant_id, ceremony_id, custodian, approved_at, approval_event_id, approval_event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, ceremony_id, custodian) DO UPDATE
		    SET approval_event_id = COALESCE(ca_ceremony_approvals.approval_event_id, EXCLUDED.approval_event_id),
		        approval_event_sequence = COALESCE(ca_ceremony_approvals.approval_event_sequence, EXCLUDED.approval_event_sequence)`,
		tenantID, ceremonyID, custodian, approvedAt, eventID, int64(eventSequence))
	return err
}

// ReserveKeyCeremonyApproval reserves a custodian's approval row (idempotent per
// custodian) and returns the current evidence-backed approval count plus whether
// this row still needs event evidence. It enforces PKIGOV-006: the custodian must
// be a named identity (not empty), and the ceremony's opener may not approve their
// own ceremony (opener != approver). PKIGOV-003: a reserved row has no quorum power
// until AttachKeyCeremonyApprovalEvidence records the event id/sequence that is
// present in the immutable audit bundle.
func (s *Store) ReserveKeyCeremonyApproval(ctx context.Context, tenantID, ceremonyID, custodian string) (int, bool, error) {
	if custodian == "" {
		return 0, false, ErrAnonymousApproval
	}
	var count int
	var evidenced bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Separation of duties: a ceremony's opener cannot also approve it.
		var opener, status string
		if err := tx.QueryRow(ctx,
			`SELECT opener, status FROM ca_key_ceremonies WHERE tenant_id = $1 AND id = $2`,
			tenantID, ceremonyID).Scan(&opener, &status); err != nil {
			return err
		}
		if status != "pending" {
			return ErrKeyCeremonyNotPending
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
		if err := tx.QueryRow(ctx,
			`SELECT approval_event_id IS NOT NULL
			   FROM ca_ceremony_approvals
			  WHERE tenant_id = $1 AND ceremony_id = $2 AND custodian = $3`,
			tenantID, ceremonyID, custodian).Scan(&evidenced); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM ca_ceremony_approvals
			  WHERE tenant_id = $1 AND ceremony_id = $2 AND approval_event_id IS NOT NULL`,
			tenantID, ceremonyID).Scan(&count)
	})
	return count, !evidenced, err
}

// AttachKeyCeremonyApprovalEvidence gives a reserved approval row quorum power by
// binding it to the event id and stream sequence returned by events.Append. If the
// event append never happened, callers cannot call this method with real evidence,
// and the row remains ignored by quorum checks.
func (s *Store) AttachKeyCeremonyApprovalEvidence(ctx context.Context, tenantID, ceremonyID, custodian, eventID string, eventSequence uint64) (int, error) {
	if eventID == "" || eventSequence == 0 {
		return 0, errors.New("store: ceremony approval evidence requires event id and sequence")
	}
	var count int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var attachedID string
		if err := tx.QueryRow(ctx,
			`UPDATE ca_ceremony_approvals
			    SET approval_event_id = COALESCE(approval_event_id, $4),
			        approval_event_sequence = COALESCE(approval_event_sequence, $5)
			  WHERE tenant_id = $1 AND ceremony_id = $2 AND custodian = $3
			  RETURNING approval_event_id`,
			tenantID, ceremonyID, custodian, eventID, int64(eventSequence)).Scan(&attachedID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrKeyCeremonyQuorumNotMet
			}
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM ca_ceremony_approvals
			  WHERE tenant_id = $1 AND ceremony_id = $2 AND approval_event_id IS NOT NULL`,
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
			          WHERE a.tenant_id = c.tenant_id AND a.ceremony_id = c.id
			            AND a.approval_event_id IS NOT NULL)
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
		          WHERE a.tenant_id = c.tenant_id AND a.ceremony_id = c.id
		            AND a.approval_event_id IS NOT NULL)
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
