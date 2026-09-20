// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds the certificate-lifecycle repository methods (F6, S4.5): the
// alert bookkeeping plus the scans that drive renewal and expiry alerting. The
// mutating methods take the caller's transaction so the state change and its
// outbox entry (AN-6) commit atomically. All queries are tenant-scoped (AN-1).
//
// Certificate status transitions (successor recorded, predecessor superseded,
// revoked) are NOT written here as direct read-table UPDATEs — that was the
// CORRECT-002 defect, where the emitted events had no projector case and the
// status was lost on a Rebuild(). Those transitions are now event-sourced through
// the orchestrator (RecordSuccessorCertificate / SupersedeCertificate /
// RevokeCertificate) and applied by the projector — the sole read-model writer
// (AN-2) — so they are reconstructable from the log. The alert stamp below is a
// projection-side annotation (not a lifecycle status), so it remains a direct
// write here.

// MarkCertificateAlertedTx stamps alerted_at, on the caller's tx, so an expiry
// alert is emitted to the notification surface at most once per certificate.
func (s *Store) MarkCertificateAlertedTx(ctx context.Context, tx pgx.Tx, tenantID, id string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE certificates SET alerted_at = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, at)
	return err
}

// ListExpiringActiveCertificates returns active certificates whose not_after is
// before the cutoff, oldest expiry first — the renewal scan's input.
func (s *Store) ListExpiringActiveCertificates(ctx context.Context, tenantID string, before time.Time) ([]Certificate, error) {
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+certificateColumns+`
			   FROM certificates
			  WHERE tenant_id = $1 AND status = 'active'
			    AND not_after IS NOT NULL AND not_after < $2
			  ORDER BY not_after`,
			tenantID, before)
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

// ListAlertableCertificates returns active certificates expiring within the
// window (now, before) that have not yet been alerted — the expiry-alert scan's
// input. Already-expired certs (not_after < now) are excluded: alerts fire
// before expiry.
func (s *Store) ListAlertableCertificates(ctx context.Context, tenantID string, now, before time.Time) ([]Certificate, error) {
	var out []Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+certificateColumns+`
			   FROM certificates
			  WHERE tenant_id = $1 AND status = 'active' AND alerted_at IS NULL
			    AND not_after IS NOT NULL AND not_after >= $2 AND not_after < $3
			  ORDER BY not_after`,
			tenantID, now, before)
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

// TenantsWithAlertableCertificates returns tenant ids that currently have at least
// one active certificate inside the alert window. It is a system enumerator only:
// each tenant's actual certificate rows are then loaded by ListAlertableCertificates
// under that tenant's RLS context.
func (s *Store) TenantsWithAlertableCertificates(ctx context.Context, now, before time.Time) ([]string, error) {
	rows, err := s.SystemPool().Query(ctx,
		//trstctl:system-query — cross-tenant by design: the leader scheduler enumerates which tenants have expiry-alert work, then re-enters tenant-scoped RLS for the rows themselves.
		`SELECT DISTINCT tenant_id::text
		   FROM certificates
		  WHERE status = 'active'
		    AND alerted_at IS NULL
		    AND not_after IS NOT NULL
		    AND not_after >= $1
		    AND not_after < $2
		  ORDER BY 1`, now, before)
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

// CertificateAlertContext returns the responsible owner plus active approver
// principals for an expiry alert. It is read-only and tenant-scoped: the scheduler
// uses it to enrich notification payloads, while the alert enqueue and alerted_at
// stamp still happen atomically in AlertExpiring.
type CertificateAlertContext struct {
	Owner     *Owner
	Approvers []TenantMember
}

// CertificateOwnerIDViaClaim resolves the owner to alert for a certificate that
// carries no owner of its own: a certificate discovery observed and an operator
// then claimed into a managed identity is owned by that identity's current owner
// (DP2-020). Empty when no claim links it.
func (s *Store) CertificateOwnerIDViaClaim(ctx context.Context, tenantID, fingerprint string) (string, error) {
	if fingerprint == "" {
		return "", nil
	}
	var ownerID string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT i.owner_id::text
			   FROM discovery_findings AS f
			   JOIN identities AS i ON i.tenant_id = f.tenant_id AND i.id = f.managed_identity_id
			  WHERE f.tenant_id = $1 AND f.fingerprint = $2 AND f.managed_identity_id IS NOT NULL
			  ORDER BY f.discovered_at DESC
			  LIMIT 1`, tenantID, fingerprint).Scan(&ownerID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: certificate owner via claim: %w", err)
	}
	return ownerID, nil
}

// CertificateAlertContextForOwner loads alert-routing context for a certificate
// owner. Missing owners do not suppress alerting: an orphaned certificate still
// produces an expiry alert, just without owner contact fields.
func (s *Store) CertificateAlertContextForOwner(ctx context.Context, tenantID, ownerID string) (CertificateAlertContext, error) {
	out := CertificateAlertContext{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if ownerID != "" {
			var (
				owner Owner
				kind  string
			)
			err := tx.QueryRow(ctx,
				`SELECT id::text, tenant_id::text, kind, name, email, created_at
				   FROM owners WHERE tenant_id = $1 AND id = $2`,
				tenantID, ownerID).Scan(&owner.ID, &owner.TenantID, &kind, &owner.Name, &owner.Email, &owner.CreatedAt)
			if err != nil && err != pgx.ErrNoRows {
				return err
			}
			if err == nil {
				owner.Kind = OwnerKind(kind)
				out.Owner = &owner
			}
		}

		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, subject, display_name, email, roles, source, status,
			        created_at, updated_at, offboarded_at, offboarded_by, offboard_reason
			   FROM tenant_members
			  WHERE tenant_id = $1
			    AND status <> 'offboarded'
			    AND roles && $2::text[]
			  ORDER BY subject LIMIT 10000`,
			tenantID, []string{"admin", "operator", "approver", "cert-approver", "cert_approver", "certificate-approver", "certificate_approver"})
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m TenantMember
			if err := rows.Scan(&m.TenantID, &m.Subject, &m.DisplayName, &m.Email, &m.Roles, &m.Source, &m.Status, &m.CreatedAt, &m.UpdatedAt, &m.OffboardedAt, &m.OffboardedBy, &m.OffboardReason); err != nil {
				return err
			}
			out.Approvers = append(out.Approvers, m)
		}
		return rows.Err()
	})
	return out, err
}
