package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file holds the read-model projection sinks (AN-2). They are the ONLY
// writers of the served domain read model, and they run on the caller's
// tenant-scoped transaction so a projection can share a transaction with the
// orchestrator's outbox enqueue (AN-6). Each sink sets created_at from the
// event's time, so replaying the log reproduces the read model byte-for-byte
// (deterministic), rather than stamping a fresh now() on every rebuild.

// ApplyOwnerCreatedTx projects an owner.created event: it inserts the owner with
// the id and created_at carried by the event. Replaying the event is idempotent.
func (s *Store) ApplyOwnerCreatedTx(ctx context.Context, tx pgx.Tx, o Owner) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO owners (id, tenant_id, kind, name, email, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET kind = EXCLUDED.kind, name = EXCLUDED.name, email = EXCLUDED.email`,
		o.ID, o.TenantID, string(o.Kind), o.Name, o.Email, o.CreatedAt)
	return err
}

// ApplyOwnerUpdatedTx projects an owner.updated event. A projection is tolerant:
// applying an update to an owner the log has not yet created is a no-op (the
// preceding owner.created always replays first).
func (s *Store) ApplyOwnerUpdatedTx(ctx context.Context, tx pgx.Tx, o Owner) error {
	_, err := tx.Exec(ctx,
		`UPDATE owners SET kind = $3, name = $4, email = $5 WHERE tenant_id = $1 AND id = $2`,
		o.TenantID, o.ID, string(o.Kind), o.Name, o.Email)
	return err
}

// DeleteOwnerTx projects an owner.deleted event.
func (s *Store) DeleteOwnerTx(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	_, err := tx.Exec(ctx, `DELETE FROM owners WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	return err
}

// ApplyIssuerCreatedTx projects an issuer.created event.
func (s *Store) ApplyIssuerCreatedTx(ctx context.Context, tx pgx.Tx, i Issuer) error {
	chain := i.Chain
	if chain == nil {
		chain = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO issuers (id, tenant_id, kind, name, chain, public_key, internal, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET kind = EXCLUDED.kind, name = EXCLUDED.name, chain = EXCLUDED.chain,
		        public_key = EXCLUDED.public_key, internal = EXCLUDED.internal`,
		i.ID, i.TenantID, string(i.Kind), i.Name, chain, i.PublicKey, i.Internal, i.CreatedAt)
	return err
}

// ApplyIdentityCreatedTx projects an identity.created event in its initial
// lifecycle status; later identity.* transitions update the status via
// SetIdentityStatusTx.
func (s *Store) ApplyIdentityCreatedTx(ctx context.Context, tx pgx.Tx, it Identity) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO identities
		        (id, tenant_id, kind, name, owner_id, issuer_id, status, not_before, not_after, attributes, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET kind = EXCLUDED.kind, name = EXCLUDED.name, owner_id = EXCLUDED.owner_id,
		        issuer_id = EXCLUDED.issuer_id, not_before = EXCLUDED.not_before,
		        not_after = EXCLUDED.not_after, attributes = EXCLUDED.attributes`,
		it.ID, it.TenantID, string(it.Kind), it.Name, it.OwnerID, it.IssuerID,
		it.Status, it.NotBefore, it.NotAfter, jsonbOrEmpty(it.Attributes), it.CreatedAt)
	return err
}

// ApplyCertificateRecordedTx projects a certificate.recorded event. The
// inventory is keyed by (tenant, fingerprint): re-recording the same certificate
// refreshes the existing row (keeping its original id and created_at), so two
// events collapse to one row deterministically. When the event carries
// replaces_id, the same transaction also supersedes that predecessor; successor
// creation and predecessor retirement are one replay step, so a crash or replay
// before a later lifecycle/audit event cannot leave two active certificates.
func (s *Store) ApplyCertificateRecordedTx(ctx context.Context, tx pgx.Tx, c Certificate) error {
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	certDER := c.CertificateDER
	if certDER == nil {
		certDER = []byte{}
	}
	if c.ReplacesID != nil && *c.ReplacesID == c.ID {
		return fmt.Errorf("certificate successor %s cannot replace itself", c.ID)
	}
	// replaces_id is carried when this certificate is the successor of a
	// renewal/rotation (CORRECT-002); nil on a first issuance. Projecting it here
	// keeps the predecessor link reconstructable from the log on a Rebuild().
	_, err := tx.Exec(ctx,
		`INSERT INTO certificates
		        (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
		         key_algorithm, not_before, not_after, deployment_location, source, certificate_der, issuance_idempotency_key,
		         replaces_id, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
		    SET owner_id = EXCLUDED.owner_id, subject = EXCLUDED.subject, sans = EXCLUDED.sans,
		        issuer = EXCLUDED.issuer, serial = EXCLUDED.serial, key_algorithm = EXCLUDED.key_algorithm,
		        not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
		        deployment_location = EXCLUDED.deployment_location, source = EXCLUDED.source,
		        certificate_der = EXCLUDED.certificate_der,
		        issuance_idempotency_key = EXCLUDED.issuance_idempotency_key,
		        replaces_id = EXCLUDED.replaces_id`,
		c.ID, c.TenantID, c.OwnerID, c.Subject, sans, c.Issuer, c.Serial, c.Fingerprint,
		c.KeyAlgorithm, c.NotBefore, c.NotAfter, c.DeploymentLocation, c.Source, certDER, c.IssuanceIdempotencyKey,
		c.ReplacesID, c.CreatedAt)
	if err != nil {
		return err
	}
	if c.ReplacesID == nil || *c.ReplacesID == "" {
		return nil
	}
	tag, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET status = 'superseded', renewed_at = $3
		  WHERE tenant_id = $1 AND id = $2 AND status <> 'revoked'`,
		c.TenantID, *c.ReplacesID, c.CreatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	var status string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM certificates WHERE tenant_id = $1 AND id = $2`,
		c.TenantID, *c.ReplacesID).Scan(&status); err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("certificate successor %s replaces missing predecessor %s", c.ID, *c.ReplacesID)
		}
		return err
	}
	if status == "revoked" {
		return nil
	}
	return fmt.Errorf("certificate successor %s did not supersede predecessor %s in status %q", c.ID, *c.ReplacesID, status)
}

// SetCertificateRevokedTx projects a certificate.revoked event: it marks the
// inventoried certificate revoked (status, reason, timestamp) on the caller's
// transaction, the same way an identity transition status change is projected.
// Because the status change is driven by the projector (the sole read-model
// writer, AN-2) rather than a direct UPDATE, it is reconstructed from the log on
// a Rebuild() instead of being lost. Keyed by fingerprint so a replay is
// deterministic and idempotent.
func (s *Store) SetCertificateRevokedTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint, reason string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET status = 'revoked', revoked_at = $3, revocation_reason = $4
		  WHERE tenant_id = $1 AND fingerprint = $2`,
		tenantID, fingerprint, at, reason)
	return err
}

// SetCertificateSupersededTx projects a certificate.superseded event: it retires
// the inventoried certificate (status superseded, renewed_at stamped) on the
// caller's transaction (CORRECT-002). Like SetCertificateRevokedTx, the status
// change runs through the projector — the sole read-model writer (AN-2) — so it is
// reconstructed from the log on a Rebuild() instead of being a lost direct write.
// A revoked certificate is NOT downgraded to superseded: revocation is terminal,
// so the guard keeps a revoke that raced a renewal authoritative. Keyed by
// fingerprint so a replay is deterministic and idempotent.
func (s *Store) SetCertificateSupersededTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET status = 'superseded', renewed_at = $3
		  WHERE tenant_id = $1 AND fingerprint = $2 AND status <> 'revoked'`,
		tenantID, fingerprint, at)
	return err
}

// GetCertificateByFingerprint loads the inventoried certificate with the given
// fingerprint in its tenant context. The served ingest command uses it to return
// the canonical row after recording (the row's id is stable across re-ingest).
func (s *Store) GetCertificateByFingerprint(ctx context.Context, tenantID, fingerprint string) (Certificate, error) {
	var c Certificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanCertificate(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, owner_id::text, subject, sans, issuer, serial,
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source,
			        certificate_der, issuance_idempotency_key, created_at,
			        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at
			   FROM certificates WHERE tenant_id = $1 AND fingerprint = $2`, tenantID, fingerprint), &c)
	})
	return c, err
}

// IdentityTransition is one applied lifecycle change, as projected into the
// identity_transitions read model. Seq is the appending event's stream sequence
// (monotonic within a tenant), giving the deterministic order a replay
// reproduces.
type IdentityTransition struct {
	IdentityID string
	Seq        uint64
	FromState  string
	ToState    string
	EventType  string
	Reason     string
	OccurredAt time.Time
}

// AppendIdentityTransitionTx projects a lifecycle transition event into the
// identity_transitions read model on the caller's transaction (SPINE-001), so an
// identity's History/State is a single tenant-scoped, indexed read rather than a
// full cross-tenant log replay. Keyed by (tenant_id, identity_id, seq), so
// replaying the same event is idempotent and a Rebuild reproduces the row exactly
// (occurred_at comes from the event's own time, not now()). It is tenant-scoped
// (AN-1); the projector is the sole writer (AN-2).
func (s *Store) AppendIdentityTransitionTx(ctx context.Context, tx pgx.Tx, tenantID string, t IdentityTransition) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO identity_transitions
		        (tenant_id, identity_id, seq, from_state, to_state, event_type, reason, occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, identity_id, seq) DO UPDATE
		    SET from_state = EXCLUDED.from_state, to_state = EXCLUDED.to_state,
		        event_type = EXCLUDED.event_type, reason = EXCLUDED.reason,
		        occurred_at = EXCLUDED.occurred_at`,
		tenantID, t.IdentityID, int64(t.Seq), t.FromState, t.ToState, t.EventType, t.Reason, t.OccurredAt)
	return err
}

// ApplyProfileVersionTx projects a profile.created/profile.updated v2 event into
// certificate_profiles. A new active profile version deactivates all earlier active
// versions for the same tenant/name in the same transaction, then upserts the carried
// version row. Replaying the log in order reproduces the active version exactly.
func (s *Store) ApplyProfileVersionTx(ctx context.Context, tx pgx.Tx, r ProfileRecord) error {
	if r.Active {
		if _, err := tx.Exec(ctx,
			`UPDATE certificate_profiles
			    SET active = false
			  WHERE tenant_id = $1 AND name = $2 AND active AND version <> $3`,
			r.TenantID, r.Name, r.Version); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO certificate_profiles
		        (id, tenant_id, name, version, spec, active, created_by, created_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
		 ON CONFLICT (tenant_id, name, version) DO UPDATE
		    SET id = EXCLUDED.id,
		        spec = EXCLUDED.spec,
		        active = EXCLUDED.active,
		        created_by = EXCLUDED.created_by,
		        created_at = EXCLUDED.created_at`,
		r.ID, r.TenantID, r.Name, r.Version, jsonbOrEmpty(r.Spec), r.Active, r.CreatedBy, r.CreatedAt)
	return err
}

// ListIdentityTransitions returns an identity's lifecycle transitions in order,
// read from the identity_transitions projection in its tenant context
// (RLS-enforced, AN-1). The work is bounded by this identity's transition count
// and never scans another tenant's rows (SPINE-001). The caller supplies the
// WithTenant transaction so the read shares the tenant scope.
func (s *Store) ListIdentityTransitions(ctx context.Context, tx pgx.Tx, tenantID, identityID string) ([]IdentityTransition, error) {
	rows, err := tx.Query(ctx,
		`SELECT seq, from_state, to_state, event_type, reason, occurred_at
		   FROM identity_transitions
		  WHERE tenant_id = $1 AND identity_id = $2
		  ORDER BY seq`,
		tenantID, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IdentityTransition
	for rows.Next() {
		t := IdentityTransition{IdentityID: identityID}
		var seq int64
		if err := rows.Scan(&seq, &t.FromState, &t.ToState, &t.EventType, &t.Reason, &t.OccurredAt); err != nil {
			return nil, err
		}
		t.Seq = uint64(seq)
		out = append(out, t)
	}
	return out, rows.Err()
}

// ReadModelTables are the PostgreSQL tables that are pure projections of the
// event log (AN-2): they are truncated and re-derived from the log on Rebuild, so
// they never need a separate backup. Any new table that is an event-sourced
// read model joins this list (and is therefore covered by the log backup); a
// table that holds independent state instead joins the PostgreSQL backup set. The
// backup-set manifest test (internal/backup) enforces that every persistent table
// is classified one way or the other, so a new store cannot silently fall out of
// the disaster-recovery plan (SF.4).
var ReadModelTables = []string{"owners", "issuers", "identities", "certificates", "crypto_assets", "agents", "tenants", "identity_transitions", "certificate_profiles", "tenant_members", "ca_issued_certs", "ca_crls", "ca_ocsp_responders", "discovery_sources", "discovery_schedules", "discovery_runs", "discovery_findings", "connector_delivery_receipts", "lifecycle_rotation_runs", "incident_executions", "pam_sessions", "privacy_subject_erasures", "privacy_retention_runs"}

// TruncateReadModel empties the event-sourced read model so it can be rebuilt
// from the log (AN-2). It is a system operation. It covers exactly
// ReadModelTables — the tables this platform projects from events today; other
// read models with independent rebuild paths are kept out of this list until they
// become event-sourced.
func (s *Store) TruncateReadModel(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`TRUNCATE `+strings.Join(ReadModelTables, ", ")+` CASCADE`)
	return err
}

// RebuildReadModelTx runs an atomic read-model rebuild (RESIL-003): in ONE
// transaction it truncates ReadModelTables, then calls apply to re-derive every row
// from the event log. Either the whole rebuild commits or it rolls back — a crash
// or error mid-replay leaves the prior read model fully intact rather than a
// truncated/partial inventory the API might answer queries from.
//
// It runs as the connecting (owner) role, which bypasses row-level security, because
// (a) TRUNCATE needs owner privilege and (b) a rebuild re-derives EVERY tenant's
// rows in one pass — a deliberate cross-tenant system operation, like the projection
// workers and the backup/restore path. AN-1 is preserved because every projection
// write carries its tenant_id explicitly in the SQL (the read-model sinks filter/
// insert on tenant_id), so RLS bypass here does not let a row land under the wrong
// tenant. The session's trstctl.tenant_id GUC is set per event by the caller via
// SetTenantGUCTx so any tenant-scoped logic still sees the right tenant.
func (s *Store) RebuildReadModelTx(ctx context.Context, apply func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `TRUNCATE `+strings.Join(ReadModelTables, ", ")+` CASCADE`); err != nil {
		return err
	}
	if err := apply(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RestoreReadModelTx runs apply inside ONE owner-role transaction, for the atomic
// snapshot-restore boot path (SPINE-007): apply both rehydrates the read model from
// the latest snapshots (RestoreSnapshotsTx, which TRUNCATEs and reloads) AND replays
// the tail after the covered offset, so the whole restore-then-catch-up commits or
// rolls back as a unit. A crash mid-restore leaves the prior read model intact rather
// than a half-loaded inventory the API might answer from. It runs as the connecting
// (owner) role like RebuildReadModelTx — it must TRUNCATE and write every tenant —
// and apply carries tenant_id explicitly on every write, so AN-1 holds with RLS
// bypassed for this trusted system operation.
func (s *Store) RestoreReadModelTx(ctx context.Context, apply func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := apply(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetTenantGUCTx sets the trstctl.tenant_id session variable on tx (LOCAL to the
// transaction) so tenant-scoped projection logic sees the right tenant during an
// atomic rebuild (RESIL-003). Unlike WithTenant it does NOT switch to the RLS role:
// the atomic rebuild runs as the owner (it must TRUNCATE and write every tenant), so
// only the GUC is set.
func (s *Store) SetTenantGUCTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", tenantID)
	return err
}

// UpsertTenantTx inserts or updates a tenant row on the caller's transaction, for
// the atomic rebuild path (RESIL-003) where the tenant projection must share the
// rebuild's single transaction. It is a system (cross-tenant) write, like
// UpsertTenant.
func (s *Store) UpsertTenantTx(ctx context.Context, tx pgx.Tx, t Tenant) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO tenants (tenant_id, name, event_seq) VALUES ($1, $2, $3)
		 ON CONFLICT (tenant_id) DO UPDATE SET name = EXCLUDED.name, event_seq = EXCLUDED.event_seq`,
		t.TenantID, t.Name, int64(t.EventSeq))
	return err
}

// DeleteTenantReadModelTx deletes one tenant's rows from the event-sourced read
// model (ReadModelTables) on the caller's transaction, for the atomic-rebuild replay
// of a tenant.offboarded event (RESIL-003): within a rebuild, a deleted tenant must
// not be resurrected, and the rebuild owns exactly these tables. Each DELETE carries
// tenant_id explicitly (AN-1). It does NOT touch independent tenant tables (those are
// not rebuilt from the log); the live OffboardTenant path handles the full erase.
// Deletes children before the tenants row so a foreign key never blocks the erase.
func (s *Store) DeleteTenantReadModelTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("store: DeleteTenantReadModelTx requires a tenant id (AN-1)")
	}
	// Order: dependents first. identity_transitions and certificates reference
	// identities/owners; the tenants row is removed last.
	ordered := []string{"identity_transitions", "connector_delivery_receipts", "lifecycle_rotation_runs", "pam_sessions", "ca_crls", "ca_ocsp_responders", "ca_issued_certs", "certificates", "crypto_assets", "identities", "certificate_profiles", "discovery_findings", "discovery_runs", "discovery_schedules", "discovery_sources", "privacy_retention_runs", "privacy_subject_erasures", "issuers", "owners", "tenants"}
	for _, table := range ordered {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE tenant_id = $1", tenantID); err != nil {
			return fmt.Errorf("store: delete read-model %s for tenant: %w", table, err)
		}
	}
	return nil
}
