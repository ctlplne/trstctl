package store

import (
	"context"
	"strings"

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
		 ON CONFLICT (id) DO UPDATE
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
		 ON CONFLICT (id) DO UPDATE
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
		 ON CONFLICT (id) DO UPDATE
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
// events collapse to one row deterministically.
func (s *Store) ApplyCertificateRecordedTx(ctx context.Context, tx pgx.Tx, c Certificate) error {
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO certificates
		        (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
		         key_algorithm, not_before, not_after, deployment_location, source, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 ON CONFLICT (tenant_id, fingerprint) DO UPDATE
		    SET owner_id = EXCLUDED.owner_id, subject = EXCLUDED.subject, sans = EXCLUDED.sans,
		        issuer = EXCLUDED.issuer, serial = EXCLUDED.serial, key_algorithm = EXCLUDED.key_algorithm,
		        not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after,
		        deployment_location = EXCLUDED.deployment_location, source = EXCLUDED.source`,
		c.ID, c.TenantID, c.OwnerID, c.Subject, sans, c.Issuer, c.Serial, c.Fingerprint,
		c.KeyAlgorithm, c.NotBefore, c.NotAfter, c.DeploymentLocation, c.Source, c.CreatedAt)
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
			        fingerprint, key_algorithm, not_before, not_after, deployment_location, source, created_at,
			        status, replaces_id::text, revoked_at, revocation_reason, renewed_at, alerted_at
			   FROM certificates WHERE tenant_id = $1 AND fingerprint = $2`, tenantID, fingerprint), &c)
	})
	return c, err
}

// ReadModelTables are the PostgreSQL tables that are pure projections of the
// event log (AN-2): they are truncated and re-derived from the log on Rebuild, so
// they never need a separate backup. Any new table that is an event-sourced
// read model joins this list (and is therefore covered by the log backup); a
// table that holds independent state instead joins the PostgreSQL backup set. The
// backup-set manifest test (internal/backup) enforces that every persistent table
// is classified one way or the other, so a new store cannot silently fall out of
// the disaster-recovery plan (SF.4).
var ReadModelTables = []string{"owners", "issuers", "identities", "certificates", "tenants"}

// TruncateReadModel empties the event-sourced read model so it can be rebuilt
// from the log (AN-2). It is a system operation. It covers exactly
// ReadModelTables — the tables this platform projects from events today; other
// read models (discovery inventory, CA state) are rebuilt by their own subsystems
// and join this set as they become event-sourced.
func (s *Store) TruncateReadModel(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`TRUNCATE `+strings.Join(ReadModelTables, ", ")+` CASCADE`)
	return err
}
