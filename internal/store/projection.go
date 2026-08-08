// SPDX-License-Identifier: MPL-2.0

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

// ApplyAgentUpgradeCampaignOpenedTx projects agent.upgrade.campaign.opened (A5).
func (s *Store) ApplyAgentUpgradeCampaignOpenedTx(ctx context.Context, tx pgx.Tx, tenantID, id, version, createdBy string, artifacts []byte, at time.Time) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO agent_upgrade_campaigns (id, tenant_id, target_version, created_by, artifacts, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
		id, tenantID, version, createdBy, artifacts, at)
	return err
}

// ApplyAgentUpgradeCampaignAdvancedTx projects a campaign state change (A5).
//
// halted_at_ring is only ever SET, never cleared by an advance: it is the
// record of which ring stopped the rollout, and Resume restarts there. Clearing
// it on resume would lose the one fact needed to restart correctly.
//
// dispatched_ring IS cleared whenever the campaign enters running. Entering
// running is what "the current ring should have jobs" means, and clearing the
// stamp is what makes the sweep dispatch them — including a re-dispatch of the
// same ring after a resume, which is required: the agent whose failure halted
// the round needs a fresh job after the fix, and the old round's receipts must
// stop counting.
func (s *Store) ApplyAgentUpgradeCampaignAdvancedTx(ctx context.Context, tx pgx.Tx, tenantID, id, status, currentRing, haltedAtRing, reason string) error {
	_, err := tx.Exec(ctx,
		`UPDATE agent_upgrade_campaigns
		    SET status = $3, current_ring = $4,
		        halted_at_ring = CASE WHEN $5 <> '' THEN $5 ELSE halted_at_ring END,
		        dispatched_ring = CASE WHEN $3 = 'running' THEN NULL ELSE dispatched_ring END,
		        reason = $6, updated_at = now()
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, status, currentRing, haltedAtRing, reason)
	return err
}

// UpgradeDispatchJob names one dispatched agent and its outbox job key (A5).
type UpgradeDispatchJob struct {
	AgentID string
	JobKey  string
}

// ApplyAgentUpgradeRingDispatchedTx projects agent.upgrade.ring.dispatched (A5).
//
// Replay-safe twice over: dispatch rows land ON CONFLICT DO NOTHING (the PK is
// the event's own identity), and the campaign's round only moves FORWARD — a
// replayed round cannot drag dispatch_round backwards past a later one.
func (s *Store) ApplyAgentUpgradeRingDispatchedTx(ctx context.Context, tx pgx.Tx, tenantID, campaignID, ring string, round int, jobs []UpgradeDispatchJob, at time.Time) error {
	for _, j := range jobs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO agent_upgrade_dispatches (tenant_id, campaign_id, round, ring, agent_id, job_key, dispatched_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (tenant_id, campaign_id, round, agent_id) DO NOTHING`,
			tenantID, campaignID, round, ring, j.AgentID, j.JobKey, at); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx,
		`UPDATE agent_upgrade_campaigns
		    SET dispatch_round = $3, dispatched_ring = $4, status = 'running',
		        current_ring = $4, updated_at = now()
		  WHERE tenant_id = $1 AND id = $2 AND coalesce(dispatch_round, 0) < $3`,
		tenantID, campaignID, round, ring)
	return err
}

// ApplyAgentUpgradeRingAssignedTx places an agent in a rollout ring (A5).
func (s *Store) ApplyAgentUpgradeRingAssignedTx(ctx context.Context, tx pgx.Tx, tenantID, agentID, ring string) error {
	_, err := tx.Exec(ctx,
		`UPDATE agents SET upgrade_ring = nullif($3, '') WHERE tenant_id = $1 AND id = $2`, tenantID, agentID, ring)
	return err
}

// ApplyIssuanceRequestOpenedTx projects an issuance.request.opened event (I3).
func (s *Store) ApplyIssuanceRequestOpenedTx(ctx context.Context, tx pgx.Tx, r IssuanceRequest) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO issuance_requests
		   (id, tenant_id, subject, profile, csr_pem, requester, justification, origin,
		    ticket_ref, status, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'requested', $10, $11)
		 ON CONFLICT (id) DO NOTHING`,
		r.ID, r.TenantID, r.Subject, r.Profile, r.CSRPEM, r.Requester, r.Justification,
		r.Origin, r.TicketRef, r.ExpiresAt, r.CreatedAt)
	return err
}

// ApplyIssuanceRequestDecidedTx projects an issuance.request.decided event (I3).
//
// The WHERE clause pins the expected prior status, so a replay or a concurrent
// second decision cannot overwrite a decision that already landed. A denial
// silently becoming an approval because two reviewers clicked at once is the
// failure this guards.
func (s *Store) ApplyIssuanceRequestDecidedTx(ctx context.Context, tx pgx.Tx, tenantID, id, status, decidedBy, reason, identityID string, at time.Time) error {
	var identity any
	if identityID != "" {
		identity = identityID
	}
	_, err := tx.Exec(ctx,
		`UPDATE issuance_requests
		    SET status = $3, decided_by = $4, decision_reason = $5,
		        identity_id = coalesce($6::uuid, identity_id),
		        decided_at = $7, updated_at = now()
		  WHERE tenant_id = $1 AND id = $2
		    AND status IN ('requested', 'approved')`,
		tenantID, id, status, decidedBy, reason, identity, at)
	return err
}

// ApplyOwnershipConflictResolvedTx closes an ownership disagreement (I2).
//
// The WHERE pins resolved_at IS NULL, so a second operator resolving the same
// row cannot overwrite the first one's judgement. Two people closing a conflict
// with different reasons and the later one silently winning is exactly what the
// queue exists to prevent.
func (s *Store) ApplyOwnershipConflictResolvedTx(ctx context.Context, tx pgx.Tx, tenantID, id, by, resolution string, at time.Time) error {
	_, err := tx.Exec(ctx,
		`UPDATE owner_ownership_conflicts
		    SET resolved_at = $4, resolution = $5
		  WHERE tenant_id = $1 AND id = $2 AND resolved_at IS NULL
		    AND $3 <> ''`,
		tenantID, id, by, at, resolution)
	return err
}

// ApplyOwnershipReconciledTx projects an ownership.reconciled event (I2).
//
// It writes BOTH halves in one transaction: the fields the reconcile was
// allowed to set, stamped with where they came from, and the disagreements it
// refused. Splitting them would let a crash leave an estate whose ownership had
// changed with no record of what was overruled to change it.
//
// Conflicts are appended, never replaced. A disagreement that was recorded last
// week and still stands is the same problem, and clearing the queue on each
// sync would make a persistent conflict look freshly discovered every time.
func (s *Store) ApplyOwnershipReconciledTx(ctx context.Context, tx pgx.Tx, tenantID, ownerID string,
	fields map[string]string, source, sourceRef string, observed time.Time, conflicts []OwnershipConflict) error {
	if len(fields) > 0 {
		// Only the four application-model columns are reachable from a
		// reconcile. An external source may describe what an asset is FOR; it
		// may not rename an owner or change who to email, because those are
		// this system's own identity for the owner.
		if _, err := tx.Exec(ctx,
			`UPDATE owners
			    SET application_id = coalesce($3, application_id),
			        service        = coalesce($4, service),
			        business_unit  = coalesce($5, business_unit),
			        environment    = coalesce($6, environment),
			        ownership_source = $7, ownership_source_ref = $8,
			        ownership_source_observed_at = $9
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, ownerID,
			nullableText(fields["application_id"]), nullableText(fields["service"]),
			nullableText(fields["business_unit"]), nullableText(fields["environment"]),
			nullableText(source), nullableText(sourceRef), observed); err != nil {
			return err
		}
	}
	for _, c := range conflicts {
		if _, err := tx.Exec(ctx,
			`INSERT INTO owner_ownership_conflicts
			   (tenant_id, owner_id, field, current_value, current_source,
			    incoming_value, incoming_source, incoming_ref, current_attested)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			tenantID, c.OwnerID, c.Field, c.CurrentValue, c.CurrentSource,
			c.IncomingValue, c.IncomingSource, c.IncomingRef, c.CurrentAttested); err != nil {
			return err
		}
	}
	return nil
}

// ApplyCMDBScheduleConfiguredTx projects a cmdb.schedule.configured event (I2).
//
// last_run_at and last_error are deliberately NOT touched: they are the
// scheduler's observations, not the operator's instruction, and a replay that
// reset them would make a sync that has been failing for a week look like one
// that had simply never run.
func (s *Store) ApplyCMDBScheduleConfiguredTx(ctx context.Context, tx pgx.Tx, tenantID string, in CMDBReconcileSchedule) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO cmdb_reconcile_schedules (tenant_id, instance_url, token_ref, ci_query, allow_private_endpoint, interval_seconds, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (tenant_id) DO UPDATE SET
		   instance_url = EXCLUDED.instance_url, token_ref = EXCLUDED.token_ref,
		   ci_query = EXCLUDED.ci_query, allow_private_endpoint = EXCLUDED.allow_private_endpoint,
		   interval_seconds = EXCLUDED.interval_seconds,
		   enabled = EXCLUDED.enabled, updated_at = now()`,
		tenantID, in.InstanceURL, in.TokenRef, in.CIQuery, in.AllowPrivateEndpoint,
		in.IntervalSeconds, in.Enabled)
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
	certPEM := c.CertificatePEM
	if certPEM == nil {
		certPEM = []byte{}
	}
	issuanceResponse := c.IssuanceResponse
	if issuanceResponse == nil {
		issuanceResponse = []byte{}
	}
	if c.ReplacesID != nil && *c.ReplacesID == c.ID {
		return fmt.Errorf("certificate successor %s cannot replace itself", c.ID)
	}
	// replaces_id is carried when this certificate is the successor of a
	// renewal/rotation (CORRECT-002); nil on a first issuance. Projecting it here
	// keeps the predecessor link reconstructable from the log on a Rebuild().
	// There are two legitimate uniqueness paths: an exact redelivery conflicts on
	// id, while re-recording the same certificate with a fresh event id conflicts on
	// (tenant_id, fingerprint). A targeted ON CONFLICT clause can lose the inline
	// projector versus durable-tailer race when PostgreSQL observes the other unique
	// index first. Ignore either insert conflict, then converge through the tenant +
	// fingerprint key below. A true id reuse with a different fingerprint is detected
	// explicitly instead of being swallowed.
	_, err := tx.Exec(ctx,
		`INSERT INTO certificates
		        (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint,
		         key_algorithm, not_before, not_after, deployment_location, source, certificate_der, certificate_pem, issuance_response,
		         issuance_idempotency_key, issuance_request_binding, replaces_id, created_at,
		         -- B5/B2: whose process generated this certificate's private key.
		         -- The column existed and the issuing paths set the value, but
		         -- this INSERT never listed it, so every projected certificate
		         -- recorded an empty custody origin. A custody claim that lives
		         -- in the code and not in the row is not auditable, which is the
		         -- entire reason the column exists.
		         key_origin, key_storage, key_exportable, key_generated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
		 ON CONFLICT DO NOTHING`,
		c.ID, c.TenantID, c.OwnerID, c.Subject, sans, c.Issuer, c.Serial, c.Fingerprint,
		c.KeyAlgorithm, c.NotBefore, c.NotAfter, c.DeploymentLocation, c.Source, certDER, certPEM, issuanceResponse,
		c.IssuanceIdempotencyKey, c.IssuanceRequestBinding, c.ReplacesID, c.CreatedAt,
		c.KeyOrigin, c.KeyStorage, c.KeyExportable, c.KeyGeneratedBy)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE certificates
		    SET owner_id = $2, subject = $3, sans = $4, issuer = $5, serial = $6,
		        key_algorithm = $8, not_before = $9, not_after = $10,
		        deployment_location = $11, source = $12,
		        certificate_der = CASE WHEN octet_length($13::bytea) > 0 THEN $13 ELSE certificate_der END,
		        certificate_pem = CASE WHEN octet_length($14::bytea) > 0 THEN $14 ELSE certificate_pem END,
		        issuance_response = CASE WHEN octet_length($15::bytea) > 0 THEN $15 ELSE issuance_response END,
		        issuance_idempotency_key = CASE WHEN $16::text <> '' THEN $16 ELSE issuance_idempotency_key END,
		        issuance_request_binding = CASE WHEN $17::text <> '' THEN $17 ELSE issuance_request_binding END,
		        replaces_id = $18
		  WHERE tenant_id = $1 AND fingerprint = $7`,
		c.TenantID, c.OwnerID, c.Subject, sans, c.Issuer, c.Serial, c.Fingerprint,
		c.KeyAlgorithm, c.NotBefore, c.NotAfter, c.DeploymentLocation, c.Source, certDER, certPEM, issuanceResponse,
		c.IssuanceIdempotencyKey, c.IssuanceRequestBinding, c.ReplacesID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var existingFingerprint string
		queryErr := tx.QueryRow(ctx,
			`SELECT fingerprint FROM certificates WHERE tenant_id = $1 AND id = $2`,
			c.TenantID, c.ID).Scan(&existingFingerprint)
		if queryErr == nil {
			return fmt.Errorf("certificate event reuses id %s for fingerprint %q; existing fingerprint is %q", c.ID, c.Fingerprint, existingFingerprint)
		}
		if queryErr != pgx.ErrNoRows {
			return queryErr
		}
		return fmt.Errorf("certificate event reuses id %s outside tenant %s or references an unavailable row", c.ID, c.TenantID)
	}
	if c.ReplacesID == nil || *c.ReplacesID == "" {
		return nil
	}
	tag, err = tx.Exec(ctx,
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
			`SELECT `+certificateColumns+`
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
		tenantID, t.IdentityID, int64(t.Seq), t.FromState, t.ToState, t.EventType, t.Reason, t.OccurredAt) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
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
		t.Seq = uint64(seq) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
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
var ReadModelTables = []string{"owners", "issuers", "identities", "certificates", "crypto_assets", "pqc_migration_campaigns", "pqc_migration_campaign_findings", "agents", "agent_cert_revocations", "kubernetes_controller_posture", "tenants", "tenant_key_domains", "identity_transitions", "certificate_profiles", "acme_dns01_provider_configs", "acme_upstream_authorizations", "endpoint_verifications", "mdm_scep_policies", "workload_attester_trust_sources", "secret_sync_workload_identity_sources", "tenant_members", "ca_authorities", "ca_key_ceremonies", "ca_ceremony_approvals", "ca_issued_certs", "ca_crls", "ca_ocsp_responders", "discovery_sources", "discovery_schedules", "discovery_runs", "discovery_findings", "discovery_coverage", "notification_channels", "notification_reads", "notification_threshold_deliveries", "notification_test_operations", "notification_delivery_receipts", "connector_delivery_receipts", "lifecycle_rotation_runs", "incident_executions", "incident_fleet_reissuance_runs", "remediation_playbook_runs", "pam_sessions", "compliance_report_schedules", "secret_rotation_schedules", "dynamic_secret_operations", "dynamic_secret_leases", "secret_sync_jobs", "managed_key_operations", "managed_keys", "code_signing_operations", "privacy_subject_erasures", "privacy_retention_runs", "privacy_archive_erasure_attestations", "nhi_access_review_campaigns", "nhi_access_review_items", "access_change_requests", "access_change_request_decisions", "machine_sessions", "machine_auth_method_overrides",
	// I2. Both are projections: owner_ownership_conflicts from ownership.reconciled,
	// cmdb_reconcile_schedules from cmdb.schedule.configured. A rebuild does lose
	// the schedule's last_run_at/last_error, which the SCHEDULER writes rather than
	// the log — the cost is one extra sync within a minute of the rebuild, and the
	// alternative (calling them independent PG state) would claim the operator's
	// instruction is not event-sourced when it is.
	"owner_ownership_conflicts", "cmdb_reconcile_schedules",
	// I3: projected from issuance.request.opened / .decided.
	"issuance_requests",
	// I5: projected from mdm.device.correlated.
	"mdm_device_correlations",
	// A5: projected from agent.upgrade.campaign.* / agent.upgrade.ring.dispatched.
	"agent_upgrade_campaigns", "agent_upgrade_dispatches"}

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
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// DR rebuilds legitimately exceed the bounded statement deadline
	// (OPS-TIMEOUTS-001): widen it for THIS transaction only.
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = 0"); err != nil {
		return fmt.Errorf("store: widen rebuild statement deadline: %w", err)
	}
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
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = 0"); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("store: widen restore statement deadline: %w", err)
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
		t.TenantID, t.Name, int64(t.EventSeq)) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	return err
}

// DeleteTenantReadModelTx deletes one tenant's rows from the event-sourced read
// model (ReadModelTables) on the caller's transaction, for the atomic-rebuild replay
// of a tenant.offboarded event (RESIL-003): within a rebuild, a deleted tenant must
// not be resurrected, and the rebuild owns exactly these tables. Each DELETE carries
// tenant_id explicitly (AN-1). It does NOT touch independent tenant tables (those are
// not rebuilt from the log); the live OffboardTenant path handles the full erase.
//
// The table set is DERIVED from ReadModelTables by readModelDeleteOrder (RMODEL-001)
// rather than re-typed here: a second hand-maintained literal had drifted seven
// tables behind ReadModelTables — including tenant_members — so a rebuild resurrected
// those rows for an offboarded tenant. Children are deleted before the parents they
// reference and the tenants row last, so a foreign key never blocks the erase.
func (s *Store) DeleteTenantReadModelTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("store: DeleteTenantReadModelTx requires a tenant id (AN-1)")
	}
	ordered, err := readModelDeleteOrder()
	if err != nil {
		return err
	}
	for _, table := range ordered {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE tenant_id = $1", tenantID); err != nil {
			return fmt.Errorf("store: delete read-model %s for tenant: %w", table, err)
		}
	}
	return nil
}
