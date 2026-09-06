// SPDX-License-Identifier: MPL-2.0

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const ADCSDriftFindingKind = "adcs_template_drift"

// AD CS template posture read model (epic F1).
//
// An in-domain relay reads the directory; this is where what it found becomes
// something an operator can look at tomorrow, rather than only in the job report
// from the run that produced it.

// ADCSTemplatePosture is one template's observed posture.
type ADCSTemplatePosture struct {
	TenantID      string
	Domain        string
	Template      string
	DisplayName   string
	SchemaVersion int
	PublishedBy   []string
	// WorstSeverity is "" when the template has no findings, which is a real
	// and common state — it must not read as unknown.
	WorstSeverity string
	FindingCount  int
	// Findings is the analysis output verbatim, so the console can show what an
	// attacker could do and what removes it without the store needing to model
	// a vocabulary that grows.
	Findings json.RawMessage
	// ObservedBy and ObservedAt say which relay looked and when. An operator
	// reading a dangerous template needs to know whether this is yesterday's
	// answer.
	ObservedBy string
	ObservedAt time.Time
	// ObservedTemplate is the template exactly as the directory reported it
	// (epic F2), so the next sweep can compute a semantic diff against what was
	// really there rather than against a reconstruction. Without it a second
	// sweep would report the whole estate as newly dangerous.
	ObservedTemplate json.RawMessage
}

// ADCSEnrollmentServicePosture is one CA's normalized LDAP, HTTP, and CA-policy
// evidence. ObservedService is the exact privacy-safe event fragment used to
// derive the row; raw HTTP/certutil output never enters this model.
type ADCSEnrollmentServicePosture struct {
	TenantID               string
	Domain                 string
	Service                string
	DNSName                string
	EnrollmentWebServices  []string
	AgentRestrictionState  string
	AgentRestrictionSource string
	WorstSeverity          string
	FindingCount           int
	Findings               json.RawMessage
	ObservedService        json.RawMessage
	ObservedBy             string
	ObservedAt             time.Time
}

// ApplyADCSPostureObservedTx atomically replaces both halves of one domain's
// posture from a single immutable observation. A reader can therefore never see
// new templates beside stale enrollment services, including during replay.
func (s *Store) ApplyADCSPostureObservedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, domain, observedBy string,
	templates []ADCSTemplatePosture,
	services []ADCSEnrollmentServicePosture,
	at time.Time,
) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "adcs-posture\x1f"+tenantID+"\x1f"+domain); err != nil {
		return fmt.Errorf("store: lock AD CS posture domain: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM adcs_template_posture WHERE tenant_id = $1 AND domain = $2`, tenantID, domain); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM adcs_enrollment_service_posture WHERE tenant_id = $1 AND domain = $2`, tenantID, domain); err != nil {
		return err
	}
	if err := s.insertADCSTemplatePostureObservedTx(ctx, tx, tenantID, domain, observedBy, templates, at); err != nil {
		return err
	}
	for _, row := range services {
		findings := row.Findings
		if len(findings) == 0 {
			findings = json.RawMessage("[]")
		}
		webServices := row.EnrollmentWebServices
		if webServices == nil {
			webServices = []string{}
		}
		observed := row.ObservedService
		if len(observed) == 0 {
			observed = json.RawMessage("{}")
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO adcs_enrollment_service_posture
			     (tenant_id, domain, service, dns_name, enrollment_web_services,
			      agent_restriction_state, agent_restriction_source,
			      worst_severity, finding_count, findings, observed_service,
			      observed_by, observed_at)
			 VALUES ($1, $2, $3, $4, $5::text[], $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12, $13)`,
			tenantID, domain, row.Service, row.DNSName, webServices,
			row.AgentRestrictionState, row.AgentRestrictionSource,
			row.WorstSeverity, row.FindingCount, string(findings), string(observed), observedBy, at.UTC()); err != nil {
			return err
		}
	}
	return nil
}

// ApplyADCSTemplatePostureObservedTx is the projector-only writer for one
// immutable adcs.template.inventory.observed event. Delete+insert is atomic, so
// a removed directory template disappears on replay without a partial domain
// ever becoming visible. There is deliberately no non-projector wrapper: all
// state changes must enter through the event log (AN-2).
func (s *Store) ApplyADCSTemplatePostureObservedTx(ctx context.Context, tx pgx.Tx, tenantID, domain, observedBy string, rows []ADCSTemplatePosture, at time.Time) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "adcs-posture\x1f"+tenantID+"\x1f"+domain); err != nil {
		return fmt.Errorf("store: lock AD CS posture domain: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM adcs_template_posture WHERE tenant_id = $1 AND domain = $2`,
		tenantID, domain); err != nil {
		return err
	}
	return s.insertADCSTemplatePostureObservedTx(ctx, tx, tenantID, domain, observedBy, rows, at)
}

func (s *Store) insertADCSTemplatePostureObservedTx(ctx context.Context, tx pgx.Tx, tenantID, domain, observedBy string, rows []ADCSTemplatePosture, at time.Time) error {
	for _, row := range rows {
		findings := row.Findings
		if len(findings) == 0 {
			findings = json.RawMessage("[]")
		}
		published := row.PublishedBy
		if published == nil {
			published = []string{}
		}
		observed := row.ObservedTemplate
		if len(observed) == 0 {
			observed = json.RawMessage("{}")
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO adcs_template_posture
			     (tenant_id, domain, template, display_name, schema_version,
			      published_by, worst_severity, finding_count, findings,
			      observed_by, observed_at, observed_template)
			 VALUES ($1, $2, $3, $4, $5, $6::text[], $7, $8, $9::jsonb, $10, $11, $12::jsonb)`,
			tenantID, domain, row.Template, row.DisplayName, row.SchemaVersion,
			published, row.WorstSeverity, row.FindingCount, string(findings),
			observedBy, at.UTC(), string(observed)); err != nil {
			return err
		}
	}
	return nil
}

// ListADCSTemplatePosture returns a tenant's observed templates, most dangerous
// first — which is the order an operator wants and the order the index serves.
func (s *Store) ListADCSTemplatePosture(ctx context.Context, tenantID string, limit int) ([]ADCSTemplatePosture, error) {
	if limit <= 0 {
		limit = 200
	}
	var out []ADCSTemplatePosture
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			// Severity ranked deliberately rather than alphabetically: sorted as
			// text, "critical" would come before "high" by luck and "medium"
			// before both, which is the wrong order presented confidently.
			`SELECT tenant_id::text, domain, template, display_name, schema_version,
			        published_by, worst_severity, finding_count, findings,
			        observed_by, observed_at, observed_template
			   FROM adcs_template_posture
			  WHERE tenant_id = $1
			  ORDER BY CASE worst_severity
			             WHEN 'critical' THEN 0
			             WHEN 'high'     THEN 1
			             WHEN 'medium'   THEN 2
			             ELSE 3
			           END, domain, template
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row ADCSTemplatePosture
			var findings, observed []byte
			if err := rows.Scan(&row.TenantID, &row.Domain, &row.Template, &row.DisplayName,
				&row.SchemaVersion, &row.PublishedBy, &row.WorstSeverity, &row.FindingCount,
				&findings, &row.ObservedBy, &row.ObservedAt, &observed); err != nil {
				return err
			}
			row.Findings = json.RawMessage(findings)
			row.ObservedTemplate = json.RawMessage(observed)
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// ListADCSEnrollmentServicePosture returns a tenant's latest observed service
// facts, worst first. tenant_id is explicit even though RLS is the floor (AN-1).
func (s *Store) ListADCSEnrollmentServicePosture(ctx context.Context, tenantID string, limit int) ([]ADCSEnrollmentServicePosture, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []ADCSEnrollmentServicePosture
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, domain, service, dns_name, enrollment_web_services,
			        agent_restriction_state, agent_restriction_source,
			        worst_severity, finding_count, findings, observed_service,
			        observed_by, observed_at
			   FROM adcs_enrollment_service_posture
			  WHERE tenant_id = $1
			  ORDER BY CASE worst_severity
			             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3
			           END, domain, service
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var row ADCSEnrollmentServicePosture
			var findings, observed []byte
			if err := rows.Scan(&row.TenantID, &row.Domain, &row.Service, &row.DNSName,
				&row.EnrollmentWebServices, &row.AgentRestrictionState, &row.AgentRestrictionSource,
				&row.WorstSeverity, &row.FindingCount, &findings, &observed,
				&row.ObservedBy, &row.ObservedAt); err != nil {
				return err
			}
			row.Findings, row.ObservedService = json.RawMessage(findings), json.RawMessage(observed)
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyADCSTemplateDriftObservedTx projects one immutable semantic-drift
// finding and, only for a worsening record, its notification intent in the same
// tenant transaction (AN-2/AN-6). The existing discovery_findings table is the
// right durable shape: each row belongs to the real source/run that observed it,
// already has RLS, and already participates in rebuild/snapshot/offboarding.
func (s *Store) ApplyADCSTemplateDriftObservedTx(
	ctx context.Context,
	tx pgx.Tx,
	finding DiscoveryFinding,
	alertDestination string,
	alertPayload []byte,
	alertKey string,
) error {
	if finding.TenantID == "" || finding.ID == "" || finding.RunID == "" ||
		finding.SourceID == "" || finding.Kind != ADCSDriftFindingKind ||
		len(finding.Metadata) == 0 || finding.DiscoveredAt.IsZero() {
		return errors.New("store: AD CS drift finding is incomplete")
	}
	if (alertDestination == "") != (len(alertPayload) == 0) ||
		(alertDestination == "") != (alertKey == "") {
		return errors.New("store: AD CS drift alert intent is incomplete")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"adcs-template-drift\x1f"+finding.TenantID+"\x1f"+finding.ID); err != nil {
		return fmt.Errorf("store: lock AD CS drift finding: %w", err)
	}
	var existed bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (
		     SELECT 1 FROM discovery_findings
		      WHERE tenant_id = $1 AND (id = $2 OR $2::uuid = ANY(recorded_ids))
		 )`, finding.TenantID, finding.ID).Scan(&existed); err != nil {
		return err
	}
	if err := s.ApplyDiscoveryFindingRecordedTx(ctx, tx, finding); err != nil {
		return err
	}
	// Exact replay validates through ApplyDiscoveryFindingRecordedTx above and
	// does not recreate an alert while the immutable projected finding exists.
	if existed || alertDestination == "" {
		return nil
	}
	var existingDestination string
	var existingPayload []byte
	err := tx.QueryRow(ctx,
		`SELECT destination, payload FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id LIMIT 1`,
		finding.TenantID, alertKey).Scan(&existingDestination, &existingPayload)
	if err == nil {
		if existingDestination != alertDestination || !bytes.Equal(existingPayload, alertPayload) {
			return fmt.Errorf("%w: AD CS drift alert key is already bound", ErrIdempotencyConflict)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key)
		 VALUES ($1, $2, $2, $3, $4)`,
		finding.TenantID, alertDestination, alertPayload, alertKey); err != nil {
		return fmt.Errorf("store: enqueue AD CS drift alert: %w", err)
	}
	return nil
}

// ListADCSTemplateDrift returns immutable drift findings newest first. The kind
// predicate prevents unrelated discovery metadata from crossing this purpose-
// built history surface; tenant_id is still explicit in SQL and enforced by RLS.
func (s *Store) ListADCSTemplateDrift(ctx context.Context, tenantID string, limit int) ([]DiscoveryFinding, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []DiscoveryFinding
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, run_id::text, source_id::text, kind, ref,
			        provenance, fingerprint, risk_score, metadata, discovered_at,
			        triage_status, managed_identity_id::text, triage_actor, triage_reason, triaged_at,
		              first_seen_at, last_seen_at, seen_count
			   FROM discovery_findings
			  WHERE tenant_id = $1 AND kind = $2
			  ORDER BY discovered_at DESC, id DESC LIMIT $3`,
			tenantID, ADCSDriftFindingKind, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var finding DiscoveryFinding
			if err := scanDiscoveryFinding(rows, &finding); err != nil {
				return err
			}
			out = append(out, finding)
		}
		return rows.Err()
	})
	return out, err
}
