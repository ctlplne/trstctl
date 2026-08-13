// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// EnrollmentDiagnosticRetentionLimit bounds the number of distinct diagnosis
// keys retained for one tenant. Repeats collapse into Count, so a retry storm
// cannot evict every other useful failure.
const EnrollmentDiagnosticRetentionLimit = 200

// enrollmentDiagnosticObservationDedupLimit retains enough recent event ids to
// suppress the normal inline-projection plus tail-replay duplicate without
// turning a retry storm into an unbounded PostgreSQL table. Snapshots capture
// this window; a full rebuild starts empty and deterministically replays once.
const enrollmentDiagnosticObservationDedupLimit = 10000

var (
	// ErrEnrollmentDiagnosticNoVerificationRoute means the requested identity
	// has no single enabled deployment target with an explicit verify_address.
	// The refusal is still recorded; only the prove-fixed action is unavailable.
	ErrEnrollmentDiagnosticNoVerificationRoute = errors.New("store: enrollment diagnostic has no exact verification route")
	// ErrEnrollmentDiagnosticNoPostFailureCertificate means the operator has
	// not yet completed a successful retry that produced an active certificate
	// after this refusal. A pre-failure certificate cannot prove this fix.
	ErrEnrollmentDiagnosticNoPostFailureCertificate = errors.New("store: enrollment diagnostic has no post-failure certificate")
)

type EnrollmentDiagnosticVerificationRoute struct {
	Address    string
	ServerName string
}

// EnrollmentDiagnostic is the tenant-scoped read projection of one collapsed
// enrollment failure class. SourceEventID and EventSequence bind the latest
// fields to immutable evidence and make a replayed/out-of-order projection a
// no-op rather than another observation.
type EnrollmentDiagnostic struct {
	TenantID                   string
	DiagnosticID               string
	Protocol                   string
	Step                       string
	Cause                      string
	Summary                    string
	Remediation                string
	OperationRef               string
	IdentityRef                string
	EndpointRef                string
	VerificationKind           string
	VerificationAddress        string
	VerificationServerName     string
	ExpectedFingerprint        string
	VerificationEndpointID     string
	VerificationQueuedAt       time.Time
	VerificationStatus         string
	VerificationEvidenceDigest string
	VerificationAgent          string
	VerificationCheckedAt      time.Time
	Actionable                 bool
	ObservedAt                 time.Time
	Count                      int64
	SourceEventID              string
	EventSequence              uint64
}

// ApplyEnrollmentDiagnosticVerificationQueuedTx projects the operator action;
// it never creates a diagnosis that was not already observed for this tenant.
func (s *Store) ApplyEnrollmentDiagnosticVerificationQueuedTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, diagnosticID, endpointID, expectedFingerprint string,
	queuedAt time.Time,
	eventSequence uint64,
) error {
	if tenantID == "" || diagnosticID == "" || endpointID == "" || expectedFingerprint == "" || queuedAt.IsZero() || eventSequence == 0 {
		return fmt.Errorf("store: invalid enrollment diagnostic verification event")
	}
	tag, err := tx.Exec(ctx,
		`UPDATE enrollment_diagnostics
		    SET verification_endpoint_id = $3,
		        verification_queued_at = $4,
		        verification_event_sequence = $5,
		        expected_fingerprint = $6
		  WHERE tenant_id = $1 AND diagnostic_id = $2
		    AND verification_event_sequence < $5`,
		tenantID, diagnosticID, endpointID, queuedAt.UTC(), int64(eventSequence), expectedFingerprint) // #nosec G115 -- JetStream sequence fits positive bigint (CWE-190)
	if err != nil {
		return fmt.Errorf("store: project enrollment diagnostic verification: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1 FROM enrollment_diagnostics
			     WHERE tenant_id = $1 AND diagnostic_id = $2
			)`, tenantID, diagnosticID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return pgx.ErrNoRows
		}
	}
	return nil
}

// GetEnrollmentDiagnosticVerificationTarget resolves only the authenticated
// tenant's exact durable target before a prove-fixed job is queued.
func (s *Store) GetEnrollmentDiagnosticVerificationTarget(ctx context.Context, tenantID, diagnosticID string) (EnrollmentDiagnostic, error) {
	var diagnostic EnrollmentDiagnostic
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT tenant_id::text, diagnostic_id, verification_kind,
			        verification_address, verification_server_name, expected_fingerprint,
			        identity_ref, observed_at
			   FROM enrollment_diagnostics
			  WHERE tenant_id = $1 AND diagnostic_id = $2`, tenantID, diagnosticID).
			Scan(&diagnostic.TenantID, &diagnostic.DiagnosticID, &diagnostic.VerificationKind,
				&diagnostic.VerificationAddress, &diagnostic.VerificationServerName,
				&diagnostic.ExpectedFingerprint, &diagnostic.IdentityRef, &diagnostic.ObservedAt); err != nil {
			return err
		}
		if diagnostic.VerificationKind != "endpoint.verify" || strings.TrimSpace(diagnostic.VerificationAddress) == "" {
			return ErrEnrollmentDiagnosticNoVerificationRoute
		}
		identityName, ok := strings.CutPrefix(diagnostic.IdentityRef, "dns:")
		if !ok || strings.TrimSpace(identityName) == "" {
			return ErrEnrollmentDiagnosticNoPostFailureCertificate
		}
		err := tx.QueryRow(ctx,
			`SELECT fingerprint
			   FROM certificates
			  WHERE tenant_id = $1
			    AND EXISTS (SELECT 1 FROM unnest(sans) AS san WHERE lower(san) = lower($2))
			    AND source = 'issued' AND status = 'active' AND created_at > $3
			  ORDER BY created_at DESC, id DESC
			  LIMIT 1`, tenantID, identityName, diagnostic.ObservedAt.UTC()).Scan(&diagnostic.ExpectedFingerprint)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrEnrollmentDiagnosticNoPostFailureCertificate
		}
		return err
	})
	return diagnostic, err
}

// ResolveEnrollmentDiagnosticVerificationRoute maps a DNS identity to one
// configured deployment target. It never guesses host:443 from a SAN: D2 must
// probe the endpoint the operator actually configured, not a plausible address.
func (s *Store) ResolveEnrollmentDiagnosticVerificationRoute(
	ctx context.Context,
	tenantID, identityRef string,
) (EnrollmentDiagnosticVerificationRoute, error) {
	identityName, ok := strings.CutPrefix(identityRef, "dns:")
	if tenantID == "" || !ok || strings.TrimSpace(identityName) == "" {
		return EnrollmentDiagnosticVerificationRoute{}, ErrEnrollmentDiagnosticNoVerificationRoute
	}
	var configs [][]byte
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT target.config
			   FROM identities AS identity
			   JOIN deployment_targets AS target
			     ON target.tenant_id = $1
			    AND target.tenant_id = identity.tenant_id
			    AND target.id::text = identity.attributes->>'deployment_target_id'
			  WHERE identity.tenant_id = $1 AND lower(identity.name) = lower($2) AND target.enabled
			  ORDER BY identity.id, target.id
			  LIMIT 2`, tenantID, identityName)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			configs = append(configs, raw)
		}
		return rows.Err()
	})
	if err != nil {
		return EnrollmentDiagnosticVerificationRoute{}, err
	}
	if len(configs) != 1 {
		return EnrollmentDiagnosticVerificationRoute{}, ErrEnrollmentDiagnosticNoVerificationRoute
	}
	var config struct {
		Address    string `json:"verify_address"`
		ServerName string `json:"verify_server_name"`
	}
	if err := json.Unmarshal(configs[0], &config); err != nil || strings.TrimSpace(config.Address) == "" {
		return EnrollmentDiagnosticVerificationRoute{}, ErrEnrollmentDiagnosticNoVerificationRoute
	}
	return EnrollmentDiagnosticVerificationRoute{
		Address: strings.TrimSpace(config.Address), ServerName: strings.TrimSpace(config.ServerName),
	}, nil
}

// ApplyEnrollmentDiagnosticObservedTx projects one immutable observation. The
// caller supplies the event transaction and tenant GUC. Both the collapse and
// retention queries bind tenant_id explicitly, in addition to FORCE RLS.
func (s *Store) ApplyEnrollmentDiagnosticObservedTx(ctx context.Context, tx pgx.Tx, diagnostic EnrollmentDiagnostic) error {
	if diagnostic.TenantID == "" {
		return fmt.Errorf("store: enrollment diagnostic tenant id is required (AN-1)")
	}
	if diagnostic.DiagnosticID == "" {
		// Direct v1 projection callers and cold replay fixtures predate exact
		// operation references. Preserve their old class-collapse semantics under
		// the same deterministic id the projector assigns to v1 events.
		diagnostic.DiagnosticID = "legacy:" + diagnostic.Protocol + ":" + diagnostic.Step + ":" + diagnostic.Cause
	}
	if diagnostic.Protocol == "" || diagnostic.Step == "" || diagnostic.Cause == "" || diagnostic.Summary == "" {
		return fmt.Errorf("store: enrollment diagnostic protocol, step, cause, and summary are required")
	}
	if diagnostic.ObservedAt.IsZero() || diagnostic.SourceEventID == "" || diagnostic.EventSequence == 0 {
		return fmt.Errorf("store: enrollment diagnostic event identity, sequence, and observation time are required")
	}
	var inserted int
	err := tx.QueryRow(ctx,
		`INSERT INTO enrollment_diagnostic_observations
		    (tenant_id, source_event_id, event_sequence, diagnostic_id, protocol, step, cause, observed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, source_event_id) DO NOTHING
		 RETURNING 1`, diagnostic.TenantID, diagnostic.SourceEventID,
		int64(diagnostic.EventSequence), diagnostic.DiagnosticID, diagnostic.Protocol, diagnostic.Step, diagnostic.Cause, diagnostic.ObservedAt.UTC()).Scan(&inserted) // #nosec G115 -- JetStream/PostgreSQL sequences share the signed-bigint storage bound (CWE-190)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: remember enrollment diagnostic event: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO enrollment_diagnostics
		    (tenant_id, diagnostic_id, protocol, step, cause, summary, remediation,
		     operation_ref, identity_ref, endpoint_ref, verification_kind, verification_address,
		     verification_server_name, expected_fingerprint, actionable,
		     observed_at, observation_count, source_event_id, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 1, $17, $18)
		 ON CONFLICT (tenant_id, diagnostic_id) DO UPDATE SET
		    protocol = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.protocol ELSE enrollment_diagnostics.protocol END,
		    step = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.step ELSE enrollment_diagnostics.step END,
		    cause = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.cause ELSE enrollment_diagnostics.cause END,
		    summary = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.summary ELSE enrollment_diagnostics.summary END,
		    remediation = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.remediation ELSE enrollment_diagnostics.remediation END,
		    operation_ref = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.operation_ref ELSE enrollment_diagnostics.operation_ref END,
		    identity_ref = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.identity_ref ELSE enrollment_diagnostics.identity_ref END,
		    endpoint_ref = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.endpoint_ref ELSE enrollment_diagnostics.endpoint_ref END,
		    verification_kind = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.verification_kind ELSE enrollment_diagnostics.verification_kind END,
		    verification_address = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.verification_address ELSE enrollment_diagnostics.verification_address END,
		    verification_server_name = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.verification_server_name ELSE enrollment_diagnostics.verification_server_name END,
		    expected_fingerprint = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.expected_fingerprint ELSE enrollment_diagnostics.expected_fingerprint END,
		    verification_endpoint_id = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN '' ELSE enrollment_diagnostics.verification_endpoint_id END,
		    verification_queued_at = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN NULL ELSE enrollment_diagnostics.verification_queued_at END,
		    verification_event_sequence = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN 0 ELSE enrollment_diagnostics.verification_event_sequence END,
		    actionable = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.actionable ELSE enrollment_diagnostics.actionable END,
		    observed_at = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.observed_at ELSE enrollment_diagnostics.observed_at END,
		    observation_count = enrollment_diagnostics.observation_count + 1,
		    source_event_id = CASE WHEN enrollment_diagnostics.event_sequence < EXCLUDED.event_sequence THEN EXCLUDED.source_event_id ELSE enrollment_diagnostics.source_event_id END,
		    event_sequence = GREATEST(enrollment_diagnostics.event_sequence, EXCLUDED.event_sequence)
		 WHERE enrollment_diagnostics.tenant_id = EXCLUDED.tenant_id`,
		diagnostic.TenantID, diagnostic.DiagnosticID, diagnostic.Protocol, diagnostic.Step, diagnostic.Cause,
		diagnostic.Summary, diagnostic.Remediation, diagnostic.OperationRef, diagnostic.IdentityRef,
		diagnostic.EndpointRef, diagnostic.VerificationKind, diagnostic.VerificationAddress,
		diagnostic.VerificationServerName, diagnostic.ExpectedFingerprint, diagnostic.Actionable,
		diagnostic.ObservedAt.UTC(), diagnostic.SourceEventID, int64(diagnostic.EventSequence)); err != nil { // #nosec G115 -- JetStream/PostgreSQL sequences share the signed-bigint storage bound (CWE-190)
		return fmt.Errorf("store: project enrollment diagnostic: %w", err)
	}

	// Retain the newest distinct keys for THIS tenant only. The deterministic
	// tie-breakers make rebuilds and replicas choose the same boundary.
	if _, err := tx.Exec(ctx,
		`DELETE FROM enrollment_diagnostics
		 WHERE tenant_id = $1
		   AND diagnostic_id IN (
		       SELECT diagnostic_id
		         FROM enrollment_diagnostics
		        WHERE tenant_id = $1
		        ORDER BY observed_at DESC, event_sequence DESC, diagnostic_id
		        OFFSET $2
		   )`, diagnostic.TenantID, EnrollmentDiagnosticRetentionLimit); err != nil {
		return fmt.Errorf("store: enforce enrollment diagnostic retention: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM enrollment_diagnostic_observations AS observation
		 WHERE observation.tenant_id = $1
		   AND NOT EXISTS (
		       SELECT 1
		         FROM enrollment_diagnostics AS diagnostic
		        WHERE diagnostic.tenant_id = $1
		          AND diagnostic.tenant_id = observation.tenant_id
		          AND diagnostic.diagnostic_id = observation.diagnostic_id
		   )`, diagnostic.TenantID); err != nil {
		return fmt.Errorf("store: prune evicted enrollment diagnostic observations: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM enrollment_diagnostic_observations
		 WHERE tenant_id = $1
		   AND source_event_id IN (
		       SELECT source_event_id
		         FROM enrollment_diagnostic_observations
		        WHERE tenant_id = $1
		        ORDER BY event_sequence DESC, source_event_id
		        OFFSET $2
		   )`, diagnostic.TenantID, enrollmentDiagnosticObservationDedupLimit); err != nil {
		return fmt.Errorf("store: bound enrollment diagnostic event deduplication: %w", err)
	}
	return nil
}

// ListEnrollmentDiagnostics returns only the authenticated tenant's recent
// diagnoses, newest first. The explicit predicate is load-bearing even with RLS:
// it is the repository contract and lets the AN-1 analyzer prove the boundary.
func (s *Store) ListEnrollmentDiagnostics(ctx context.Context, tenantID string, limit int) ([]EnrollmentDiagnostic, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: enrollment diagnostic tenant id is required (AN-1)")
	}
	if limit <= 0 || limit > EnrollmentDiagnosticRetentionLimit {
		limit = EnrollmentDiagnosticRetentionLimit
	}
	out := make([]EnrollmentDiagnostic, 0)
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT diagnostic.tenant_id::text, diagnostic.diagnostic_id, diagnostic.protocol,
			        diagnostic.step, diagnostic.cause, diagnostic.summary, diagnostic.remediation,
			        diagnostic.operation_ref, diagnostic.identity_ref, diagnostic.endpoint_ref,
			        diagnostic.verification_kind, diagnostic.verification_address,
			        diagnostic.verification_server_name, diagnostic.expected_fingerprint,
			        diagnostic.verification_endpoint_id, diagnostic.verification_queued_at,
			        verification.reached, verification.mismatch, verification.evidence_digest,
			        verification.agent_common_name, verification.last_checked_at,
			        diagnostic.actionable, diagnostic.observed_at, diagnostic.observation_count,
			        diagnostic.source_event_id, diagnostic.event_sequence
			   FROM enrollment_diagnostics AS diagnostic
			   LEFT JOIN endpoint_verifications AS verification
			     ON verification.tenant_id = $1
			    AND verification.tenant_id = diagnostic.tenant_id
			    AND verification.endpoint_id = diagnostic.verification_endpoint_id
			    AND verification.vantage = 'relay'
			  WHERE diagnostic.tenant_id = $1
			  ORDER BY diagnostic.observed_at DESC, diagnostic.event_sequence DESC, diagnostic.diagnostic_id
			  LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var diagnostic EnrollmentDiagnostic
			var sequence int64
			var queuedAt, checkedAt *time.Time
			var reached *bool
			var mismatch, evidenceDigest, agentCommonName *string
			if err := rows.Scan(&diagnostic.TenantID, &diagnostic.DiagnosticID, &diagnostic.Protocol, &diagnostic.Step,
				&diagnostic.Cause, &diagnostic.Summary, &diagnostic.Remediation, &diagnostic.OperationRef,
				&diagnostic.IdentityRef, &diagnostic.EndpointRef, &diagnostic.VerificationKind,
				&diagnostic.VerificationAddress, &diagnostic.VerificationServerName, &diagnostic.ExpectedFingerprint,
				&diagnostic.VerificationEndpointID, &queuedAt, &reached, &mismatch, &evidenceDigest,
				&agentCommonName, &checkedAt,
				&diagnostic.Actionable, &diagnostic.ObservedAt, &diagnostic.Count,
				&diagnostic.SourceEventID, &sequence); err != nil {
				return err
			}
			diagnostic.EventSequence = uint64(sequence) // #nosec G115 -- constrained positive bigint written from a JetStream sequence (CWE-190)
			if queuedAt != nil {
				diagnostic.VerificationQueuedAt = *queuedAt
				diagnostic.VerificationStatus = "queued"
			}
			if reached != nil {
				diagnostic.VerificationStatus = "unreachable"
				if *reached && mismatch != nil && *mismatch == "" {
					diagnostic.VerificationStatus = "verified"
				} else if *reached {
					diagnostic.VerificationStatus = "diverged"
				}
			}
			if evidenceDigest != nil {
				diagnostic.VerificationEvidenceDigest = *evidenceDigest
			}
			if agentCommonName != nil {
				diagnostic.VerificationAgent = *agentCommonName
			}
			if checkedAt != nil {
				diagnostic.VerificationCheckedAt = *checkedAt
			}
			out = append(out, diagnostic)
		}
		return rows.Err()
	})
	return out, err
}
