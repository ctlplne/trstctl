// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// IssuanceRequest is a first-class request for a credential (I3).
//
// Distinct from issuance_approval_requests, which is a dual-control GATE keyed
// on (tenant, resource, action) and can only answer "have enough people
// approved". This answers the requester's questions: was it denied, did it
// expire, can I withdraw it.
type IssuanceRequest struct {
	ID             string
	TenantID       string
	Subject        string
	OwnerID        string
	Profile        string
	CSRPEM         string
	Requester      string
	Justification  string
	Origin         string
	TicketRef      string
	Status         string
	DecidedBy      string
	DecisionReason string
	DecidedAt      *time.Time
	IdentityID     string
	IssuedBy       string
	IssuedAt       *time.Time
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

const issuanceRequestCols = `id::text, tenant_id::text, subject, coalesce(owner_id::text, ''), profile, csr_pem, requester,
	justification, origin, ticket_ref, status, decided_by, decision_reason, decided_at,
	coalesce(identity_id::text, ''), coalesce(issued_by, ''), issued_at, expires_at, created_at`

func scanIssuanceRequest(row pgx.Row) (IssuanceRequest, error) {
	var r IssuanceRequest
	err := row.Scan(&r.ID, &r.TenantID, &r.Subject, &r.OwnerID, &r.Profile, &r.CSRPEM, &r.Requester,
		&r.Justification, &r.Origin, &r.TicketRef, &r.Status, &r.DecidedBy, &r.DecisionReason,
		&r.DecidedAt, &r.IdentityID, &r.IssuedBy, &r.IssuedAt, &r.ExpiresAt, &r.CreatedAt)
	return r, err
}

// GetIssuanceRequest loads one request in its tenant context.
func (s *Store) GetIssuanceRequest(ctx context.Context, tenantID, id string) (IssuanceRequest, error) {
	var out IssuanceRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanIssuanceRequest(tx.QueryRow(ctx,
			`SELECT `+issuanceRequestCols+` FROM issuance_requests WHERE tenant_id = $1 AND id = $2`,
			tenantID, id))
		return err
	})
	return out, err
}

// ListIssuanceRequests returns the tenant's requests, newest first. A status
// filter of "" returns every state — an operator auditing what was DENIED needs
// the closed ones as much as the open queue needs the pending ones.
func (s *Store) ListIssuanceRequests(ctx context.Context, tenantID, status string, limit int) ([]IssuanceRequest, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []IssuanceRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+issuanceRequestCols+` FROM issuance_requests
			  WHERE tenant_id = $1 AND ($2 = '' OR status = $2)
			  ORDER BY created_at DESC LIMIT $3`, tenantID, status, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanIssuanceRequest(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// TenantsWithExpirableIssuanceRequests enumerates tenants holding a request that
// is still waiting and past due, so the leader-only sweep can visit each under
// its own RLS context.
func (s *Store) TenantsWithExpirableIssuanceRequests(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants hold an overdue issuance request so the leader-only expiry sweep can visit each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM issuance_requests
		  WHERE status = 'requested' AND expires_at <= $1 ORDER BY tenant_id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DueIssuanceRequests returns the tenant's requests that have run out of time.
func (s *Store) DueIssuanceRequests(ctx context.Context, tenantID string, now time.Time, limit int) ([]IssuanceRequest, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []IssuanceRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+issuanceRequestCols+` FROM issuance_requests
			  WHERE tenant_id = $1 AND status = 'requested' AND expires_at <= $2
			  ORDER BY expires_at LIMIT $3`, tenantID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanIssuanceRequest(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ErrIssuanceRequestNotFound is returned when a decision names a request that
// does not exist in the caller's tenant.
var ErrIssuanceRequestNotFound = errors.New("store: issuance request not found")

// TicketIntakeSchedule is a tenant's standing instruction to read its ITSM for
// certificate-request tickets (I3).
type TicketIntakeSchedule struct {
	TenantID    string
	System      string
	InstanceURL string
	TokenRef    string
	// SNTable is bounded by the schema CHECK to the request-shaped tables.
	SNTable     string
	JiraProject string
	Query       string
	// The field mapping is explicit, never inferred. A ticket missing the
	// mapped subject or profile is skipped and counted, not guessed at.
	SubjectField         string
	ProfileField         string
	RequesterField       string
	JustificationField   string
	IntervalSeconds      int
	Enabled              bool
	AllowPrivateEndpoint bool
	PrivateEgressCIDRs   []string
	LastRunAt            *time.Time
	LastError            string
	CurrentSweepID       string
	SweepStartedAt       *time.Time
	LastAttemptAt        *time.Time
	Cursor               string
	ReadCount            int
	ExpectedCount        *int
	PagesCompleted       int
	CoverageComplete     bool
	EligibleCount        int
	SkippedCount         int
}

const ticketIntakeCols = `tenant_id::text, system, instance_url, token_ref, sn_table, jira_project, query,
	subject_field, profile_field, requester_field, justification_field,
	interval_seconds, enabled, allow_private_endpoint, coalesce(private_egress_cidrs, '{}'),
	last_run_at, last_error, coalesce(current_sweep_id::text, ''), sweep_started_at,
	last_attempt_at, cursor, read_count, expected_count, pages_completed, coverage_complete,
	eligible_count, skipped_count`

// Keep this statement literal so the AN-1 analyzer can prove the tenant
// predicate instead of having to trust a dynamically assembled SELECT list.
const ticketIntakeDueSQL = `SELECT tenant_id::text, system, instance_url, token_ref,
	sn_table, jira_project, query, subject_field, profile_field, requester_field,
	justification_field, interval_seconds, enabled, allow_private_endpoint,
	coalesce(private_egress_cidrs, '{}'), last_run_at, last_error,
	coalesce(current_sweep_id::text, ''), sweep_started_at, last_attempt_at,
	cursor, read_count, expected_count, pages_completed, coverage_complete,
	eligible_count, skipped_count
	FROM ticket_intake_schedules WHERE tenant_id = $1 AND enabled AND interval_seconds > 0
	ORDER BY system`

func scanTicketIntake(row pgx.Row) (TicketIntakeSchedule, error) {
	var s TicketIntakeSchedule
	err := row.Scan(&s.TenantID, &s.System, &s.InstanceURL, &s.TokenRef, &s.SNTable, &s.JiraProject, &s.Query,
		&s.SubjectField, &s.ProfileField, &s.RequesterField, &s.JustificationField,
		&s.IntervalSeconds, &s.Enabled, &s.AllowPrivateEndpoint, &s.PrivateEgressCIDRs,
		&s.LastRunAt, &s.LastError, &s.CurrentSweepID, &s.SweepStartedAt, &s.LastAttemptAt,
		&s.Cursor, &s.ReadCount, &s.ExpectedCount, &s.PagesCompleted, &s.CoverageComplete,
		&s.EligibleCount, &s.SkippedCount)
	return s, err
}

// GetTicketIntakeSchedule returns the tenant's intake schedule for one system.
func (s *Store) GetTicketIntakeSchedule(ctx context.Context, tenantID, system string) (TicketIntakeSchedule, bool, error) {
	var out TicketIntakeSchedule
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		sched, err := scanTicketIntake(tx.QueryRow(ctx,
			`SELECT `+ticketIntakeCols+` FROM ticket_intake_schedules
			  WHERE tenant_id = $1 AND system = $2`, tenantID, system))
		switch {
		case err == nil:
			out, found = sched, true
			return nil
		case err.Error() == pgx.ErrNoRows.Error():
			return nil
		default:
			return err
		}
	})
	return out, found, err
}

// TenantsWithEnabledTicketIntake enumerates tenants for the leader ticker.
func (s *Store) TenantsWithEnabledTicketIntake(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: enumerates which tenants have an enabled ticket intake so the leader-only scheduler can sweep each tenant under its own RLS context (AN-1 exemption).
		`SELECT DISTINCT tenant_id::text FROM ticket_intake_schedules WHERE enabled ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TicketIntakeDueSchedules returns every provider schedule that needs a new
// sweep or has an incomplete cursor to resume. ServiceNow must not starve Jira.
func (s *Store) TicketIntakeDueSchedules(ctx context.Context, tenantID string, now time.Time) ([]TicketIntakeSchedule, error) {
	var out []TicketIntakeSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, ticketIntakeDueSQL, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sched, err := scanTicketIntake(rows)
			if err != nil {
				return err
			}
			if sched.CurrentSweepID != "" && !sched.CoverageComplete {
				out = append(out, sched)
				continue
			}
			if sched.LastRunAt == nil || now.Sub(*sched.LastRunAt) >= time.Duration(sched.IntervalSeconds)*time.Second {
				out = append(out, sched)
			}
		}
		return rows.Err()
	})
	return out, err
}

// TicketIntakeDue is retained for older embedders and returns the first due
// provider in stable system order.
func (s *Store) TicketIntakeDue(ctx context.Context, tenantID string, now time.Time) (TicketIntakeSchedule, bool, error) {
	due, err := s.TicketIntakeDueSchedules(ctx, tenantID, now)
	if err != nil || len(due) == 0 {
		return TicketIntakeSchedule{}, false, err
	}
	return due[0], true, nil
}

// ApplyTicketIntakeConfiguredTx projects ticket.intake.configured (I3).
func (s *Store) ApplyTicketIntakeConfiguredTx(ctx context.Context, tx pgx.Tx, tenantID string, in TicketIntakeSchedule) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO ticket_intake_schedules
		   (tenant_id, system, instance_url, token_ref, sn_table, jira_project, query,
		    subject_field, profile_field, requester_field, justification_field,
		    interval_seconds, enabled, allow_private_endpoint, private_egress_cidrs)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 ON CONFLICT (tenant_id, system) DO UPDATE SET
		   instance_url = EXCLUDED.instance_url, token_ref = EXCLUDED.token_ref,
		   sn_table = EXCLUDED.sn_table, jira_project = EXCLUDED.jira_project, query = EXCLUDED.query,
		   subject_field = EXCLUDED.subject_field, profile_field = EXCLUDED.profile_field,
		   requester_field = EXCLUDED.requester_field, justification_field = EXCLUDED.justification_field,
		   interval_seconds = EXCLUDED.interval_seconds, enabled = EXCLUDED.enabled,
		   allow_private_endpoint = EXCLUDED.allow_private_endpoint,
		   private_egress_cidrs = EXCLUDED.private_egress_cidrs,
		   current_sweep_id = NULL, sweep_started_at = NULL, last_attempt_at = NULL,
		   cursor = '', read_count = 0, expected_count = NULL, pages_completed = 0,
		   coverage_complete = false, eligible_count = 0, skipped_count = 0,
		   last_error = '', updated_at = now()`,
		tenantID, in.System, in.InstanceURL, in.TokenRef, in.SNTable, in.JiraProject, in.Query,
		in.SubjectField, in.ProfileField, in.RequesterField, in.JustificationField,
		in.IntervalSeconds, in.Enabled, false, nil)
	return err
}

// IssuanceRequestExistsForTicket reports whether a request already carries this
// ticket reference — the intake's idempotency: one ticket, one request, however
// many polls see it. Closed or expired requests still count; a ticket whose
// request was denied must not silently reopen on the next sweep, because the
// denial WAS the answer to that ticket.
func (s *Store) IssuanceRequestExistsForTicket(ctx context.Context, tenantID, ticketRef string) (bool, error) {
	var exists bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM issuance_requests WHERE tenant_id = $1 AND ticket_ref = $2)`,
			tenantID, ticketRef).Scan(&exists)
	})
	return exists, err
}
