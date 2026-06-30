package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrAccessChangeRequestTerminal   = errors.New("access change request is already terminal")
	ErrAccessChangeDecisionDuplicate = errors.New("access change request decision already recorded")
)

// AccessChangeRequest is an event-sourced approval / PR change-management request
// for non-human identity access. It carries metadata and evidence refs only.
type AccessChangeRequest struct {
	ID                string
	TenantID          string
	RequestedAction   string
	RequesterSubject  string
	NHIID             string
	NHIKind           string
	DisplayName       string
	OwnerRef          string
	Resource          string
	Entitlement       string
	ChangeRef         string
	ChangeSystem      string
	ChangeURL         string
	Risk              string
	Reason            string
	EvidenceRefs      []string
	Status            string
	RequiredApprovals int
	ApprovalCount     int
	CreatedAt         time.Time
	UpdatedAt         time.Time
	CompletedAt       *time.Time
	Decisions         []AccessChangeDecision
}

// AccessChangeDecision is a distinct approver decision for an access-change request.
type AccessChangeDecision struct {
	RequestID            string
	ApproverSubject      string
	Decision             string
	Reason               string
	DecisionEvidenceRefs []string
	DecidedAt            time.Time
}

// ApplyAccessChangeRequestCreatedTx projects a request-created event. Replays are
// deterministic because the event supplies the request id and timestamp.
func (s *Store) ApplyAccessChangeRequestCreatedTx(ctx context.Context, tx pgx.Tx, r AccessChangeRequest) error {
	refs := r.EvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO access_change_requests
		        (tenant_id, id, requested_action, requester_subject, nhi_id, nhi_kind, display_name,
		         owner_ref, resource, entitlement, change_ref, change_system, change_url, risk, reason,
		         evidence_refs, status, required_approvals, approval_count, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
		         $8, $9, $10, $11, $12, $13, $14, $15,
		         $16, 'pending', $17, 0, $18, $18)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		r.TenantID, r.ID, r.RequestedAction, r.RequesterSubject, r.NHIID, r.NHIKind, r.DisplayName,
		r.OwnerRef, r.Resource, r.Entitlement, r.ChangeRef, r.ChangeSystem, r.ChangeURL, r.Risk, r.Reason,
		refs, r.RequiredApprovals, r.CreatedAt)
	return err
}

// ApplyAccessChangeRequestDecidedTx projects one approval or denial. A second
// decision by the same approver or any decision after terminal state fails closed;
// HTTP idempotent replays are answered before they reach this projector.
func (s *Store) ApplyAccessChangeRequestDecidedTx(ctx context.Context, tx pgx.Tx, tenantID string, d AccessChangeDecision) error {
	var status string
	var required int
	err := tx.QueryRow(ctx,
		`SELECT status, required_approvals
		   FROM access_change_requests
		  WHERE tenant_id = $1
		    AND id = $2
		  FOR UPDATE`,
		tenantID, d.RequestID).Scan(&status, &required)
	if err != nil {
		return err
	}
	if status != "pending" {
		return fmt.Errorf("%w: request %s is %s", ErrAccessChangeRequestTerminal, d.RequestID, status)
	}

	refs := d.DecisionEvidenceRefs
	if refs == nil {
		refs = []string{}
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO access_change_request_decisions
		        (tenant_id, request_id, approver_subject, decision, reason, decision_evidence_refs, decided_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (tenant_id, request_id, approver_subject) DO NOTHING`,
		tenantID, d.RequestID, d.ApproverSubject, d.Decision, d.Reason, refs, d.DecidedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s already decided request %s", ErrAccessChangeDecisionDuplicate, d.ApproverSubject, d.RequestID)
	}

	if d.Decision == "denied" {
		_, err = tx.Exec(ctx,
			`WITH counts AS (
			    SELECT count(*) FILTER (WHERE decision = 'approved')::integer AS approval_count
			      FROM access_change_request_decisions
			     WHERE tenant_id = $1
			       AND request_id = $2
			)
			UPDATE access_change_requests r
			   SET status = 'denied',
			       approval_count = counts.approval_count,
			       completed_at = $3,
			       updated_at = $3
			  FROM counts
			 WHERE r.tenant_id = $1
			   AND r.id = $2`,
			tenantID, d.RequestID, d.DecidedAt)
		return err
	}

	_, err = tx.Exec(ctx,
		`WITH counts AS (
		    SELECT count(*) FILTER (WHERE decision = 'approved')::integer AS approval_count
		      FROM access_change_request_decisions
		     WHERE tenant_id = $1
		       AND request_id = $2
		)
		UPDATE access_change_requests r
		   SET approval_count = counts.approval_count,
		       status = CASE WHEN counts.approval_count >= $3 THEN 'approved' ELSE 'pending' END,
		       completed_at = CASE WHEN counts.approval_count >= $3 THEN COALESCE(r.completed_at, $4) ELSE r.completed_at END,
		       updated_at = $4
		  FROM counts
		 WHERE r.tenant_id = $1
		   AND r.id = $2`,
		tenantID, d.RequestID, required, d.DecidedAt)
	return err
}

// GetAccessChangeRequest loads a request with its decisions under tenant RLS.
func (s *Store) GetAccessChangeRequest(ctx context.Context, tenantID, id string) (AccessChangeRequest, error) {
	var out AccessChangeRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		req, err := scanAccessChangeRequest(tx.QueryRow(ctx,
			`SELECT tenant_id::text, id::text, requested_action, requester_subject, nhi_id, nhi_kind, display_name,
			        owner_ref, resource, entitlement, change_ref, change_system, change_url, risk, reason,
			        evidence_refs, status, required_approvals, approval_count, created_at, updated_at, completed_at
			   FROM access_change_requests
			  WHERE tenant_id = $1
			    AND id = $2`,
			tenantID, id))
		if err != nil {
			return err
		}
		decisions, err := s.listAccessChangeDecisionsTx(ctx, tx, tenantID, id)
		if err != nil {
			return err
		}
		req.Decisions = decisions
		out = req
		return nil
	})
	return out, err
}

// ListAccessChangeRequestsPage lists access-change request headers with stable UUID keyset pagination.
func (s *Store) ListAccessChangeRequestsPage(ctx context.Context, tenantID, after string, limit int) ([]AccessChangeRequest, error) {
	if after == "" {
		after = ZeroUUID
	}
	var out []AccessChangeRequest
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT tenant_id::text, id::text, requested_action, requester_subject, nhi_id, nhi_kind, display_name,
			        owner_ref, resource, entitlement, change_ref, change_system, change_url, risk, reason,
			        evidence_refs, status, required_approvals, approval_count, created_at, updated_at, completed_at
			   FROM access_change_requests
			  WHERE tenant_id = $1
			    AND id > $2
			  ORDER BY id
			  LIMIT $3`,
			tenantID, after, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			req, err := scanAccessChangeRequest(rows)
			if err != nil {
				return err
			}
			out = append(out, req)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) listAccessChangeDecisionsTx(ctx context.Context, tx pgx.Tx, tenantID, requestID string) ([]AccessChangeDecision, error) {
	rows, err := tx.Query(ctx,
		`SELECT request_id::text, approver_subject, decision, reason, decision_evidence_refs, decided_at
		   FROM access_change_request_decisions
		  WHERE tenant_id = $1
		    AND request_id = $2
		  ORDER BY decided_at, approver_subject`,
		tenantID, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessChangeDecision
	for rows.Next() {
		var d AccessChangeDecision
		if err := rows.Scan(&d.RequestID, &d.ApproverSubject, &d.Decision, &d.Reason, &d.DecisionEvidenceRefs, &d.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func scanAccessChangeRequest(row pgx.Row) (AccessChangeRequest, error) {
	var r AccessChangeRequest
	err := row.Scan(&r.TenantID, &r.ID, &r.RequestedAction, &r.RequesterSubject, &r.NHIID, &r.NHIKind,
		&r.DisplayName, &r.OwnerRef, &r.Resource, &r.Entitlement, &r.ChangeRef, &r.ChangeSystem,
		&r.ChangeURL, &r.Risk, &r.Reason, &r.EvidenceRefs, &r.Status, &r.RequiredApprovals,
		&r.ApprovalCount, &r.CreatedAt, &r.UpdatedAt, &r.CompletedAt)
	return r, err
}
