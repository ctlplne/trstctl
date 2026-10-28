// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

var ErrSSHTrustFleetNotFound = errors.New("store: SSH trust fleet rollout not found")

type SSHTrustFleetRollout struct {
	TenantID          string               `json:"tenant_id"`
	ID                string               `json:"id"`
	Plan              sshtrustrollout.Plan `json:"plan"`
	PlanDigest        string               `json:"plan_digest"`
	ApprovalRequestID string               `json:"approval_request_id"`
	Requester         string               `json:"requester"`
	State             string               `json:"state"`
	WindowExpired     bool                 `json:"window_expired"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
	Hosts             []SSHTrustFleetHost  `json:"hosts"`
}

type SSHTrustFleetHost struct {
	AgentID        string                  `json:"agent_id"`
	State          string                  `json:"state"`
	SkipReason     string                  `json:"skip_reason,omitempty"`
	Receipt        *sshtrustrollout.Report `json:"receipt,omitempty"`
	ReceiptEventID string                  `json:"receipt_event_id,omitempty"`
	JobID          *int64                  `json:"job_id,omitempty"`
	Attempt        *int                    `json:"attempt,omitempty"`
	CheckedAt      *time.Time              `json:"checked_at,omitempty"`
}

// ApplySSHTrustFleetStartedTx is called only by the immutable event projector.
func (s *Store) ApplySSHTrustFleetStartedTx(ctx context.Context, tx pgx.Tx, r SSHTrustFleetRollout, at time.Time, seq uint64) error {
	// Reviewer metadata belongs to the cataloged immutable source. This index
	// stores only the public effect and a tenant-bound requester reference, so
	// snapshots never duplicate personal name/reason/identity text. Served reads
	// restore that metadata from the matching source (including privacy rewrites).
	effect := r.Plan
	effect.Name, effect.Reason = "", ""
	requesterRef := privacy.SubjectRef(r.TenantID, r.Requester)
	raw, err := json.Marshal(effect)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO ssh_trust_fleet_rollouts (tenant_id,id,plan,plan_digest,approval_request_id,requester,created_at,updated_at,event_sequence)
 VALUES($1,$2,$3::jsonb,$4,$5,$6,$7,$7,$8) ON CONFLICT(tenant_id,id) DO NOTHING`, r.TenantID, r.ID, raw, r.PlanDigest, r.ApprovalRequestID, requesterRef, at, seq)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	for position, h := range r.Plan.Hosts {
		state := "queued"
		if h.State == "skipped" {
			state = "skipped"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ssh_trust_fleet_hosts(tenant_id,rollout_id,agent_id,position,readiness_digest,state,skip_reason,event_sequence)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.TenantID, r.ID, h.AgentID, position, h.ReadinessDigest, state, h.Reason, seq); err != nil {
			return err
		}
	}
	return nil
}

// ApplySSHTrustFleetObservedTx applies only the exact claimed host/plan. The
// immutable per-attempt source fence rejects conflicting duplicate facts before
// this projection runs; an older attempt cannot overwrite a newer observation.
func (s *Store) ApplySSHTrustFleetObservedTx(ctx context.Context, tx pgx.Tx, tenantID, eventID string, jobID int64, attempt int, report sshtrustrollout.Report, evidenceDigest string, at time.Time, seq uint64) error {
	var digest string
	var planRaw []byte
	if err := tx.QueryRow(ctx, `SELECT plan_digest,plan FROM ssh_trust_fleet_rollouts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, report.RolloutID).Scan(&digest, &planRaw); err != nil {
		return err
	}
	if digest != report.PlanDigest {
		return errors.New("SSH trust receipt names a different reviewed plan")
	}
	var plan sshtrustrollout.Plan
	if err := json.Unmarshal(planRaw, &plan); err != nil {
		return err
	}
	var bound *sshtrustrollout.Host
	for i := range plan.Hosts {
		if plan.Hosts[i].AgentID == report.AgentID {
			bound = &plan.Hosts[i]
			break
		}
	}
	if bound == nil || bound.State != "ready" {
		return errors.New("SSH trust receipt names no approved ready host")
	}
	command := sshtrustrollout.Command{RolloutID: report.RolloutID, AgentID: report.AgentID, PublicCAKey: plan.PublicCAKey, CAFingerprint: plan.CAFingerprint, PlanDigest: digest, ReadinessDigest: bound.ReadinessDigest, ExpiresAt: plan.ExpiresAt}
	if err := report.Validate(command, evidenceDigest); err != nil {
		return err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE ssh_trust_fleet_hosts SET state=$4,receipt=$5::jsonb,receipt_event_id=$6,job_id=$7,attempt=$8,checked_at=$9,event_sequence=$10
 WHERE tenant_id=$1 AND rollout_id=$2 AND agent_id=$3 AND state<>'skipped' AND readiness_digest=$11
 AND (attempt IS NULL OR attempt<$8) AND event_sequence<$10`, tenantID, report.RolloutID, report.AgentID, report.State, raw, eventID, jobID, attempt, report.CheckedAt, seq, report.ReadinessDigest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ssh_trust_fleet_hosts WHERE tenant_id=$1 AND rollout_id=$2 AND agent_id=$3 AND state<>'skipped' AND readiness_digest=$4)`, tenantID, report.RolloutID, report.AgentID, report.ReadinessDigest).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errors.New("SSH trust receipt names no dispatched host policy")
		}
	}
	_, err = tx.Exec(ctx, `UPDATE ssh_trust_fleet_rollouts SET updated_at=$3,event_sequence=$4 WHERE tenant_id=$1 AND id=$2 AND event_sequence<$4`, tenantID, report.RolloutID, at, seq)
	return err
}

func (s *Store) GetSSHTrustFleetRollout(ctx context.Context, tenantID, id string) (SSHTrustFleetRollout, error) {
	var r SSHTrustFleetRollout
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT id::text,plan,plan_digest,approval_request_id::text,requester,created_at,updated_at FROM ssh_trust_fleet_rollouts WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&r.ID, &raw, &r.PlanDigest, &r.ApprovalRequestID, &r.Requester, &r.CreatedAt, &r.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSSHTrustFleetNotFound
		}
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &r.Plan); err != nil {
			return err
		}
		r.TenantID = tenantID
		r.Hosts = []SSHTrustFleetHost{}
		rows, err := tx.Query(ctx, `SELECT agent_id::text,state,skip_reason,receipt,coalesce(receipt_event_id::text,''),job_id,attempt,checked_at FROM ssh_trust_fleet_hosts WHERE tenant_id=$1 AND rollout_id=$2 ORDER BY position`, tenantID, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		ready, verified, failed := 0, 0, false
		queued := false
		for rows.Next() {
			var h SSHTrustFleetHost
			var receipt []byte
			if err := rows.Scan(&h.AgentID, &h.State, &h.SkipReason, &receipt, &h.ReceiptEventID, &h.JobID, &h.Attempt, &h.CheckedAt); err != nil {
				return err
			}
			if len(receipt) > 0 {
				if err = json.Unmarshal(receipt, &h.Receipt); err != nil {
					return err
				}
			}
			if h.State != "skipped" {
				ready++
			}
			if h.State == "queued" {
				queued = true
			}
			if h.State == "verified" {
				verified++
			}
			if h.State == "failed" || h.State == "refused" {
				failed = true
			}
			r.Hosts = append(r.Hosts, h)
		}
		r.State = "pending"
		if ready > 0 && verified == ready {
			r.State = "verified"
		}
		if failed {
			r.State = "attention_required"
		}
		r.WindowExpired = queued && !time.Now().UTC().Before(r.Plan.ExpiresAt)
		if r.WindowExpired {
			r.State = "execution_window_expired"
		}
		return rows.Err()
	})
	return r, err
}

// ListSSHTrustFleetRolloutIDs is a stable keyset page; read each selected
// tenant-bound ID through GetSSHTrustFleetRollout for host receipts.
func (s *Store) ListSSHTrustFleetRolloutIDs(ctx context.Context, tenantID string, afterCreatedAt *time.Time, afterID string, limit int) ([]string, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("SSH trust rollout page size must be between one and 100")
	}
	if afterID == "" {
		afterID = "00000000-0000-0000-0000-000000000000"
	}
	ids := []string{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text FROM ssh_trust_fleet_rollouts WHERE tenant_id=$1 AND ($2::timestamptz IS NULL OR created_at<$2 OR(created_at=$2 AND id<$3::uuid)) ORDER BY created_at DESC,id DESC LIMIT $4`, tenantID, afterCreatedAt, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}
