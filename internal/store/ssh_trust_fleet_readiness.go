// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/sshtrustrollout"
)

// SSHTrustFleetHostTx reads one tenant-scoped enrolled host's current census.
// The receiver attributed that census to the verified peer. It never replaces
// the host's own opt-in check when a command actually arrives.
func (s *Store) SSHTrustFleetHostTx(ctx context.Context, tx pgx.Tx, tenantID, agentID, candidateFP string, now time.Time) (sshtrustrollout.Host, error) {
	host := sshtrustrollout.Host{AgentID: agentID, State: "skipped", Reason: "not_reported"}
	var roles []string
	var raw []byte
	var reported, offboarded *time.Time
	err := tx.QueryRow(ctx, `SELECT roles,executors,executors_reported_at,offboarded_at FROM agents WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenantID, agentID).Scan(&roles, &raw, &reported, &offboarded)
	if errors.Is(err, pgx.ErrNoRows) {
		return host, nil
	}
	if err != nil {
		return host, err
	}
	if offboarded != nil {
		host.Reason = "disabled"
		return host, nil
	}
	if !slices.Contains(roles, "host") {
		host.Reason = "not_host_role"
		return host, nil
	}
	if reported == nil || len(raw) == 0 {
		return host, nil
	}
	if now.Sub(*reported) > sshtrustrollout.ReadinessMaxAge || reported.After(now.Add(time.Minute)) {
		host.Reason = "stale"
		return host, nil
	}
	var census struct {
		SSHTrust           *sshtrustrollout.Readiness `json:"ssh_trust,omitempty"`
		PendingReportError string                     `json:"pending_report_error,omitempty"`
	}
	if err := json.Unmarshal(raw, &census); err != nil {
		return host, err
	}
	if census.PendingReportError != "" {
		host.Reason = "claims_paused"
		return host, nil
	}
	if census.SSHTrust == nil {
		return host, nil
	}
	readiness := *census.SSHTrust
	if !readiness.Ready() {
		host.Reason = readiness.State()
		return host, nil
	}
	if readiness.CAFingerprint != candidateFP {
		host.Reason = "ca_not_staged"
		return host, nil
	}
	host.State = "ready"
	host.Reason = ""
	host.ReadinessDigest = readiness.PolicyDigest
	return host, nil
}

// ValidateSSHTrustFleetReadyTx is the pre-append fence. A host that became
// ready after review stays skipped; the authorized ready subset cannot expand.
func (s *Store) ValidateSSHTrustFleetReadyTx(ctx context.Context, tx pgx.Tx, tenantID string, plan sshtrustrollout.Plan, now time.Time) error {
	if err := plan.ExecutionWindow(now); err != nil {
		return err
	}
	for _, reviewed := range plan.Hosts {
		if reviewed.State != "ready" {
			continue
		}
		current, err := s.SSHTrustFleetHostTx(ctx, tx, tenantID, reviewed.AgentID, plan.CAFingerprint, now)
		if err != nil {
			return err
		}
		if current.State != "ready" || current.ReadinessDigest != reviewed.ReadinessDigest {
			return fmt.Errorf("%w: an SSH host's opt-in, CA pin or readiness changed after review; preview again", ErrApprovalDrifted)
		}
	}
	return nil
}
