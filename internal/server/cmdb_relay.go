// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/store"
)

// Relay-executed CMDB sync (epic I2).
//
// The domain-joined relay sits inside the estate, claims a cmdb.sync job over
// its outbound channel, reads the one permitted table, and reports parsed
// records. The RECONCILE still happens here — the relay observes, the control
// plane decides — so the rule that a source never overwrites a human's
// attestation has exactly one implementation without giving the brain an
// estate HTTP or token path.

// agentJobKindCMDBSync is the relay-executed CMDB read (I2).
const agentJobKindCMDBSync = "cmdb.sync"

func cmdbSyncIntent(sched store.CMDBReconcileSchedule) ownership.CMDBSyncIntent {
	return ownership.CMDBSyncIntent{
		InstanceURL: sched.InstanceURL,
		CIQuery:     sched.CIQuery,
		TokenRef:    sched.TokenRef,
		PageLimit:   cmdbPageLimit,
	}
}

// CMDBSyncReport is what a relay reports back from one sync: the parsed
// records, never the raw response. Parsing on the relay bounds what travels
// and keeps a misbehaving instance's 50MB error page out of the report path.
type CMDBSyncReport struct {
	ObservedAt   time.Time          `json:"observed_at"`
	Records      []ownership.Record `json:"records"`
	Unattributed []string           `json:"unattributed,omitempty"`
}

// dispatchCMDBSyncJob enqueues one relay-claimable sync for a due schedule.
//
// One in flight per tenant: a pending job that nothing has claimed means no
// network relay is picking the work up, and stacking a second behind it would
// have the eventual relay replay a backlog of identical reads. The stamp on
// the schedule says which state the operator is in — dispatched-and-waiting is
// different from failing, and both are different from healthy.
func (s *Server) dispatchCMDBSyncJob(ctx context.Context, tenantID string, sched store.CMDBReconcileSchedule) {
	pending, err := s.store.HasPendingAgentJob(ctx, tenantID, agentJobKindCMDBSync)
	if err != nil {
		s.logger.Warn("cmdb relay dispatch: pending check failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	if pending {
		// The prior dispatch has not been claimed or has not reported. Say so
		// on the schedule rather than silently skipping: "waiting on a relay"
		// is the one state an operator can fix by enrolling one.
		if err := s.store.MarkCMDBScheduleRun(ctx, tenantID, time.Now().UTC(),
			"a dispatched cmdb.sync job is still waiting; if no network relay is enrolled and claiming, none will run it"); err != nil {
			s.logger.Warn("cmdb relay dispatch: stamp failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		}
		return
	}
	intent := cmdbSyncIntent(sched)
	payload, err := json.Marshal(intent)
	if err != nil {
		s.logger.Warn("cmdb relay dispatch: encode intent failed", slog.String("error", err.Error()))
		return
	}
	// The idempotency key carries the dispatch instant: each due tick that
	// actually dispatches creates one job, and the pending gate above is what
	// stops pileup — not key collision, which would silently swallow the
	// SECOND sync an operator expected after fixing their relay.
	key := "cmdb-sync:" + tenantID + ":" + time.Now().UTC().Format(time.RFC3339)
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    agentJobKindCMDBSync,
			IdempotencyKey: key,
			Payload:        payload,
			// NETWORK role demanded per row, like the kind-level vantage map
			// says: the read exists to happen from inside the segment.
			RequiredAgentRole: mtls.AgentRoleNetwork,
		})
		return err
	})
	if err != nil {
		s.logger.Warn("cmdb relay dispatch failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	s.logger.Info("cmdb sync dispatched to relay", slog.String("tenant_id", tenantID))
	if err := s.store.MarkCMDBScheduleRun(ctx, tenantID, time.Now().UTC(), ""); err != nil {
		s.logger.Warn("cmdb relay dispatch: stamp failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
	}
}

// recordCMDBSync ingests a relay's reported observation: the reconcile core
// runs here after the relay observation, and the schedule is stamped with the
// real outcome.
func (s *Server) recordCMDBSync(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	var intent ownership.CMDBSyncIntent
	if err := json.Unmarshal(jobPayload, &intent); err != nil {
		return fmt.Errorf("server: decode durable CMDB sync intent: %w", err)
	}
	if intent.PageLimit <= 0 || intent.PageLimit > cmdbPageLimit {
		return fmt.Errorf("server: durable CMDB sync intent is outside its page bound")
	}
	if _, err := ownership.CMDBEndpoint(intent.InstanceURL, intent.CIQuery, intent.PageLimit); err != nil {
		return fmt.Errorf("server: validate durable CMDB sync intent: %w", err)
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return fmt.Errorf("server: CMDB relay report exceeds the %d-byte bound", maxStructuredSyncReportBytes)
	}
	var report CMDBSyncReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		s.logger.Warn("cmdb relay report: undecodable",
			slog.String("tenant_id", tenantID), slog.String("agent", agentName), slog.String("error", err.Error()))
		_ = s.store.MarkCMDBScheduleRun(ctx, tenantID, time.Now().UTC(),
			"a relay reported a cmdb.sync result this control plane could not decode")
		return fmt.Errorf("server: decode CMDB relay report: %w", err)
	}
	if report.ObservedAt.IsZero() || len(report.Records) > cmdbPageLimit || len(report.Unattributed) > cmdbPageLimit {
		return fmt.Errorf("server: CMDB relay report is outside its observation or record bound")
	}
	res, err := s.reconcileCMDBRecords(ctx, tenantID, idempotencyKey, report.ObservedAt, report.Records, report.Unattributed)
	msg := ""
	if err != nil {
		msg = err.Error()
		s.logger.Warn("cmdb relay reconcile failed",
			slog.String("tenant_id", tenantID), slog.String("error", msg))
	} else {
		s.logger.Info("cmdb relay reconcile complete",
			slog.String("tenant_id", tenantID), slog.String("agent", agentName),
			slog.Int("read", res.Read), slog.Int("applied", res.Applied),
			slog.Int("conflicts", res.Conflicts), slog.Int("unattributed", len(res.Unattributed)))
	}
	if err := s.store.MarkCMDBScheduleRun(ctx, tenantID, time.Now().UTC(), msg); err != nil {
		s.logger.Warn("cmdb relay report: stamp failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
	}
	return err
}
