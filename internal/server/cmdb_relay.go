// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/ownership"
	"trstctl.com/trstctl/internal/projections"
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
		InstanceURL: sched.InstanceURL, CIQuery: sched.CIQuery, TokenRef: sched.TokenRef,
		PageLimit: cmdbPageLimit, SweepID: sched.CurrentSweepID,
		AfterSysID: sched.AfterSysID, ReadCount: sched.ReadCount, ExpectedCount: sched.ExpectedCount,
	}
}

// CMDBSyncReport is what a relay reports back from one sync: the parsed
// records, never the raw response. Parsing on the relay bounds what travels
// and keeps a misbehaving instance's 50MB error page out of the report path.
type CMDBSyncReport = ownership.CMDBSyncReport

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
		// Waiting is visible as incomplete coverage plus last_attempt_at. It is
		// not a run, and therefore must never manufacture last_run_at success.
		return
	}
	intent := cmdbSyncIntent(sched)
	now := time.Now().UTC()
	if intent.SweepID != "" && !sched.CoverageComplete {
		// Restart recovery: re-derive the exact missing page command from the
		// durable checkpoint. EnqueueIfAbsent makes this harmless when the row
		// merely has not been claimed yet.
		err = s.orch.ResumeCMDBSweep(ctx, tenantID, intent)
	} else {
		intent.SweepID = uuid.NewString()
		intent.AfterSysID = ""
		intent.ReadCount = 0
		intent.ExpectedCount = nil
		err = s.orch.QueueCMDBSweep(ctx, tenantID, intent, now)
	}
	if err != nil {
		s.logger.Warn("cmdb relay dispatch failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	s.logger.Info("cmdb sync dispatched to relay", slog.String("tenant_id", tenantID))
}

// recordCMDBSync ingests a relay's reported observation: the reconcile core
// runs here after the relay observation, and the schedule is stamped with the
// real outcome.
func (s *Server) recordCMDBSync(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	return s.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		return s.recordCMDBSyncLocked(lockCtx, tenantID, agentName, idempotencyKey, jobPayload, reportJSON)
	})
}

func (s *Server) recordCMDBSyncLocked(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	var intent ownership.CMDBSyncIntent
	if err := json.Unmarshal(jobPayload, &intent); err != nil {
		return fmt.Errorf("server: decode durable CMDB sync intent: %w", err)
	}
	if intent.PageLimit <= 0 || intent.PageLimit > cmdbPageLimit || intent.SweepID == "" || intent.ReadCount < 0 {
		return fmt.Errorf("server: durable CMDB sync intent is outside its page bound")
	}
	if _, err := ownership.CMDBPageEndpoint(intent.InstanceURL, intent.CIQuery, intent.PageLimit, intent.AfterSysID); err != nil {
		return fmt.Errorf("server: validate durable CMDB sync intent: %w", err)
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return fmt.Errorf("server: CMDB relay report exceeds the %d-byte bound", maxStructuredSyncReportBytes)
	}
	var report ownership.CMDBSyncReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		s.logger.Warn("cmdb relay report: undecodable",
			slog.String("tenant_id", tenantID), slog.String("agent", agentName), slog.String("error", err.Error()))
		return fmt.Errorf("server: decode CMDB relay report: %w", err)
	}
	if err := validateCMDBSyncReport(intent, report); err != nil {
		return err
	}
	schedule, found, err := s.store.GetCMDBReconcileSchedule(ctx, tenantID)
	if err != nil {
		return err
	}
	nextCursor := intent.AfterSysID
	if len(report.SourceRefs) > 0 {
		nextCursor = report.SourceRefs[len(report.SourceRefs)-1]
	}
	currentPage := found && !schedule.CoverageComplete && schedule.CurrentSweepID == intent.SweepID &&
		schedule.AfterSysID == intent.AfterSysID && schedule.ReadCount == intent.ReadCount
	committedReplay := found && schedule.CurrentSweepID == intent.SweepID &&
		schedule.ReadCount >= report.ReadCount && schedule.AfterSysID >= nextCursor &&
		(schedule.ReadCount > intent.ReadCount || schedule.CoverageComplete)
	if !currentPage && !committedReplay {
		return fmt.Errorf("server: CMDB relay report does not match the current checkpoint")
	}
	res := CMDBReconcileResult{}
	observations := make([]projections.CMDBCIObservation, 0, len(report.SourceRefs))
	if committedReplay {
		stored, err := s.store.CMDBCIObservationsByRefs(ctx, tenantID, report.SourceRefs)
		if err != nil {
			return err
		}
		for _, observation := range stored {
			observations = append(observations, projections.CMDBCIObservation{
				SourceRef: observation.SourceRef, OwnerID: observation.OwnerID,
				ApplicationID: observation.ApplicationID, Service: observation.Service,
				BusinessUnit: observation.BusinessUnit, Environment: observation.Environment,
			})
			if observation.OwnerID == "" {
				res.Unattributed = append(res.Unattributed, observation.SourceRef)
			}
		}
	} else {
		res, err = s.reconcileCMDBRecords(ctx, tenantID, idempotencyKey, report.ObservedAt, report.Records, report.Unattributed)
		if err != nil {
			s.logger.Warn("cmdb relay reconcile failed",
				slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
			return err
		}
		byRef := make(map[string]projections.CMDBCIObservation, len(res.Observations))
		for _, observation := range res.Observations {
			byRef[observation.SourceRef] = observation
		}
		for _, sourceRef := range report.SourceRefs {
			observation := byRef[sourceRef]
			observation.SourceRef = sourceRef
			observations = append(observations, observation)
		}
	}
	var next *ownership.CMDBSyncIntent
	if !report.Complete {
		continued := intent
		continued.AfterSysID = report.SourceRefs[len(report.SourceRefs)-1]
		continued.ReadCount = report.ReadCount
		continued.ExpectedCount = report.ExpectedCount
		next = &continued
	}
	if err := s.orch.RecordCMDBSweepPage(ctx, tenantID, idempotencyKey, projections.CMDBSweepPageObserved{
		Intent: intent, ObservedAt: report.ObservedAt, Observations: observations,
		ReadCount: report.ReadCount, ExpectedCount: report.ExpectedCount, Complete: report.Complete,
		Unattributed: len(res.Unattributed), NextIntent: next,
	}); err != nil {
		return err
	}
	s.logger.Info("cmdb relay page committed",
		slog.String("tenant_id", tenantID), slog.String("agent", agentName),
		slog.String("sweep_id", intent.SweepID), slog.Int("read", res.Read),
		slog.Int("applied", res.Applied), slog.Int("conflicts", res.Conflicts),
		slog.Bool("complete", report.Complete))
	return nil
}

func validateCMDBSyncReport(intent ownership.CMDBSyncIntent, report ownership.CMDBSyncReport) error {
	if report.ObservedAt.IsZero() || report.SweepID != intent.SweepID || report.AfterSysID != intent.AfterSysID ||
		len(report.SourceRefs) > intent.PageLimit || len(report.Records) > intent.PageLimit ||
		len(report.Unattributed) > intent.PageLimit || report.ReadCount != intent.ReadCount+len(report.SourceRefs) ||
		len(report.SourceRefs) != len(report.Records)+len(report.Unattributed) ||
		(report.Complete && len(report.SourceRefs) >= intent.PageLimit) ||
		(!report.Complete && len(report.SourceRefs) != intent.PageLimit) {
		return fmt.Errorf("server: CMDB relay report is outside its observation or record bound")
	}
	previous := intent.AfterSysID
	refSet := make(map[string]bool, len(report.SourceRefs))
	recordRefs := make(map[string]bool, len(report.Records))
	for _, sourceRef := range report.SourceRefs {
		if !ownership.ValidCMDBSourceRef(sourceRef) || (previous != "" && sourceRef <= previous) || refSet[sourceRef] {
			return fmt.Errorf("server: CMDB relay report source refs are not a strict continuation")
		}
		refSet[sourceRef] = true
		previous = sourceRef
	}
	for _, record := range report.Records {
		if record.SourceRef == "" || !refSet[record.SourceRef] || recordRefs[record.SourceRef] {
			return fmt.Errorf("server: CMDB ownership record is not bound to an observed source ref")
		}
		recordRefs[record.SourceRef] = true
	}
	if report.ExpectedCount != nil && *report.ExpectedCount < report.ReadCount {
		return fmt.Errorf("server: CMDB expected count is behind the observed read count")
	}
	return nil
}

func (s *Server) recordCMDBSyncFailure(
	ctx context.Context,
	tenantID, idempotencyKey string,
	payload []byte,
	attempt int, failedAt time.Time,
	detail string,
) error {
	var intent ownership.CMDBSyncIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return fmt.Errorf("server: decode failed CMDB sync intent: %w", err)
	}
	return s.orch.RecordCMDBSweepFailure(ctx, tenantID, idempotencyKey, attempt, intent, failedAt, detail)
}
