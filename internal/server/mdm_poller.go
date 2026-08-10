// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/mdmevidence"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// The MDM poller (epic I5): the producer the correlation surface never had.
//
// Every ingredient — parsers, endpoint builders, the correlated event, the
// served routes, the console panel — existed with nothing calling it, so the
// table the console reads was written only by tests. This leader-only ticker
// is the missing caller. The control plane commits an mdm.sync intent; a
// network relay performs the read, and the CORRELATION always happens here.

const (
	// mdmPollerInterval is detection latency for due schedules, matching the
	// CMDB scheduler's shape.
	mdmPollerInterval = time.Minute
	// agentJobKindMDMSync is the relay-executed MDM read (I5).
	agentJobKindMDMSync = "mdm.sync"
)

// MDMSyncReport is what a relay reports from one mdm.sync: parsed devices,
// never the raw response.
type MDMSyncReport struct {
	ObservedAt time.Time    `json:"observed_at"`
	MDM        string       `json:"mdm"`
	Devices    []mdm.Device `json:"devices"`
}

// RunMDMPoller is the leader-only ticker.
func (s *Server) RunMDMPoller(ctx context.Context) {
	if s.store == nil || s.orch == nil {
		return
	}
	sweep := func() {
		tenants, err := s.store.TenantsWithEnabledMDMPollSchedules(ctx)
		if err != nil {
			s.logger.Warn("mdm poller: list tenants failed", slog.String("error", err.Error()))
			return
		}
		for _, tenantID := range tenants {
			due, err := s.store.MDMPollSchedulesDue(ctx, tenantID, time.Now())
			if err != nil {
				continue
			}
			for _, sched := range due {
				// MDM reads are estate work. The brain commits an intent; a
				// network relay redeems the token and performs the call.
				s.dispatchMDMSyncJob(ctx, tenantID, sched)
			}
		}
	}
	sweep()
	tk := time.NewTicker(mdmPollerInterval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			sweep()
		}
	}
}

func (s *Server) enabledMDMSCEPProfileIDs(ctx context.Context, tenantID, provider string) ([]string, error) {
	policies, err := s.store.ListMDMSCEPPolicies(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("server: list MDM SCEP policies for certificate evidence: %w", err)
	}
	var profileIDs []string
	for _, policy := range policies {
		if policy.Enabled && policy.Provider == provider && strings.TrimSpace(policy.SCEPProfile) != "" {
			profileIDs = append(profileIDs, strings.TrimSpace(policy.SCEPProfile))
		}
	}
	return profileIDs, nil
}

// correlateMDMDevices is the correlation core. Production observations arrive
// from a relay; direct callers use this wrapper only to exercise the pure join.
// The join is EXACT serial-to-identity-name equality — a looser match would invent
// correlations, and an invented correlation sends an operator to the wrong
// laptop. Devices with no identity are still recorded: "a device the MDM
// manages that has no certificate" is one of the two gaps this surface exists
// to show.
func (s *Server) correlateMDMDevices(ctx context.Context, tenantID string, devices []mdm.Device) error {
	return s.correlateMDMRelayDevices(ctx, tenantID, "", devices)
}

func (s *Server) correlateMDMRelayDevices(ctx context.Context, tenantID, resultKey string, devices []mdm.Device) error {
	bySerial, err := s.store.IdentitiesBySerial(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, d := range devices {
		identityID := ""
		if join, ok := bySerial[strings.ToUpper(strings.TrimSpace(d.SerialNumber))]; ok {
			identityID = join.IdentityID
		}
		transactionID := ""
		installState := mdm.OutcomeUnknown
		installDetail := d.InstallDetail
		attempts, loadErr := mdmevidence.Load(ctx, s.log, tenantID, d.SerialNumber, "")
		if loadErr != nil {
			return loadErr
		}
		if len(attempts) > 0 {
			attempt := attempts[len(attempts)-1]
			transactionID = attempt.TransactionID
			installState, installDetail = mdm.EvaluateCertificateInstallation(d, attempt.CertificateSerial)
		} else if d.InstallObserved {
			installDetail = "The MDM returned certificate evidence for this device, but no immutable SCEP attempt with the exact device serial exists; verify the SCEP profile subject before correlating installation."
		}
		observed := d.ObservedAt
		ev := projections.MDMDeviceCorrelated{
			MDM: d.MDM, MDMDeviceID: d.MDMDeviceID, DeviceName: d.Name,
			SerialNumber: d.SerialNumber, TransactionID: transactionID, IdentityID: identityID,
			InstallState: string(installState), InstallDetail: installDetail,
		}
		if !observed.IsZero() {
			ev.ObservedAt = &observed
		}
		var correlateErr error
		if resultKey == "" {
			correlateErr = s.orch.CorrelateMDMDevice(ctx, tenantID, ev)
		} else {
			correlateErr = s.orch.CorrelateMDMDeviceFromRelay(ctx, tenantID, resultKey, ev)
		}
		if correlateErr != nil {
			return correlateErr
		}
	}
	return nil
}

// dispatchMDMSyncJob enqueues one relay-claimable read, one in flight per
// (tenant, mdm) — the same discipline as the CMDB dispatch and for the same
// reason: stacking identical reads behind an unclaimed job has the eventual
// relay replay a backlog.
func (s *Server) dispatchMDMSyncJob(ctx context.Context, tenantID string, sched store.MDMPollSchedule) {
	pending, err := s.store.HasPendingMDMSyncJob(ctx, tenantID, sched.MDM)
	if err != nil {
		s.logger.Warn("mdm relay dispatch: pending check failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	if pending {
		if err := s.store.MarkMDMPollRun(ctx, tenantID, sched.MDM, time.Now().UTC(),
			"a dispatched mdm.sync job is still waiting; if no network relay is enrolled and claiming, none will run it"); err != nil {
			s.logger.Warn("mdm relay dispatch: stamp failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		}
		return
	}
	profileIDs, err := s.enabledMDMSCEPProfileIDs(ctx, tenantID, sched.MDM)
	if err != nil {
		s.logger.Warn("mdm relay dispatch: profile evidence lookup failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	payload, err := json.Marshal(mdm.SyncIntent{
		MDM: sched.MDM, BaseURL: sched.BaseURL, Filter: sched.Filter, TokenRef: sched.TokenRef,
		SCEPProfileIDs: profileIDs,
	})
	if err != nil {
		return
	}
	key := "mdm-sync:" + tenantID + ":" + sched.MDM + ":" + time.Now().UTC().Format(time.RFC3339)
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:          tenantID,
			Destination:       agentJobKindMDMSync,
			IdempotencyKey:    key,
			Payload:           payload,
			RequiredAgentRole: mtls.AgentRoleNetwork,
		})
		return err
	})
	if err != nil {
		s.logger.Warn("mdm relay dispatch failed",
			slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		return
	}
	s.logger.Info("mdm sync dispatched to relay",
		slog.String("tenant_id", tenantID), slog.String("mdm", sched.MDM))
	if err := s.store.MarkMDMPollRun(ctx, tenantID, sched.MDM, time.Now().UTC(), ""); err != nil {
		s.logger.Warn("mdm relay dispatch: stamp failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
	}
}

// recordMDMSync ingests a relay's reported devices through the shared
// correlation core and stamps the schedule with the real outcome.
func (s *Server) recordMDMSync(ctx context.Context, tenantID, agentName, idempotencyKey string, jobPayload []byte, reportJSON string) error {
	var intent mdm.SyncIntent
	if err := json.Unmarshal(jobPayload, &intent); err != nil {
		return fmt.Errorf("server: decode durable MDM sync intent: %w", err)
	}
	if len(reportJSON) > maxStructuredSyncReportBytes {
		return fmt.Errorf("server: MDM relay report exceeds the %d-byte bound", maxStructuredSyncReportBytes)
	}
	var report MDMSyncReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		s.logger.Warn("mdm relay report: undecodable",
			slog.String("tenant_id", tenantID), slog.String("agent", agentName), slog.String("error", err.Error()))
		return fmt.Errorf("server: decode MDM relay report: %w", err)
	}
	if report.MDM != mdm.MDMIntune && report.MDM != mdm.MDMJamf {
		s.logger.Warn("mdm relay report: unknown mdm", slog.String("tenant_id", tenantID), slog.String("mdm", report.MDM))
		return fmt.Errorf("server: MDM relay report names unknown mdm %q", report.MDM)
	}
	if report.ObservedAt.IsZero() {
		return fmt.Errorf("server: MDM relay report has no observation time")
	}
	if report.MDM != intent.MDM {
		return fmt.Errorf("server: MDM relay report provider %q does not match durable intent %q", report.MDM, intent.MDM)
	}
	if len(report.Devices) > cmdbPageLimit {
		return fmt.Errorf("server: MDM relay report exceeds the %d-device bound", cmdbPageLimit)
	}
	msg := ""
	correlateErr := s.correlateMDMRelayDevices(ctx, tenantID, idempotencyKey, report.Devices)
	if correlateErr != nil {
		msg = correlateErr.Error()
		s.logger.Warn("mdm relay correlate failed", slog.String("tenant_id", tenantID), slog.String("error", msg))
	} else {
		s.logger.Info("mdm relay correlate complete", slog.String("tenant_id", tenantID),
			slog.String("agent", agentName), slog.Int("devices", len(report.Devices)))
	}
	if stampErr := s.store.MarkMDMPollRun(ctx, tenantID, report.MDM, time.Now().UTC(), msg); stampErr != nil {
		s.logger.Warn("mdm relay report: stamp failed", slog.String("tenant_id", tenantID), slog.String("error", stampErr.Error()))
		if correlateErr == nil {
			correlateErr = stampErr
		}
	}
	return correlateErr
}
