// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// The MDM poller (epic I5): the producer the correlation surface never had.
//
// Every ingredient — parsers, endpoint builders, the correlated event, the
// served routes, the console panel — existed with nothing calling it, so the
// table the console reads was written only by tests. This leader-only ticker
// is the missing caller. Like the CMDB scheduler beside it, the fetch can run
// from the control plane or be dispatched to a network relay (mdm.sync); the
// CORRELATION always happens here.

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
	MDM     string       `json:"mdm"`
	Devices []mdm.Device `json:"devices"`
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
				if sched.Execution == "relay" {
					s.dispatchMDMSyncJob(ctx, tenantID, sched)
					continue
				}
				s.runMDMPollOnce(ctx, tenantID, sched)
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

// runMDMPollOnce fetches one MDM from the control plane and correlates.
func (s *Server) runMDMPollOnce(ctx context.Context, tenantID string, sched store.MDMPollSchedule) {
	devices, err := s.fetchMDMDevices(ctx, sched)
	msg := ""
	if err != nil {
		msg = err.Error()
		s.logger.Warn("mdm poll failed", slog.String("tenant_id", tenantID),
			slog.String("mdm", sched.MDM), slog.String("error", msg))
	} else if err := s.correlateMDMDevices(ctx, tenantID, devices); err != nil {
		msg = err.Error()
		s.logger.Warn("mdm correlate failed", slog.String("tenant_id", tenantID),
			slog.String("mdm", sched.MDM), slog.String("error", msg))
	} else {
		s.logger.Info("mdm poll complete", slog.String("tenant_id", tenantID),
			slog.String("mdm", sched.MDM), slog.Int("devices", len(devices)))
	}
	if err := s.store.MarkMDMPollRun(ctx, tenantID, sched.MDM, time.Now().UTC(), msg); err != nil {
		s.logger.Warn("mdm poller: stamp failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
	}
}

// fetchMDMDevices performs the read. GET only, against the fixed endpoint the
// builders in internal/mdm construct — the same builders the relay uses.
func (s *Server) fetchMDMDevices(ctx context.Context, sched store.MDMPollSchedule) ([]mdm.Device, error) {
	var endpoint string
	var err error
	switch sched.MDM {
	case mdm.MDMIntune:
		endpoint, err = mdm.IntuneDevicesEndpoint(sched.BaseURL, sched.Filter)
	case mdm.MDMJamf:
		endpoint, err = mdm.JamfDevicesEndpoint(sched.BaseURL, sched.Filter)
	default:
		return nil, fmt.Errorf("server: unknown mdm %q", sched.MDM)
	}
	if err != nil {
		return nil, err
	}
	client, err := cloudHTTPClient(endpoint, sched.AllowPrivateEndpoint, sched.PrivateEgressCIDRs)
	if err != nil {
		return nil, fmt.Errorf("server: MDM endpoint rejected: %w", err)
	}
	token, err := resolveDiscoveryCredentialRef(ctx, sched.TokenRef)
	if err != nil {
		return nil, fmt.Errorf("server: resolve MDM token ref: %w", err)
	}
	tokenBytes := []byte(token)
	defer secret.Wipe(tokenBytes)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", tokenBytes))
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server: read MDM: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("server: MDM read failed with status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	switch sched.MDM {
	case mdm.MDMIntune:
		return mdm.ParseIntuneDevices(resp.Body)
	default:
		return mdm.ParseJamfDevices(resp.Body)
	}
}

// correlateMDMDevices is the correlation core, shared by BOTH vantages: the
// control-plane poll above and a relay's reported observation. The join is
// EXACT serial-to-identity-name equality — a looser match would invent
// correlations, and an invented correlation sends an operator to the wrong
// laptop. Devices with no identity are still recorded: "a device the MDM
// manages that has no certificate" is one of the two gaps this surface exists
// to show.
func (s *Server) correlateMDMDevices(ctx context.Context, tenantID string, devices []mdm.Device) error {
	bySerial, err := s.store.IdentitiesBySerial(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, d := range devices {
		identityID := ""
		if join, ok := bySerial[strings.ToUpper(strings.TrimSpace(d.SerialNumber))]; ok {
			identityID = join.IdentityID
		}
		observed := d.ObservedAt
		ev := projections.MDMDeviceCorrelated{
			MDM: d.MDM, MDMDeviceID: d.MDMDeviceID, DeviceName: d.Name,
			SerialNumber: d.SerialNumber, IdentityID: identityID,
			InstallState: string(d.InstallState), InstallDetail: d.InstallDetail,
		}
		if !observed.IsZero() {
			ev.ObservedAt = &observed
		}
		if err := s.orch.CorrelateMDMDevice(ctx, tenantID, ev); err != nil {
			return err
		}
	}
	return nil
}

// dispatchMDMSyncJob enqueues one relay-claimable read, one in flight per
// (tenant, mdm) — the same discipline as the CMDB dispatch and for the same
// reason: stacking identical reads behind an unclaimed job has the eventual
// relay replay a backlog.
func (s *Server) dispatchMDMSyncJob(ctx context.Context, tenantID string, sched store.MDMPollSchedule) {
	pending, err := s.store.HasPendingAgentJob(ctx, tenantID, agentJobKindMDMSync)
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
	payload, err := json.Marshal(mdm.SyncIntent{
		MDM: sched.MDM, BaseURL: sched.BaseURL, Filter: sched.Filter, TokenRef: sched.TokenRef,
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
func (s *Server) recordMDMSync(ctx context.Context, tenantID, agentName, _ string, reportJSON string) {
	var report MDMSyncReport
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		s.logger.Warn("mdm relay report: undecodable",
			slog.String("tenant_id", tenantID), slog.String("agent", agentName), slog.String("error", err.Error()))
		return
	}
	if report.MDM != mdm.MDMIntune && report.MDM != mdm.MDMJamf {
		s.logger.Warn("mdm relay report: unknown mdm", slog.String("tenant_id", tenantID), slog.String("mdm", report.MDM))
		return
	}
	msg := ""
	if err := s.correlateMDMDevices(ctx, tenantID, report.Devices); err != nil {
		msg = err.Error()
		s.logger.Warn("mdm relay correlate failed", slog.String("tenant_id", tenantID), slog.String("error", msg))
	} else {
		s.logger.Info("mdm relay correlate complete", slog.String("tenant_id", tenantID),
			slog.String("agent", agentName), slog.Int("devices", len(report.Devices)))
	}
	if err := s.store.MarkMDMPollRun(ctx, tenantID, report.MDM, time.Now().UTC(), msg); err != nil {
		s.logger.Warn("mdm relay report: stamp failed", slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
	}
}
