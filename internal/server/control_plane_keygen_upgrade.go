// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// controlPlaneKeygenUpgradeRetry spaces the retries of an upgrade pass that
// failed (a database or event-log outage at leader start).
const controlPlaneKeygenUpgradeRetry = time.Minute

// RunControlPlaneKeygenUpgrade decides every tenant that predates the
// control-plane key generation switch (owner decision 2026-10-24): a tenant
// already using a generator keeps it on, with its deprecation events still
// recorded, until it turns it off; any other tenant is turned off. It runs on
// the leader until one pass completes. Each decision is one
// tenant.control_plane_keygen.set event under a stable ID, so a retry or a
// second leader records nothing new. Until a tenant is decided it keeps the
// behavior it had before the switch.
func (s *Server) RunControlPlaneKeygenUpgrade(ctx context.Context) {
	if s.orch == nil || s.store == nil {
		return
	}
	for {
		decided, err := s.DecideControlPlaneKeygenForPreSwitchTenants(ctx)
		if err == nil {
			if s.logger != nil && decided > 0 {
				s.logger.Info("control-plane key generation decided for tenants that predate the switch", slog.Int("tenants", decided))
			}
			return
		}
		if s.logger != nil {
			s.logger.Warn("control-plane key generation upgrade incomplete; retrying", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(controlPlaneKeygenUpgradeRetry):
		}
	}
}

// DecideControlPlaneKeygenForPreSwitchTenants records one upgrade decision for
// each tenant without a decision and returns how many it decided. Exported for
// served-path tests.
func (s *Server) DecideControlPlaneKeygenForPreSwitchTenants(ctx context.Context) (int, error) {
	tenants, err := s.store.TenantsWithoutControlPlaneKeygenDecision(ctx)
	if err != nil {
		return 0, err
	}
	decided := 0
	for _, tenantID := range tenants {
		evidence, err := s.store.ControlPlaneKeygenEvidenceFor(ctx, tenantID)
		if err != nil {
			return decided, err
		}
		if evidence.DeprecationEvents, err = s.controlPlaneKeygenDeprecationEvents(ctx, tenantID); err != nil {
			return decided, err
		}
		evidence.WorkloadAPISocket = s.compatWorkloadAPISocketTenant() == tenantID
		reason := "predates the switch and never used control-plane key generation"
		if evidence.Used() {
			reason = "predates the switch and already used control-plane key generation; it stays on until the tenant turns it off"
		}
		if _, err := s.orch.SetControlPlaneKeygen(ctx, tenantID, projections.ControlPlaneKeygenSet{
			Enabled: evidence.Used(), Source: store.ControlPlaneKeygenSourceUpgrade, Reason: reason, Evidence: &evidence,
		}); err != nil {
			return decided, err
		}
		decided++
	}
	return decided, nil
}

// controlPlaneKeygenDeprecationEvents counts the tenant's retained records of
// a generator run. A compatibility socket record counts only for an X.509-SVID:
// a JWT-SVID generates no key.
func (s *Server) controlPlaneKeygenDeprecationEvents(ctx context.Context, tenantID string) (int64, error) {
	if s.log == nil {
		return 0, nil
	}
	var count int64
	err := s.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := s.log.LastSequence(readCtx)
		if err != nil || head == 0 {
			return err
		}
		return s.log.ReplayTenantTypesThrough(readCtx, tenantID, 1, head,
			[]string{"issuance.server_side_keygen", "spiffe.workload_api.local_socket_used"}, func(event events.Event) error {
				if event.Type == "spiffe.workload_api.local_socket_used" {
					var use struct {
						Type string `json:"type"`
					}
					if json.Unmarshal(event.Data, &use) != nil || use.Type != "x509" {
						return nil
					}
				}
				count++
				return nil
			})
	})
	return count, err
}

// compatWorkloadAPISocketTenant is the tenant the control plane's own Workload
// API socket issues X.509-SVIDs for, or "" when it serves no workloads.
func (s *Server) compatWorkloadAPISocketTenant() string {
	if s.protocols == nil || s.protocols.spiffe == nil || !s.protocols.spiffe.localWorkloadsServed {
		return ""
	}
	return s.protocols.spiffe.tenantID
}
