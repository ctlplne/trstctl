// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// N9-L2: check-in waves on the server side: the same schedule route, relay
// readiness and device checks as one check-in, with one approval naming the
// exact set of devices.

var _ api.MDMCheckInWaveService = (*Server)(nil)

// mdmCheckInWaveResourceID names one set of devices at one MDM; the set is
// canonical (unique and sorted), so the same devices name the same wave.
func mdmCheckInWaveResourceID(provider string, deviceIDs []string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("mdm-check-in-wave\x00"+provider+"\x00"+strings.Join(deviceIDs, "\x00"))).String()
}

// mdmCheckInWaveDevices reads each device as trstctl last read it from that MDM.
func (s *Server) mdmCheckInWaveDevices(ctx context.Context, tenantID, provider string, deviceIDs []string) ([]store.MDMDeviceCorrelation, error) {
	out := make([]store.MDMDeviceCorrelation, 0, len(deviceIDs))
	for _, id := range deviceIDs {
		device, err := s.mdmCheckInDevice(ctx, tenantID, provider, id)
		if err != nil {
			return nil, fmt.Errorf("%w (%s)", err, id)
		}
		out = append(out, device)
	}
	return out, nil
}

// RequestMDMCheckInWaveApproval asks reviewers to approve one wave: every
// device it names, each one trstctl has read from that MDM.
func (s *Server) RequestMDMCheckInWaveApproval(ctx context.Context, tenantID, requester, provider string,
	input api.MDMCheckInWaveRequest) (api.MDMCheckInWaveApproval, error) {
	deviceIDs, err := api.CanonicalMDMWaveDevices(input.DeviceIDs)
	if err != nil {
		return api.MDMCheckInWaveApproval{}, err
	}
	sched, err := s.mdmCheckInRoute(ctx, tenantID, provider)
	if err != nil {
		return api.MDMCheckInWaveApproval{}, err
	}
	readiness, err := s.orch.DiscoveryNetworkRelayReadinessForJob(ctx, tenantID, sched.RequiredAgentID, relay.KindMDMCheckIn)
	if err != nil {
		return api.MDMCheckInWaveApproval{}, err
	}
	if !readiness.Ready {
		return api.MDMCheckInWaveApproval{}, fmt.Errorf("%w (%s)", api.ErrMDMCheckInUnavailable, readiness.ConnectionOrigin)
	}
	devices, err := s.mdmCheckInWaveDevices(ctx, tenantID, provider, deviceIDs)
	if err != nil {
		return api.MDMCheckInWaveApproval{}, err
	}
	required := s.mdmCheckInApprovals
	if required <= 0 {
		required = defaultRequiredApprovals
	}
	refs := make([]string, 0, len(deviceIDs))
	views := make([]api.MDMCheckInWaveDevice, 0, len(devices))
	for _, d := range devices {
		refs = append(refs, "mdm-device:"+provider+":"+d.MDMDeviceID)
		views = append(views, api.MDMCheckInWaveDevice{DeviceID: d.MDMDeviceID, DeviceName: d.DeviceName})
	}
	request, err := s.orch.EnsureOperationApprovalRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "mdm_check_in_wave", ResourceID: mdmCheckInWaveResourceID(provider, deviceIDs),
		ResourceName: fmt.Sprintf("%s check-in wave of %d devices", provider, len(deviceIDs)),
		Action:       "check_in", Requester: requester, FromState: "managed", ToState: "check_in_requested", TargetVersion: 1,
		Reason: input.Reason, EvidenceRefs: refs, RequiredApprovals: required, TTL: mdmCheckInApprovalTTL,
	})
	if err != nil {
		return api.MDMCheckInWaveApproval{}, err
	}
	return api.MDMCheckInWaveApproval{MDM: provider, Devices: views, Reason: input.Reason,
		ApprovalRequestID: request.ID, ApprovalIntentDigest: request.IntentDigest, Status: request.Status,
		RequiredApprovals: request.RequiredApprovals, ApprovalCount: request.ApprovalCount, ExpiresAt: request.ExpiresAt}, nil
}

// QueueMDMCheckInWave executes an approved wave: one check-in and relay job
// per device the approval names, spending the approval once. Executing it
// again returns the same wave.
func (s *Server) QueueMDMCheckInWave(ctx context.Context, tenantID, requester, provider string,
	input api.MDMCheckInWaveStart) (store.MDMCheckInWave, error) {
	deviceIDs, err := api.CanonicalMDMWaveDevices(input.DeviceIDs)
	if err != nil {
		return store.MDMCheckInWave{}, err
	}
	sched, err := s.mdmCheckInRoute(ctx, tenantID, provider)
	if err != nil {
		return store.MDMCheckInWave{}, err
	}
	id, err := uuid.Parse(strings.TrimSpace(input.ApprovalRequestID))
	if err != nil || id == uuid.Nil {
		return store.MDMCheckInWave{}, store.ErrApprovalRequestNotFound
	}
	request, err := s.store.GetOperationApproval(ctx, tenantID, id.String())
	if err != nil {
		return store.MDMCheckInWave{}, err
	}
	if request.IntentDigest != input.ApprovalIntentDigest || request.Requester != requester || request.ResourceKind != "mdm_check_in_wave" ||
		request.ResourceID != mdmCheckInWaveResourceID(provider, deviceIDs) || request.Action != "check_in" {
		return store.MDMCheckInWave{}, store.ErrApprovalDigestMismatch
	}
	waveID := orchestrator.MDMCheckInWaveID(tenantID, request.ID)
	if existing, err := s.store.GetMDMCheckInWave(ctx, tenantID, waveID); err == nil {
		return existing, nil
	} else if !errors.Is(err, store.ErrMDMCheckInWaveNotFound) {
		return store.MDMCheckInWave{}, err
	}
	devices, err := s.mdmCheckInWaveDevices(ctx, tenantID, provider, deviceIDs)
	if err != nil {
		return store.MDMCheckInWave{}, err
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		return store.MDMCheckInWave{}, err
	}
	queued := projections.MDMCheckInWaveQueued{ID: waveID, MDM: provider, RelayAgentID: sched.RequiredAgentID, Approval: use}
	intents := make([]relay.MDMCheckInIntent, 0, len(devices))
	for _, d := range devices {
		checkInID := orchestrator.MDMCheckInWaveCheckInID(tenantID, request.ID, d.MDMDeviceID)
		queued.Devices = append(queued.Devices, projections.MDMCheckInWaveDevice{CheckInID: checkInID, DeviceID: d.MDMDeviceID, DeviceName: d.DeviceName})
		intent := relay.MDMCheckInIntent{ID: checkInID, MDM: provider, BaseURL: sched.BaseURL, TokenRef: sched.TokenRef,
			DeviceID: d.MDMDeviceID, RequiredAgentID: sched.RequiredAgentID}
		if sched.EntraClientID != "" {
			intent.ClientCredentials = &mdm.ClientCredentials{Authority: sched.EntraAuthority,
				DirectoryTenantID: sched.EntraDirectoryTenantID, ClientID: sched.EntraClientID}
		}
		if sched.JamfClientID != "" {
			intent.JamfAPIClient = &mdm.JamfAPIClient{ClientID: sched.JamfClientID}
		}
		intents = append(intents, intent)
	}
	if err := s.orch.QueueMDMCheckInWave(ctx, tenantID, queued, intents); err != nil {
		return store.MDMCheckInWave{}, err
	}
	return s.store.GetMDMCheckInWave(ctx, tenantID, waveID)
}
