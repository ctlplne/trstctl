// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// MDM device check-ins (N9), on the server side: the MDM's connection and
// relay come from its poll schedule (the relay that already reads it, I5), the
// device must be one trstctl has read from that MDM, the check-in waits on an
// exact operation approval, and the relay's checked report records the MDM's
// answer.

// mdmCheckInApprovalTTL bounds how long an approved check-in may wait to be
// executed.
const mdmCheckInApprovalTTL = 24 * time.Hour

// mdmCheckInRoute is the enabled, relay-bound schedule a check-in runs
// through. A disabled schedule sends nothing to its MDM, and a check-in, the
// one write, needs https.
func (s *Server) mdmCheckInRoute(ctx context.Context, tenantID, provider string) (store.MDMPollSchedule, error) {
	sched, found, err := s.store.GetMDMPollSchedule(ctx, tenantID, provider)
	if err != nil {
		return store.MDMPollSchedule{}, err
	}
	base, parseErr := url.Parse(strings.TrimSpace(sched.BaseURL))
	if !found || !sched.Enabled || strings.TrimSpace(sched.RequiredAgentID) == "" || strings.TrimSpace(sched.TokenRef) == "" ||
		parseErr != nil || base.Scheme != "https" || base.Host == "" {
		return store.MDMPollSchedule{}, api.ErrMDMCheckInUnavailable
	}
	return sched, nil
}

// mdmCheckInDevice is the device as trstctl last read it from that MDM.
func (s *Server) mdmCheckInDevice(ctx context.Context, tenantID, provider, deviceID string) (store.MDMDeviceCorrelation, error) {
	if !relay.ValidMDMCheckInDevice(provider, deviceID) {
		return store.MDMDeviceCorrelation{}, api.ErrMDMDeviceUnknown
	}
	device, err := s.store.GetMDMDeviceCorrelation(ctx, tenantID, provider, deviceID)
	if store.IsNotFound(err) {
		return store.MDMDeviceCorrelation{}, api.ErrMDMDeviceUnknown
	}
	return device, err
}

// mdmDeviceResourceID names one device at one MDM.
func mdmDeviceResourceID(provider, deviceID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("mdm-device\x00"+provider+"\x00"+deviceID)).String()
}

// RequestMDMCheckInApproval asks reviewers to approve one device's check-in.
func (s *Server) RequestMDMCheckInApproval(ctx context.Context, tenantID, requester, provider, deviceID string,
	input api.MDMCheckInRequest) (api.MDMCheckInApproval, error) {
	sched, err := s.mdmCheckInRoute(ctx, tenantID, provider)
	if err != nil {
		return api.MDMCheckInApproval{}, err
	}
	// Ask only for what the schedule's relay can run: a check-in it cannot
	// claim would wait queued behind an approval for nothing.
	readiness, err := s.orch.DiscoveryNetworkRelayReadinessForJob(ctx, tenantID, sched.RequiredAgentID, relay.KindMDMCheckIn)
	if err != nil {
		return api.MDMCheckInApproval{}, err
	}
	if !readiness.Ready {
		return api.MDMCheckInApproval{}, fmt.Errorf("%w (%s)", api.ErrMDMCheckInUnavailable, readiness.ConnectionOrigin)
	}
	device, err := s.mdmCheckInDevice(ctx, tenantID, provider, deviceID)
	if err != nil {
		return api.MDMCheckInApproval{}, err
	}
	required := s.mdmCheckInApprovals
	if required <= 0 {
		required = defaultRequiredApprovals
	}
	name := device.DeviceName
	if name == "" {
		name = fmt.Sprintf("%s device %s", provider, deviceID)
	}
	request, err := s.orch.EnsureOperationApprovalRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "mdm_device", ResourceID: mdmDeviceResourceID(provider, deviceID), ResourceName: name,
		Action: "check_in", Requester: requester, FromState: "managed", ToState: "check_in_requested", TargetVersion: 1,
		Reason: input.Reason, EvidenceRefs: []string{"mdm-device:" + provider + ":" + deviceID}, RequiredApprovals: required,
		TTL: mdmCheckInApprovalTTL,
	})
	if err != nil {
		return api.MDMCheckInApproval{}, err
	}
	return api.MDMCheckInApproval{MDM: provider, DeviceID: deviceID, DeviceName: device.DeviceName, Reason: input.Reason,
		ApprovalRequestID: request.ID, ApprovalIntentDigest: request.IntentDigest, Status: request.Status,
		RequiredApprovals: request.RequiredApprovals, ApprovalCount: request.ApprovalCount, ExpiresAt: request.ExpiresAt}, nil
}

// QueueMDMCheckIn executes an approved check-in: it queues one relay job,
// spending the approval. Executing it again returns the same check-in.
func (s *Server) QueueMDMCheckIn(ctx context.Context, tenantID, requester, provider, deviceID string,
	input api.MDMCheckInStart) (store.MDMCheckIn, error) {
	sched, err := s.mdmCheckInRoute(ctx, tenantID, provider)
	if err != nil {
		return store.MDMCheckIn{}, err
	}
	id, err := uuid.Parse(strings.TrimSpace(input.ApprovalRequestID))
	if err != nil || id == uuid.Nil {
		return store.MDMCheckIn{}, store.ErrApprovalRequestNotFound
	}
	request, err := s.store.GetOperationApproval(ctx, tenantID, id.String())
	if err != nil {
		return store.MDMCheckIn{}, err
	}
	if request.IntentDigest != input.ApprovalIntentDigest || request.Requester != requester || request.ResourceKind != "mdm_device" ||
		request.ResourceID != mdmDeviceResourceID(provider, deviceID) || request.Action != "check_in" {
		return store.MDMCheckIn{}, store.ErrApprovalDigestMismatch
	}
	checkInID := orchestrator.MDMCheckInID(tenantID, request.ID)
	if existing, err := s.store.GetMDMCheckIn(ctx, tenantID, checkInID); err == nil {
		return existing, nil
	} else if !errors.Is(err, store.ErrMDMCheckInNotFound) {
		return store.MDMCheckIn{}, err
	}
	device, err := s.mdmCheckInDevice(ctx, tenantID, provider, deviceID)
	if err != nil {
		return store.MDMCheckIn{}, err
	}
	use, err := store.OperationApprovalUseFromRequest(request)
	if err != nil {
		return store.MDMCheckIn{}, err
	}
	queued := projections.MDMCheckInQueued{ID: checkInID, MDM: provider, DeviceID: deviceID, DeviceName: device.DeviceName,
		RelayAgentID: sched.RequiredAgentID, Approval: use}
	intent := relay.MDMCheckInIntent{ID: checkInID, MDM: provider, BaseURL: sched.BaseURL, TokenRef: sched.TokenRef,
		DeviceID: deviceID, RequiredAgentID: sched.RequiredAgentID}
	if sched.EntraClientID != "" {
		// A156: the relay exchanges the redeemed client secret for a Graph token.
		intent.ClientCredentials = &mdm.ClientCredentials{Authority: sched.EntraAuthority,
			DirectoryTenantID: sched.EntraDirectoryTenantID, ClientID: sched.EntraClientID}
	}
	if err := s.orch.QueueMDMCheckIn(ctx, tenantID, queued, intent); err != nil {
		return store.MDMCheckIn{}, err
	}
	return s.store.GetMDMCheckIn(ctx, tenantID, checkInID)
}

// recordMDMCheckInResult checks a relay's check-in report against its queued
// job — the exact relay, the same MDM and device, accepted by the MDM — and
// records the MDM's answer.
func (a *agentService) recordMDMCheckInResult(ctx context.Context, tenantID, agentName string, payload []byte, detail string) error {
	var intent relay.MDMCheckInIntent
	if err := decodeStrictJSON(payload, &intent); err != nil {
		return fmt.Errorf("server: decode durable MDM check-in: %w", err)
	}
	if intent.RequiredAgentID == "" || intent.RequiredAgentID != agentRowID(tenantID, agentName) {
		return errors.New("server: an MDM check-in result requires the schedule's exact relay")
	}
	var report relay.MDMCheckInReport
	if err := decodeStrictJSON([]byte(detail), &report); err != nil {
		return fmt.Errorf("server: decode MDM check-in report: %w", err)
	}
	if err := relay.ValidateMDMCheckInReport(intent, report); err != nil {
		return err
	}
	if a.orch == nil {
		return errors.New("MDM check-in result receiver is not configured")
	}
	return a.orch.RecordMDMCheckedIn(ctx, tenantID, projections.MDMCheckedIn{ID: intent.ID, ProviderStatus: report.ProviderStatus})
}
