// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// resolveGatewaySession redeems a gateway session's upstream credential for
// the session's own gateway (A254): the job names the session by reference,
// and the credential is reopened from the session's lease for this attempt
// only. It is never on the queue, in an event or in any response but this
// redemption over the gateway's mTLS channel.
func (r *relayCredentialResolver) resolveGatewaySession(ctx context.Context, tenantID string, job store.AgentJobForRedemption) (redeemedMaterial, error) {
	if r.pamGatewayCredential == nil {
		return redeemedMaterial{}, errors.New("access gateway sessions are not served")
	}
	var intent accessgateway.SessionIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil || accessgateway.ValidateSessionIntent(intent) != nil {
		return redeemedMaterial{}, errors.New("gateway job payload is not a session")
	}
	if intent.RequiredAgentID != job.RequiredAgentID {
		return redeemedMaterial{}, errors.New("gateway job names another gateway")
	}
	credential, err := r.pamGatewayCredential(ctx, tenantID, intent.SessionID)
	if err != nil {
		return redeemedMaterial{}, err
	}
	return redeemedMaterial{
		items:    []transport.RedeemedSecret{{Name: intent.CredentialRef, Value: secret.JSONBytes(credential)}},
		refNames: []string{intent.CredentialRef},
		wipe:     func() { secret.Wipe(credential) },
	}, nil
}

// validateGatewaySessionReport checks a gateway's end-of-session report
// against its job: the same session, a known ending.
func validateGatewaySessionReport(payload []byte, detail string) error {
	var intent accessgateway.SessionIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return errors.New("gateway job payload is not a session")
	}
	var report accessgateway.SessionReport
	if err := json.Unmarshal([]byte(detail), &report); err != nil {
		return errors.New("gateway session report is not a session report")
	}
	switch {
	case report.SessionID != intent.SessionID:
		return errors.New("gateway session report names another session")
	case report.Ended != "deadline" && report.Ended != "recalled" && report.Ended != "credential_unavailable":
		return fmt.Errorf("gateway session report ended %q is not a known ending", report.Ended)
	case report.Connections < 0:
		return errors.New("gateway session report counts no connections")
	}
	return nil
}

// validateGatewayBinding checks a target's gateway binding (A254): both the
// agent and its address or neither; the agent enrolled in this tenant with the
// gateway role and not offboarded; the address a host and port. SSH targets
// join the gateway with its SSH half.
func (s *pamService) validateGatewayBinding(ctx context.Context, tenantID string, target api.PAMTarget) error {
	if target.GatewayAgentID == "" && target.GatewayAddress == "" {
		return nil
	}
	if target.GatewayAgentID == "" || target.GatewayAddress == "" {
		return fmt.Errorf("%w: a gateway binding names both gateway_agent_id and gateway_address", api.ErrPAMInvalid)
	}
	if target.TargetType != pamTargetPostgres {
		return fmt.Errorf("%w: only postgres targets are served through a gateway yet", api.ErrPAMInvalid)
	}
	if _, err := uuid.Parse(target.GatewayAgentID); err != nil {
		return fmt.Errorf("%w: gateway_agent_id must be an agent UUID", api.ErrPAMInvalid)
	}
	host, port, err := net.SplitHostPort(target.GatewayAddress)
	if n, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || n < 1 || n > 65535 || strings.ContainsAny(host, "/@ \t\r\n") {
		return fmt.Errorf("%w: gateway_address must be host:port", api.ErrPAMInvalid)
	}
	agent, err := s.store.GetAgent(ctx, tenantID, target.GatewayAgentID)
	if err != nil {
		return fmt.Errorf("%w: gateway agent is not enrolled in this tenant", api.ErrPAMInvalid)
	}
	if agent.OffboardedAt != nil || !slices.Contains(agent.Roles, mtls.AgentRoleGateway) {
		return fmt.Errorf("%w: gateway agent must hold the gateway role and not be offboarded", api.ErrPAMInvalid)
	}
	return nil
}

// newGatewayTicket mints a session's one-time ticket: 32 random bytes,
// URL-safe. Only its SHA-256 is stored.
func newGatewayTicket() (string, error) {
	raw, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// gatewayDelivery is what the requester needs to reach a gateway session.
func (s *pamService) gatewayDelivery(ctx context.Context, tenantID, agentID, address, ticket string) (*api.PAMGatewayDelivery, error) {
	agent, err := s.store.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("%w: gateway agent is not enrolled in this tenant", api.ErrPAMRejected)
	}
	delivery := &api.PAMGatewayDelivery{AgentID: agentID, Address: address, SPIFFEID: mtls.AgentSPIFFEID(tenantID, agent.Name)}
	if s.agentCAPEM != nil {
		delivery.CAPEM = string(s.agentCAPEM())
	}
	if ticket != "" {
		delivery.Ticket = []byte(ticket)
	}
	return delivery, nil
}

// enqueueGatewaySession queues the session's one gateway job (idempotent on
// the session), naming the gateway and the credential by reference.
func (s *pamService) enqueueGatewaySession(ctx context.Context, tenantID string, intent accessgateway.SessionIntent) error {
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{TenantID: tenantID, Destination: accessgateway.KindSession,
			IdempotencyKey: accessgateway.JobKey(intent.SessionID), Payload: payload,
			RequiredAgentRole: mtls.AgentRoleGateway, RequiredAgentID: intent.RequiredAgentID})
		return err
	})
	if err == nil && s.wakeOutbox != nil {
		s.wakeOutbox()
	}
	return err
}

// gatewaySessionIntent is the job a gateway session rides on.
func gatewaySessionIntent(rec store.PAMSession) accessgateway.SessionIntent {
	return accessgateway.SessionIntent{SessionID: rec.ID, TargetType: rec.TargetType, TargetID: rec.TargetID,
		ExpiresAt: rec.ExpiresAt, TicketDigest: rec.GatewayTicketDigest,
		CredentialRef: accessgateway.CredentialRef(rec.ID), RequiredAgentID: rec.GatewayAgentID}
}

// gatewaySessionCredential reopens an active gateway session's upstream
// credential from its lease, for the redemption of its gateway job only.
func (s *pamService) gatewaySessionCredential(ctx context.Context, tenantID, sessionID string) ([]byte, error) {
	rec, err := s.store.GetPAMSession(ctx, tenantID, sessionID)
	if err != nil {
		return nil, errors.New("gateway session is unknown")
	}
	if rec.Delivery != "gateway" || rec.Status != api.PAMSessionStatusActive || !s.clock().UTC().Before(rec.ExpiresAt) {
		return nil, errors.New("gateway session is not active")
	}
	if rec.TargetType != pamTargetPostgres || rec.BackendRef == "" {
		return nil, errors.New("gateway session has no lease to redeem")
	}
	lifecycle, err := s.postgresLifecycle(tenantID)
	if err != nil {
		return nil, err
	}
	lease, err := s.store.GetDynamicSecretLease(ctx, tenantID, rec.BackendRef)
	if err != nil {
		return nil, errors.New("gateway session lease is unavailable")
	}
	return lifecycle.openCredential(ctx, lease)
}

// pamGatewayCredential is the job resolver's hook into PAM, nil when PAM is
// not served (the resolver then refuses gateway redemptions).
func (s *Server) pamGatewayCredential() func(ctx context.Context, tenantID, sessionID string) ([]byte, error) {
	if s.pam == nil {
		return nil
	}
	return s.pam.gatewaySessionCredential
}

// startGatewaySession records a gateway-delivered session (A254) and queues
// its gateway job. The requester receives the session and its one-time
// ticket; the started event carries only the ticket's SHA-256. A job that
// could not be queued now is queued by the expiry worker's next pass.
func (s *pamService) startGatewaySession(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time,
	att attest.Attestation, req api.PAMSessionRequest, backendRef, gatewayAgentID, gatewayAddress string, undo func()) (api.PAMSession, error) {
	ticket, err := newGatewayTicket()
	if err != nil {
		undo()
		return api.PAMSession{}, err
	}
	delivery, err := s.gatewayDelivery(ctx, tenantID, gatewayAgentID, gatewayAddress, ticket)
	if err != nil {
		undo()
		return api.PAMSession{}, err
	}
	session, payload := s.startedPayload(tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, backendRef, "", 0)
	payload.Delivery, payload.GatewayAgentID, payload.GatewayTicketDigest = "gateway", gatewayAgentID, accessgateway.TicketDigest(ticket)
	if err := s.appendProject(ctx, tenantID, projections.EventPAMSessionStarted, payload); err != nil {
		undo()
		return api.PAMSession{}, err
	}
	_ = s.enqueueGatewaySession(ctx, tenantID, gatewaySessionIntent(store.PAMSession{ID: id, TargetType: req.TargetType,
		TargetID: req.TargetID, ExpiresAt: expiresAt, GatewayTicketDigest: payload.GatewayTicketDigest, GatewayAgentID: gatewayAgentID}))
	session.Delivery, session.Gateway = "gateway", delivery
	return session, nil
}

// ensureGatewayJobs queues the gateway job of every active gateway session
// that has none (an open interrupted between its event and its job). The job
// key is the session, so a queued job is never queued twice.
func (s *pamService) ensureGatewayJobs(ctx context.Context) {
	sessions, err := s.store.ListActiveGatewayPAMSessions(ctx, s.clock().UTC(), 200)
	if err != nil {
		return
	}
	for _, rec := range sessions {
		_ = s.enqueueGatewaySession(ctx, rec.TenantID, gatewaySessionIntent(rec))
	}
}

// gatewayDeliveryForRead is a gateway session's delivery on a read: the
// gateway and how to verify it, with the target's current gateway address.
// The ticket was shown once, by the open.
func (s *pamService) gatewayDeliveryForRead(ctx context.Context, tenantID string, rec store.PAMSession) *api.PAMGatewayDelivery {
	address := ""
	if rec.TargetType == pamTargetPostgres {
		if target, err := s.postgresTarget(ctx, tenantID, rec.TargetID); err == nil && target.cfg.GatewayAgentID == rec.GatewayAgentID {
			address = target.cfg.GatewayAddress
		}
	}
	delivery, err := s.gatewayDelivery(ctx, tenantID, rec.GatewayAgentID, address, "")
	if err != nil {
		return &api.PAMGatewayDelivery{AgentID: rec.GatewayAgentID, Address: address}
	}
	return delivery
}
