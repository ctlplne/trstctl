// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func (s *pamService) databaseGatewayBinding(ctx context.Context, tenantID, providerID string) (*projections.PAMDatabaseGatewayBinding, error) {
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != providerID {
			continue
		}
		resolver, ok := provider.(interface {
			DynamicSecretDatabaseGatewayRoute(context.Context) (dbdsn.GatewayRoute, []byte, string, error)
		})
		if !ok {
			break
		}
		route, ca, name, err := resolver.DynamicSecretDatabaseGatewayRoute(ctx)
		if err != nil || route.ProviderID != providerID {
			return nil, dbdsn.ErrGatewayRoute
		}
		return &projections.PAMDatabaseGatewayBinding{Route: route, CAPEM: string(ca), ServerName: name, Record: s.recordings != nil}, nil
	}
	return nil, dbdsn.ErrGatewayRoute
}

func (s *pamService) gatewayCredentialForJob(ctx context.Context, tenantID string, intent accessgateway.SessionIntent) ([]byte, error) {
	if dbdsn.GatewayDriver(intent.TargetType) == "" {
		return s.gatewaySessionCredential(ctx, tenantID, intent.SessionID)
	}
	session, err := s.store.GetPAMSession(ctx, tenantID, intent.SessionID)
	if err != nil || session.Status != "active" || !s.clock().UTC().Before(session.ExpiresAt) ||
		session.TargetType != intent.TargetType || session.TargetID != intent.TargetID ||
		session.GatewayAgentID != intent.RequiredAgentID || session.GatewayTicketDigest != intent.TicketDigest ||
		!dynamicSecretPersistedTimeEqual(session.ExpiresAt, intent.ExpiresAt) || session.GatewayEndedAt != nil || intent.DatabaseRoute == nil {
		return nil, dbdsn.ErrGatewayRoute
	}
	target, err := s.databaseTarget(ctx, tenantID, session.TargetType, session.TargetID)
	if err != nil {
		return nil, dbdsn.ErrGatewayRoute
	}
	bound, err := s.databaseGatewayBinding(ctx, tenantID, target.cfg.ProviderID)
	if err != nil || !bound.Route.Equal(*intent.DatabaseRoute) || bound.CAPEM != intent.DatabaseCAPEM || bound.ServerName != intent.DatabaseServerName {
		return nil, dbdsn.ErrGatewayRoute
	}
	value, err := s.gatewaySessionCredential(ctx, tenantID, intent.SessionID)
	if err != nil {
		return nil, err
	}
	if err := intent.CheckDatabaseCredential(value); err != nil {
		secret.Wipe(value)
		return nil, err
	}
	return value, nil
}

func (s *pamService) databaseGatewayRequestDigest(tenantID, requester string, req api.PAMSessionRequest) (string, error) {
	input, err := json.Marshal(struct {
		Tenant, Requester, Request, Approval, Intent, Kind, Target, Role string
		Method, Evidence, Reason, Template, Run, SSHKey, SSHPrincipal    string
		TTL                                                              int64
		Browser                                                          bool
	}{
		Tenant: tenantID, Requester: requester, Request: req.RequestID, Approval: req.ApprovalRequestID,
		Intent: req.IntentDigest, Kind: req.TargetType, Target: req.TargetID, Role: req.Role, Method: req.Method,
		Evidence: crypto.SHA256Hex(req.Payload), Reason: req.Reason, Template: req.TemplateID, Run: req.RunID,
		SSHKey: crypto.SHA256Hex(req.SSHPublicKey), SSHPrincipal: req.SSHPrincipal, TTL: req.TTLSeconds, Browser: req.Browser,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(input)
	digest, err := s.databaseGatewayDigest("trstctl/pam/database-gateway/request/v1", input)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(digest)
	return hex.EncodeToString(digest), nil
}

func (s *pamService) databaseGatewayDigest(label string, material []byte) ([]byte, error) {
	key, ok := s.kek.(principalNameDigest)
	if !ok {
		return nil, fmt.Errorf("%w: database gateway ticket protection is unavailable", api.ErrPAMRejected)
	}
	digest, err := key.DerivedDigest([]byte(label), material)
	if err != nil || len(digest) != 32 {
		secret.Wipe(digest)
		return nil, fmt.Errorf("%w: database gateway ticket protection is unavailable", api.ErrPAMRejected)
	}
	return digest, nil
}

func (s *pamService) databaseGatewayTicket(tenantID string, start projections.PAMDatabaseGatewayStarted) ([]byte, error) {
	material, err := json.Marshal([]string{tenantID, start.ID, start.ApprovalRequestID, start.AttestationID,
		start.GatewayAgentID, start.RequestDigest})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(material)
	value, err := s.databaseGatewayDigest("trstctl/pam/database-gateway/ticket/v1", material)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(value)
	ticket := make([]byte, base64.RawURLEncoding.EncodedLen(len(value)))
	base64.RawURLEncoding.Encode(ticket, value)
	return ticket, nil
}

func (s *pamService) replayDatabaseGatewayStart(ctx context.Context, tenantID, idempotencyKey, requester, id string,
	req api.PAMSessionRequest) (api.PAMSession, bool, error) {
	event, found, err := s.log.EventByID(ctx, databaseGatewayStartedEventID(tenantID, id))
	if err != nil || !found {
		return api.PAMSession{}, found, err
	}
	var started projections.PAMDatabaseGatewayStarted
	if event.Type != projections.EventPAMSessionStarted || event.TenantID != tenantID ||
		event.SchemaVersion != projections.PAMDatabaseGatewayStartSchemaVersion ||
		json.Unmarshal(event.Data, &started) != nil || started.ID != id || started.RequestedBy != requester ||
		started.IdempotencyKey != idempotencyKey || started.ApprovalRequestID != req.ApprovalRequestID ||
		req.ResolvedDatabaseGatewayRequestDigest == "" ||
		!crypto.ConstantTimeEqual([]byte(started.RequestDigest), []byte(req.ResolvedDatabaseGatewayRequestDigest)) {
		return api.PAMSession{}, true, orchestrator.ErrIdempotencyConflict
	}
	if !s.clock().Before(started.ExpiresAt) {
		return api.PAMSession{}, true, api.ErrPAMTerminal
	}
	// A missing session means the atomic SQL start has not projected. An
	// existing row must retain its job, even if that job now refuses release.
	if _, err := s.store.GetPAMSession(ctx, tenantID, id); store.IsNotFound(err) {
		if err := s.projector.Apply(ctx, event); err != nil {
			return api.PAMSession{}, true, err
		}
	} else if err != nil {
		return api.PAMSession{}, true, err
	}
	result, err := s.databaseGatewayOpenResult(ctx, tenantID, started)
	return result, true, err
}

func (s *pamService) databaseGatewayOpenResult(ctx context.Context, tenantID string, started projections.PAMDatabaseGatewayStarted) (api.PAMSession, error) {
	session, err := s.store.GetPAMSession(ctx, tenantID, started.ID)
	if err != nil {
		return api.PAMSession{}, err
	}
	if session.Status != api.PAMSessionStatusActive || session.GatewayEndedAt != nil || session.EndedAt != nil ||
		session.RevocationRequestedAt != nil || !s.clock().Before(session.ExpiresAt) || session.Delivery != "gateway" ||
		session.GatewayAgentID != started.GatewayAgentID || session.RequestedBy != started.RequestedBy ||
		session.GatewayTicketDigest != started.GatewayTicketDigest || session.IdempotencyKey != started.IdempotencyKey ||
		session.TargetType != started.TargetType || session.TargetID != started.TargetID ||
		session.BackendRef != started.BackendRef {
		return api.PAMSession{}, api.ErrPAMTerminal
	}
	if err := s.validateGatewayBinding(ctx, tenantID, api.PAMTarget{TargetType: started.TargetType, GatewayAgentID: started.GatewayAgentID,
		GatewayAddress: started.GatewayAddress}); err != nil {
		return api.PAMSession{}, err
	}
	delivery, err := s.gatewayDelivery(ctx, tenantID, started.GatewayAgentID, started.GatewayAddress, "")
	if err != nil {
		return api.PAMSession{}, err
	}
	intent := started.Intent()
	payload, err := json.Marshal(intent)
	if err != nil {
		return api.PAMSession{}, err
	}
	live, err := s.store.CanReleasePAMDatabaseGatewayTicket(ctx, session, accessgateway.KindForIntent(intent),
		accessgateway.JobKey(started.ID), mtls.AgentRoleGateway, payload, s.clock())
	if err != nil {
		return api.PAMSession{}, err
	}
	if !live {
		return api.PAMSession{}, api.ErrPAMTerminal
	}
	ticket, err := s.databaseGatewayTicket(tenantID, started)
	if err != nil {
		return api.PAMSession{}, err
	}
	if !crypto.ConstantTimeEqual([]byte(crypto.SHA256Hex(ticket)), []byte(started.GatewayTicketDigest)) {
		secret.Wipe(ticket)
		return api.PAMSession{}, fmt.Errorf("%w: database gateway ticket protection has changed", api.ErrPAMRejected)
	}
	delivery.Ticket = ticket
	sessionView := pamSessionFromStore(session)
	sessionView.Gateway, sessionView.DatabaseGatewayReplay = delivery, true
	return sessionView, nil
}

func databaseGatewayStartedEventID(tenantID, sessionID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-database-gateway-started\x00"+tenantID+"\x00"+sessionID)).String()
}

func (s *pamService) startDatabaseGateway(ctx context.Context, tenantID string, payload projections.PAMSessionStarted,
	binding projections.PAMDatabaseGatewayBinding, address, requestDigest string) (api.PAMSession, error) {
	if requestDigest == "" {
		return api.PAMSession{}, dbdsn.ErrGatewayRoute
	}
	if err := s.validateGatewayBinding(ctx, tenantID, api.PAMTarget{TargetType: payload.TargetType,
		GatewayAgentID: payload.GatewayAgentID, GatewayAddress: address}); err != nil {
		return api.PAMSession{}, err
	}
	started := projections.PAMDatabaseGatewayStarted{PAMSessionStarted: payload, DatabaseGateway: binding,
		RequestDigest: requestDigest, GatewayAddress: address}
	ticket, err := s.databaseGatewayTicket(tenantID, started)
	if err != nil {
		return api.PAMSession{}, err
	}
	started.GatewayTicketDigest = crypto.SHA256Hex(ticket)
	secret.Wipe(ticket)
	if err := s.appendDatabaseGatewayStarted(ctx, tenantID, started); err != nil {
		return api.PAMSession{}, err
	}
	if s.wakeOutbox != nil {
		s.wakeOutbox()
	}
	return s.databaseGatewayOpenResult(ctx, tenantID, started)
}

func (s *pamService) appendDatabaseGatewayStarted(ctx context.Context, tenantID string, payload projections.PAMDatabaseGatewayStarted) error {
	if err := accessgateway.ValidateSessionIntent(payload.Intent()); err != nil {
		return err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	id := databaseGatewayStartedEventID(tenantID, payload.ID)
	event, err := s.log.Append(ctx, events.Event{ID: id, Type: projections.EventPAMSessionStarted, TenantID: tenantID,
		SchemaVersion: projections.PAMDatabaseGatewayStartSchemaVersion, Data: data})
	if err != nil {
		return err
	}
	if event.ID != id || event.Type != projections.EventPAMSessionStarted || event.TenantID != tenantID ||
		event.SchemaVersion != projections.PAMDatabaseGatewayStartSchemaVersion || !bytes.Equal(event.Data, data) {
		return orchestrator.ErrIdempotencyConflict
	}
	return s.projector.Apply(ctx, event)
}
