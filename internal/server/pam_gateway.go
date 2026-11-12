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
	"trstctl.com/trstctl/internal/accessconsole"
	"trstctl.com/trstctl/internal/accessdesktop"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
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
	if err := json.Unmarshal(job.Payload, &intent); err != nil || accessgateway.ValidateSessionIntent(intent) != nil || !accessgateway.MatchesSessionJob(job.Destination, intent) {
		return redeemedMaterial{}, errors.New("gateway job payload is not a session")
	}
	if intent.RequiredAgentID != job.RequiredAgentID {
		return redeemedMaterial{}, errors.New("gateway job names another gateway")
	}
	if !accessgateway.RedeemsCredential(intent.TargetType) {
		// An SSH session's gateway certifies a key of its own
		// (SignJobSSHKey); there is no credential to redeem.
		return redeemedMaterial{}, errors.New("an SSH gateway session redeems no credential")
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
	case report.Ended != "deadline" && report.Ended != "recalled" && report.Ended != "credential_unavailable" && report.Ended != "policy_unavailable":
		return fmt.Errorf("gateway session report ended %q is not a known ending", report.Ended)
	case report.Connections < 0:
		return errors.New("gateway session report counts no connections")
	}
	return nil
}

// validateGatewayBinding checks a target's gateway binding (A254): both the
// agent and its address or neither; the agent enrolled in this tenant with the
// gateway role and not offboarded; the address a host and port; an SSH target
// pins the host keys its gateway accepts.
func (s *pamService) validateGatewayBinding(ctx context.Context, tenantID string, target api.PAMTarget) error {
	if target.GatewayAgentID == "" && target.GatewayAddress == "" {
		return nil
	}
	if target.GatewayAgentID == "" || target.GatewayAddress == "" {
		return fmt.Errorf("%w: a gateway binding names both gateway_agent_id and gateway_address", api.ErrPAMInvalid)
	}
	if target.TargetType == pamTargetSSH {
		if err := validateSSHGatewayPins(target.GatewayAgentID, target.HostKeyFingerprints); err != nil {
			return fmt.Errorf("%w: %v", api.ErrPAMInvalid, err)
		}
	} else if len(target.HostKeyFingerprints) != 0 {
		return fmt.Errorf("%w: host_key_fingerprints apply only to SSH targets", api.ErrPAMInvalid)
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
	if err := accessgateway.ValidateSessionIntent(intent); err != nil {
		return err
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{TenantID: tenantID, Destination: accessgateway.KindForIntent(intent),
			IdempotencyKey: accessgateway.JobKey(intent.SessionID), Payload: payload,
			RequiredAgentRole: mtls.AgentRoleGateway, RequiredAgentID: intent.RequiredAgentID})
		return err
	})
	if err == nil && s.wakeOutbox != nil {
		s.wakeOutbox()
	}
	return err
}

// gatewaySessionIntent is the job a gateway session rides on. A database
// session names its credential for redemption; an SSH session names the
// target's address, the principal and the pinned host keys, and redeems
// nothing: its gateway certifies a key of its own.
func (s *pamService) gatewaySessionIntent(ctx context.Context, rec store.PAMSession) (accessgateway.SessionIntent, error) {
	intent := accessgateway.SessionIntent{SessionID: rec.ID, TargetType: rec.TargetType, TargetID: rec.TargetID,
		ExpiresAt: rec.ExpiresAt, TicketDigest: rec.GatewayTicketDigest, RequiredAgentID: rec.GatewayAgentID,
		Record: s.recordings != nil, CommandPolicy: rec.CommandPolicy}
	if rec.TargetType != pamTargetSSH {
		intent.CredentialRef = accessgateway.CredentialRef(rec.ID)
		// A256-L1: a database target's TLS is verified against its provider's
		// CA, carried with the job; no root file need sit on the gateway's
		// host.
		if rec.TargetType == pamTargetPostgres || rec.TargetType == pamTargetRedis || rec.TargetType == pamTargetMongo {
			caPEM, serverName, err := s.databaseTLS(ctx, rec.TenantID, rec.TargetType, rec.TargetID)
			if err != nil {
				return accessgateway.SessionIntent{}, err
			}
			intent.DatabaseCAPEM, intent.DatabaseServerName = string(caPEM), serverName
		}
		if accessgateway.HTTPUpstream(rec.TargetType) {
			// A ClickHouse credential is a user and password, a Kubernetes
			// one a token; where the server answers is the provider's
			// endpoint.
			endpoint, caPEM, serverName, err := s.databaseUpstream(ctx, rec.TenantID, rec.TargetType, rec.TargetID)
			if err != nil {
				return accessgateway.SessionIntent{}, err
			}
			intent.UpstreamURL, intent.UpstreamCAPEM, intent.UpstreamServerName = endpoint, string(caPEM), serverName
		}
		if rec.TargetType == pamTargetAWS {
			target, err := s.databaseTarget(ctx, rec.TenantID, rec.TargetType, rec.TargetID)
			if err != nil {
				return accessgateway.SessionIntent{}, err
			}
			found := false
			for _, provider := range s.providers.ForTenant(rec.TenantID) {
				if provider == nil || provider.Name() != target.cfg.ProviderID {
					continue
				}
				binding, ok := provider.(interface {
					DynamicSecretGatewayAWS() (string, string, error)
				})
				if !ok {
					continue
				}
				intent.AWSService, intent.AWSRegion, err = binding.DynamicSecretGatewayAWS()
				if err != nil {
					return accessgateway.SessionIntent{}, err
				}
				found = true
				break
			}
			if !found {
				return accessgateway.SessionIntent{}, errors.New("AWS account has no gateway signing scope")
			}
		}
		if rec.TargetType == pamTargetGCP || rec.TargetType == pamTargetAzure {
			target, err := s.databaseTarget(ctx, rec.TenantID, rec.TargetType, rec.TargetID)
			if err != nil {
				return accessgateway.SessionIntent{}, err
			}
			found := false
			for _, provider := range s.providers.ForTenant(rec.TenantID) {
				if provider == nil || provider.Name() != target.cfg.ProviderID {
					continue
				}
				binding, ok := provider.(interface {
					DynamicSecretGatewayOAuth() (string, []string, string, error)
				})
				if !ok {
					continue
				}
				intent.OAuthTokenEndpoint, intent.OAuthScopes, intent.OAuthSubject, err = binding.DynamicSecretGatewayOAuth()
				if err != nil {
					return accessgateway.SessionIntent{}, err
				}
				if rec.TargetType == pamTargetAzure {
					tenant, ok := provider.(interface{ DynamicSecretGatewayAzureTenant() string })
					if !ok || tenant.DynamicSecretGatewayAzureTenant() == "" {
						return accessgateway.SessionIntent{}, errors.New("server: Azure gateway has no frozen tenant")
					}
					intent.OAuthTenant = tenant.DynamicSecretGatewayAzureTenant()
				}

				found = true
				break
			}
			if !found {
				return accessgateway.SessionIntent{}, errors.New("server: Google Cloud account has no gateway OAuth scope")
			}
		}

		if rec.TargetType == pamTargetNetDevice {
			// A270: the device's SSH route and the account its role
			// rotates, from its provider; the vaulted password is redeemed.
			target, err := s.databaseTarget(ctx, rec.TenantID, rec.TargetType, rec.TargetID)
			if err != nil {
				return accessgateway.SessionIntent{}, err
			}
			for _, provider := range s.providers.ForTenant(rec.TenantID) {
				if provider == nil || provider.Name() != target.cfg.ProviderID {
					continue
				}
				if route, ok := provider.(pamNetDeviceRoute); ok {
					intent.SSHAddress, intent.SSHPrincipal, intent.SSHHostKeyFingerprints, err = route.DynamicSecretGatewaySSH(rec.Role)
					if err != nil {
						return accessgateway.SessionIntent{}, err
					}
				}
				break
			}
			if intent.SSHAddress == "" {
				return accessgateway.SessionIntent{}, errors.New("server: the network device's SSH route is unavailable")
			}
		}
		if rec.TargetType == pamTargetRDP {
			target, err := s.databaseTarget(ctx, rec.TenantID, rec.TargetType, rec.TargetID)
			if err != nil {
				return accessgateway.SessionIntent{}, err
			}
			for _, provider := range s.providers.ForTenant(rec.TenantID) {
				if provider == nil || provider.Name() != target.cfg.ProviderID {
					continue
				}
				source, ok := provider.(interface {
					DynamicSecretGatewayDesktop(string) (accessdesktop.Binding, error)
				})
				if !ok {
					continue
				}
				binding, e := source.DynamicSecretGatewayDesktop(rec.Role)
				if e != nil {
					return accessgateway.SessionIntent{}, e
				}
				// A269: the clipboard policy is the one its reviewers approved,
				// read from the consumed approval's evidence; none is deny.
				if binding.Clipboard, e = s.reviewedDesktopClipboard(ctx, rec); e != nil {
					return accessgateway.SessionIntent{}, e
				}
				intent.Desktop = &binding
				break
			}
			if intent.Desktop == nil {
				return accessgateway.SessionIntent{}, errors.New("server: reviewed desktop route unavailable")
			}
		}
		if rec.TargetType == pamTargetWebConsole {
			// A273: the console's route from its target and the sign-in the
			// session's reviewers approved; the vaulted account is redeemed.
			target, err := s.databaseTarget(ctx, rec.TenantID, rec.TargetType, rec.TargetID)
			if err != nil {
				return accessgateway.SessionIntent{}, err
			}
			if target.cfg.Web == nil || rec.WebSignIn == nil {
				return accessgateway.SessionIntent{}, errors.New("server: web console session has no reviewed route and sign-in")
			}
			signIn := *rec.WebSignIn
			intent.UpstreamURL, intent.UpstreamCAPEM, intent.UpstreamServerName = target.cfg.Web.URL, target.cfg.Web.CAPEM, target.cfg.Web.ServerName
			intent.WebSignIn = &signIn
		}
		if rec.TargetType == pamTargetAWSConsole {
			target, err := s.databaseTarget(ctx, rec.TenantID, rec.TargetType, rec.TargetID)
			if err != nil {
				return accessgateway.SessionIntent{}, err
			}
			found := false
			for _, provider := range s.providers.ForTenant(rec.TenantID) {
				if provider == nil || provider.Name() != target.cfg.ProviderID {
					continue
				}
				source, ok := provider.(interface {
					DynamicSecretGatewayConsole() (accessconsole.Binding, error)
				})
				if !ok {
					continue
				}
				binding, err := source.DynamicSecretGatewayConsole()
				if err != nil {
					return accessgateway.SessionIntent{}, err
				}
				intent.Console = &binding
				intent.ConsoleRole = rec.Role
				found = true
				break
			}
			if !found {
				return accessgateway.SessionIntent{}, errors.New("server: native console binding unavailable")
			}
		}

		return intent, nil
	}
	target, err := s.sshTarget(ctx, rec.TenantID, rec.TargetID)
	if err != nil {
		return accessgateway.SessionIntent{}, err
	}
	if target.GatewayAgentID != rec.GatewayAgentID {
		return accessgateway.SessionIntent{}, errors.New("the SSH target is no longer bound to this session's gateway")
	}
	intent.SSHAddress = net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	intent.SSHPrincipal = rec.SSHPrincipal
	intent.SSHHostKeyFingerprints = append([]string(nil), target.HostKeyFingerprints...)
	return intent, nil
}

// databaseUpstream is where a target's provider reaches its server — the
// endpoint, its CA (none: the system roots) and server name — for a type
// whose credential names no address.
func (s *pamService) databaseUpstream(ctx context.Context, tenantID, targetType, targetID string) (string, []byte, string, error) {
	target, err := s.databaseTarget(ctx, tenantID, targetType, targetID)
	if err != nil {
		return "", nil, "", err
	}
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != target.cfg.ProviderID {
			continue
		}
		if p, ok := provider.(interface {
			DynamicSecretGatewayUpstream(context.Context) (string, []byte, string, error)
		}); ok {
			endpoint, caPEM, serverName, err := p.DynamicSecretGatewayUpstream(ctx)
			if err == nil && endpoint != "" {
				return endpoint, caPEM, serverName, nil
			}
		}
	}
	return "", nil, "", fmt.Errorf("the %s target's provider names no endpoint", targetType)
}

// databaseTLS is the CA and certificate name a database target's provider
// trusts (A256-L1), for its gateway session's sign-in.
func (s *pamService) databaseTLS(ctx context.Context, tenantID, targetType, targetID string) ([]byte, string, error) {
	target, err := s.databaseTarget(ctx, tenantID, targetType, targetID)
	if err != nil {
		return nil, "", err
	}
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != target.cfg.ProviderID {
			continue
		}
		if p, ok := provider.(interface {
			DynamicSecretGatewayTLS(context.Context) ([]byte, string, error)
		}); ok {
			return p.DynamicSecretGatewayTLS(ctx)
		}
	}
	return nil, "", nil
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
	if !isPAMDatabaseType(rec.TargetType) || rec.BackendRef == "" {
		return nil, errors.New("gateway session has no lease to redeem")
	}
	if name, ok := strings.CutPrefix(rec.BackendRef, pamVaultedRef); ok {
		// A261: the vaulted account's current credential, read when the
		// gateway claims the session (a rotation since the session opened
		// is honored).
		if s.secretReader == nil {
			return nil, errors.New("gateway session's vaulted account needs the secrets API")
		}
		value, _, err := s.secretReader(ctx, tenantID, name)
		if err != nil {
			return nil, errors.New("gateway session's vaulted account secret is unavailable")
		}
		return value, nil
	}
	lifecycle, err := s.databaseLifecycle(tenantID)
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

// gatewayStart is what a gateway-delivered session starts with: the
// session's backend reference, its gateway and, for SSH, the key ID and
// principal the gateway's certificates will name. undo releases what the open
// created when the session cannot start.
type gatewayStart struct {
	backendRef, agentID, address string
	sshKeyID, sshPrincipal       string
	// accountRotationProvider (A273-O4) rotates a web console's account
	// once after the session ends.
	accountRotationProvider string
	undo                    func()
}

// startGatewaySession records a gateway-delivered session (A254) and queues
// its gateway job. The requester receives the session and its one-time
// ticket; the started event carries only the ticket's SHA-256. A job that
// could not be queued now is queued by the expiry worker's next pass.
func (s *pamService) startGatewaySession(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time,
	att attest.Attestation, req api.PAMSessionRequest, start gatewayStart) (api.PAMSession, error) {
	// A278: a pooled gateway shares its targets' sessions; the member the
	// session starts on owns it, and a lost or draining one is passed over.
	provisional := store.PAMSession{TenantID: tenantID, ID: id, TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role,
		ExpiresAt: expiresAt, GatewayAgentID: start.agentID, SSHPrincipal: start.sshPrincipal, CommandPolicy: req.ResolvedCommandPolicy}
	needKind := ""
	if intent, err := s.gatewaySessionIntent(ctx, provisional); err == nil {
		needKind = pamSessionNeedsExecutor(intent)
	}
	agentID, address, err := s.chooseGateway(ctx, tenantID, start.agentID, start.address, needKind)
	if err != nil {
		start.undo()
		return api.PAMSession{}, err
	}
	start.agentID, start.address = agentID, address
	ticket, err := newGatewayTicket()
	if err != nil {
		start.undo()
		return api.PAMSession{}, err
	}
	delivery, err := s.gatewayDelivery(ctx, tenantID, start.agentID, start.address, ticket)
	if err != nil {
		start.undo()
		return api.PAMSession{}, err
	}
	session, payload := s.startedPayload(tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, start.backendRef, start.sshKeyID, 0)
	payload.Delivery, payload.GatewayAgentID, payload.GatewayTicketDigest = "gateway", start.agentID, accessgateway.TicketDigest(ticket)
	payload.SSHPrincipal = start.sshPrincipal
	payload.AccountRotationProvider = start.accountRotationProvider
	if req.TargetType == pamTargetSSH {
		// The deterministic SSH started event completes the activation the
		// open recorded, exactly as a direct SSH session's does, so the
		// recovery worker never mistakes this session for an abandoned
		// signing.
		err = s.appendSSHSessionStarted(ctx, tenantID, id, payload)
		if err == nil {
			activation, lookupErr := s.store.GetPAMSSHActivation(ctx, tenantID, id)
			if lookupErr != nil || activation.Status != "completed" {
				err = fmt.Errorf("%w: SSH activation was not durably completed", api.ErrPAMRejected)
			}
		}
	} else {
		err = s.appendProject(ctx, tenantID, projections.EventPAMSessionStarted, payload)
	}
	if err != nil {
		start.undo()
		return api.PAMSession{}, err
	}
	rec := store.PAMSession{TenantID: tenantID, ID: id, TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role, ExpiresAt: expiresAt,
		GatewayTicketDigest: payload.GatewayTicketDigest, GatewayAgentID: start.agentID, SSHPrincipal: start.sshPrincipal, CommandPolicy: payload.CommandPolicy,
		ApprovalRequestID: payload.ApprovalRequestID}
	if intent, err := s.gatewaySessionIntent(ctx, rec); err == nil {
		_ = s.enqueueGatewaySession(ctx, tenantID, intent)
	}
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
		if intent, err := s.gatewaySessionIntent(ctx, rec); err == nil {
			_ = s.enqueueGatewaySession(ctx, rec.TenantID, intent)
		}
	}
}

// gatewayDeliveryForRead is a gateway session's delivery on a read: the
// gateway and how to verify it, with the target's current gateway address.
// The ticket was shown once, by the open.
func (s *pamService) gatewayDeliveryForRead(ctx context.Context, tenantID string, rec store.PAMSession) *api.PAMGatewayDelivery {
	address := ""
	switch {
	case isPAMDatabaseType(rec.TargetType):
		if target, err := s.databaseTarget(ctx, tenantID, rec.TargetType, rec.TargetID); err == nil && target.cfg.GatewayAgentID == rec.GatewayAgentID {
			address = target.cfg.GatewayAddress
		}
	case rec.TargetType == pamTargetSSH:
		if target, err := s.sshTarget(ctx, tenantID, rec.TargetID); err == nil && target.GatewayAgentID == rec.GatewayAgentID {
			address = target.GatewayAddress
		}
	}
	if address == "" {
		// A278: a pool member that owns another member's target's session
		// is reached at its own address.
		if member, ok := s.gatewayMemberAddress(ctx, tenantID, rec.GatewayAgentID); ok {
			address = member
		}
	}
	delivery, err := s.gatewayDelivery(ctx, tenantID, rec.GatewayAgentID, address, "")
	if err != nil {
		return &api.PAMGatewayDelivery{AgentID: rec.GatewayAgentID, Address: address}
	}
	if rec.TargetType == pamTargetAWS {
		service, region, err := s.store.PAMGatewayAWSScope(ctx, tenantID, rec.ID)
		if err == nil {
			delivery.AWSService, delivery.AWSRegion = service, region
		}
	}
	return delivery
}

// validateSSHGatewayPins checks a gateway-bound SSH target's host-key pins:
// one to eight SHA256 fingerprints, and none on a target with no gateway.
func validateSSHGatewayPins(gatewayAgentID string, fingerprints []string) error {
	if gatewayAgentID == "" {
		if len(fingerprints) != 0 {
			return errors.New("host_key_fingerprints apply only to a gateway-bound SSH target")
		}
		return nil
	}
	if len(fingerprints) == 0 || len(fingerprints) > 8 {
		return errors.New("a gateway-bound SSH target pins one to eight host_key_fingerprints")
	}
	for _, fp := range fingerprints {
		if !config.ValidSSHHostKeyFingerprint(fp) {
			return fmt.Errorf("host_key_fingerprints entry %q is not SHA256:<base64>", fp)
		}
	}
	return nil
}

// gatewaySSHCertificateExtensions are the only permissions a gateway's
// session certificate carries: a terminal. The gateway relays session
// channels alone, so forwarding of ports or agents is never granted.
var gatewaySSHCertificateExtensions = map[string]string{"permit-pty": ""}

// signGatewaySSHKey certifies a gateway's per-session SSH key (A254 part 2).
// The job payload is the control plane's own record of the session; the
// session must still be an active gateway SSH session of this agent's, before
// its deadline, on a target still bound to this agent that still allows the
// principal. The certificate ends at the session's deadline and carries the
// session's key ID, which revocation puts on the KRL.
func (s *pamService) signGatewaySSHKey(ctx context.Context, tenantID, agentID string, payload, publicKey []byte) ([]byte, time.Time, error) {
	var intent accessgateway.SessionIntent
	if err := json.Unmarshal(payload, &intent); err != nil || accessgateway.ValidateSessionIntent(intent) != nil ||
		intent.TargetType != accessgateway.TargetSSH || intent.RequiredAgentID != agentID {
		return nil, time.Time{}, errors.New("the job is not an SSH gateway session of this agent's")
	}
	rec, err := s.store.GetPAMSession(ctx, tenantID, intent.SessionID)
	if err != nil {
		return nil, time.Time{}, errors.New("the gateway session is unknown")
	}
	now := s.clock().UTC()
	switch {
	case rec.Delivery != "gateway" || rec.TargetType != pamTargetSSH || rec.GatewayAgentID != agentID:
		return nil, time.Time{}, errors.New("the session is not this gateway's SSH session")
	case rec.Status != api.PAMSessionStatusActive || !now.Before(rec.ExpiresAt):
		return nil, time.Time{}, errors.New("the gateway session is not active")
	case rec.SSHPrincipal == "" || rec.SSHKeyID != "pam:"+rec.ID:
		return nil, time.Time{}, errors.New("the gateway session names no principal")
	}
	target, err := s.sshTarget(ctx, tenantID, rec.TargetID)
	if err != nil {
		return nil, time.Time{}, err
	}
	if !s.gatewayServesTarget(ctx, tenantID, target.GatewayAgentID, agentID) || !principalAllowed(target.Principals, rec.SSHPrincipal) {
		return nil, time.Time{}, errors.New("the SSH target no longer admits this session through this gateway")
	}
	issued, err := s.sshCA.IssueUserCert(ctx, sshca.Profile{
		Name: "pam-gateway", MaxTTL: s.maxTTL, AllowUserCerts: true, DefaultExtensions: gatewaySSHCertificateExtensions,
	}, sshca.IssueRequest{
		SubjectPublicKey: publicKey, KeyID: rec.SSHKeyID, Principals: []string{rec.SSHPrincipal}, TTL: rec.ExpiresAt.Sub(now),
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return issued.Certificate, issued.ValidBefore, nil
}

// pamSignGatewaySSHKey is the agent channel's hook into PAM, nil when PAM is
// not served (the RPC then answers that gateways are not served).
func (s *Server) pamSignGatewaySSHKey() func(ctx context.Context, tenantID, agentID string, payload, publicKey []byte) ([]byte, time.Time, error) {
	if s.pam == nil {
		return nil
	}
	return s.pam.signGatewaySSHKey
}

// reviewedDesktopClipboard is a desktop session's clipboard policy as its
// reviewers approved it (A269): the approval's pam-desktop-clipboard evidence,
// deny when it has none (or the session had no approval).
func (s *pamService) reviewedDesktopClipboard(ctx context.Context, rec store.PAMSession) (string, error) {
	if rec.ApprovalRequestID == "" {
		return "deny", nil
	}
	approval, err := s.store.GetOperationApproval(ctx, rec.TenantID, rec.ApprovalRequestID)
	if err != nil {
		return "", err
	}
	for _, ref := range approval.EvidenceRefs {
		if policy, ok := strings.CutPrefix(ref, "pam-desktop-clipboard:"); ok {
			return policy, nil
		}
	}
	return "deny", nil
}
