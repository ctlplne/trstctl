// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/config"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	pamTargetPostgres = "postgres"
	pamTargetSSH      = "ssh"

	defaultPAMTTL            = 15 * time.Minute
	defaultPAMMaxTTL         = time.Hour
	defaultPAMExpiryInterval = 30 * time.Second
	defaultPAMApprovalTTL    = 15 * time.Minute
)

// PAMConfig enables the served just-in-time privileged-access broker (PAM-01/F33).
// Postgres targets use real scoped login roles; SSH targets use the signer-backed
// SSH CA. Every injected target is tenant-bound. An enabled broker may start
// without targets so a tenant registrar can add one through the API.
type PAMConfig struct {
	Enabled           bool
	DefaultTTL        time.Duration
	MaxTTL            time.Duration
	ExpiryInterval    time.Duration
	ApprovalTTL       time.Duration
	RequiredApprovals int
	Attestors         []attest.Attestor
	PostgresTargets   []PAMPostgresTarget
	SSHTargets        []PAMSSHTarget
}

type PAMPostgresTarget struct {
	TenantID string
	ID       string
	// ProviderID references a tenant-bound PostgreSQL dynamic-secret provider.
	// Its admin DSN remains a protected file:/secret:// reference in that provider.
	ProviderID   string
	AllowedRoles []string
}

type PAMSSHTarget struct {
	TenantID   string
	ID         string
	Host       string
	Port       int
	Principals []string
}

type pamService struct {
	store             *store.Store
	log               *events.Log
	projector         *projections.Projector
	audit             auditsink.Auditor
	attestors         []attest.Attestor
	postgres          map[pamTargetID]*pamPostgresTarget
	providers         DynamicSecretProviderRegistry
	kek               seal.KeyWrapper
	outbox            *orchestrator.Outbox
	wakeOutbox        func()
	tenantCrypto      tenantseal.Access
	sshTargets        map[pamTargetID]PAMSSHTarget
	sshCA             *sshca.CA
	sshProtocol       *sshProtocol
	defaultTTL        time.Duration
	maxTTL            time.Duration
	expiryInterval    time.Duration
	clock             func() time.Time
	orch              *orchestrator.Orchestrator
	approvalTTL       time.Duration
	requiredApprovals int
	targetDeps        pamDeps
	// Fault injection for the gap after signing and before the session event.
	// Production leaves this nil; a served test forces the crash edge.
	afterSSHSign func([]byte, uint64) error
}

type pamPostgresTarget struct {
	cfg              PAMPostgresTarget
	roles            map[string]struct{}
	providerRevision string
}

// Target names are tenant-local. In particular, a matching ID in a different
// tenant must never select an administrator DSN or a trusted SSH principal set.
type pamTargetID struct {
	tenantID string
	id       string
}

type pamDeps struct {
	Config       PAMConfig
	Store        *store.Store
	Log          *events.Log
	SSHCA        *sshca.CA
	SSHProtocol  *sshProtocol
	Audit        auditsink.Auditor
	Clock        func() time.Time
	Providers    DynamicSecretProviderRegistry
	KEK          seal.KeyWrapper
	Outbox       *orchestrator.Outbox
	WakeOutbox   func()
	TenantCrypto tenantseal.Access
	Orch         *orchestrator.Orchestrator
}

func newPAMService(d pamDeps) (*pamService, error) {
	cfg := d.Config
	if !cfg.Enabled {
		return nil, nil
	}
	if d.Store == nil || d.Log == nil || d.Orch == nil {
		return nil, errors.New("server: PAM requires store, event log, and approval orchestrator")
	}
	defaultTTL := cfg.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = defaultPAMTTL
	}
	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = defaultPAMMaxTTL
	}
	if defaultTTL > maxTTL {
		defaultTTL = maxTTL
	}
	expiryInterval := cfg.ExpiryInterval
	if expiryInterval <= 0 {
		expiryInterval = defaultPAMExpiryInterval
	}
	approvalTTL := cfg.ApprovalTTL
	if approvalTTL <= 0 {
		approvalTTL = defaultPAMApprovalTTL
	}
	requiredApprovals := cfg.RequiredApprovals
	if requiredApprovals <= 0 {
		requiredApprovals = 2
	}
	clock := d.Clock
	if clock == nil {
		clock = time.Now
	}
	audit := d.Audit
	if audit == nil {
		audit = auditsink.Nop{}
	}
	for _, a := range cfg.Attestors {
		if a == nil || strings.TrimSpace(a.Method()) == "" {
			return nil, errors.New("server: PAM attestor has empty method")
		}
	}
	postgresTargets, err := buildPAMPostgresTargets(d)
	if err != nil {
		return nil, err
	}
	sshTargets, err := buildPAMSSHTargets(d)
	if err != nil {
		return nil, err
	}
	return &pamService{
		store: d.Store, log: d.Log, projector: projections.New(d.Store), audit: audit,
		attestors: cfg.Attestors, postgres: postgresTargets,
		providers: d.Providers, kek: d.KEK, outbox: d.Outbox, wakeOutbox: d.WakeOutbox, tenantCrypto: d.TenantCrypto,
		sshTargets: sshTargets, sshCA: d.SSHCA, sshProtocol: d.SSHProtocol, defaultTTL: defaultTTL,
		maxTTL: maxTTL, expiryInterval: expiryInterval, clock: clock,
		orch: d.Orch, approvalTTL: approvalTTL, requiredApprovals: requiredApprovals,
		targetDeps: d,
	}, nil
}

func buildPAMPostgresTargets(d pamDeps) (map[pamTargetID]*pamPostgresTarget, error) {
	cfg := d.Config
	postgresTargets := make(map[pamTargetID]*pamPostgresTarget, len(cfg.PostgresTargets))
	for _, target := range cfg.PostgresTargets {
		if _, err := uuid.Parse(target.TenantID); err != nil {
			return nil, errors.New("server: PAM postgres target tenant_id must be a UUID")
		}
		target.ID = strings.TrimSpace(target.ID)
		if target.ID == "" {
			return nil, errors.New("server: PAM postgres target id is required")
		}
		key := pamTargetID{target.TenantID, target.ID}
		if _, exists := postgresTargets[key]; exists {
			return nil, fmt.Errorf("server: duplicate PAM postgres target %q in tenant %q", target.ID, target.TenantID)
		}
		if len(target.AllowedRoles) == 0 {
			return nil, fmt.Errorf("server: PAM postgres target %q requires allowed roles", target.ID)
		}
		roles := make(map[string]struct{}, len(target.AllowedRoles))
		for _, role := range target.AllowedRoles {
			if role != "readonly" && role != "writer" {
				return nil, fmt.Errorf("server: PAM postgres target %q has unsupported role %q", target.ID, role)
			}
			if _, exists := roles[role]; exists {
				return nil, fmt.Errorf("server: PAM postgres target %q repeats role %q", target.ID, role)
			}
			roles[role] = struct{}{}
		}
		if target.ProviderID == "" || d.KEK == nil || d.Outbox == nil || d.WakeOutbox == nil {
			return nil, fmt.Errorf("server: PAM postgres target %q requires a durable provider and its outbox dependencies", target.ID)
		}
		var matched bool
		var providerRevision string
		for _, provider := range d.Providers.ForTenant(target.TenantID) {
			if provider == nil || provider.Name() != target.ProviderID {
				continue
			}
			profile, ok := provider.(interface {
				DynamicSecretProviderType() string
				DynamicSecretAllowedRoles() []string
				DynamicSecretConfigurationRevision() string
			})
			if !ok || profile.DynamicSecretProviderType() != "postgresql" {
				return nil, fmt.Errorf("server: PAM target %q provider must be PostgreSQL", target.ID)
			}
			providerRevision = profile.DynamicSecretConfigurationRevision()
			if providerRevision == "" {
				return nil, fmt.Errorf("server: PAM target %q provider has no configuration revision", target.ID)
			}
			providerRoles := make(map[string]bool)
			for _, role := range profile.DynamicSecretAllowedRoles() {
				providerRoles[role] = true
			}
			for role := range roles {
				if !providerRoles[role] {
					return nil, fmt.Errorf("server: PAM target %q role %q is not enabled on its provider", target.ID, role)
				}
			}
			matched = true
			break
		}
		if !matched {
			return nil, fmt.Errorf("server: PAM target %q provider %q is not configured for its tenant", target.ID, target.ProviderID)
		}
		postgresTargets[key] = &pamPostgresTarget{cfg: target, roles: roles, providerRevision: providerRevision}
	}
	return postgresTargets, nil
}

func buildPAMSSHTargets(d pamDeps) (map[pamTargetID]PAMSSHTarget, error) {
	cfg := d.Config
	sshTargets := make(map[pamTargetID]PAMSSHTarget, len(cfg.SSHTargets))
	for _, target := range cfg.SSHTargets {
		if _, err := uuid.Parse(target.TenantID); err != nil {
			return nil, errors.New("server: PAM SSH target tenant_id must be a UUID")
		}
		target.ID = strings.TrimSpace(target.ID)
		if target.ID == "" {
			return nil, errors.New("server: PAM SSH target id is required")
		}
		key := pamTargetID{target.TenantID, target.ID}
		if _, exists := sshTargets[key]; exists {
			return nil, fmt.Errorf("server: duplicate PAM SSH target %q in tenant %q", target.ID, target.TenantID)
		}
		if strings.TrimSpace(target.Host) == "" || target.Port < 1 || target.Port > 65535 {
			return nil, fmt.Errorf("server: PAM SSH target %q requires a host and TCP port", target.ID)
		}
		if len(target.Principals) == 0 {
			return nil, fmt.Errorf("server: PAM SSH target %q requires explicit principals", target.ID)
		}
		for _, principal := range target.Principals {
			if strings.TrimSpace(principal) == "" || principal == "*" {
				return nil, fmt.Errorf("server: PAM SSH target %q has an invalid principal", target.ID)
			}
		}
		if d.SSHCA == nil {
			return nil, errors.New("server: PAM SSH targets require the served SSH CA")
		}
		if d.SSHProtocol == nil || target.TenantID != d.SSHProtocol.tenantID {
			return nil, fmt.Errorf("server: PAM SSH target %q requires its tenant-bound served KRL", target.ID)
		}
		sshTargets[key] = target
	}
	return sshTargets, nil
}

func (s *Server) OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	return s.pam.OpenPAMSession(ctx, tenantID, idempotencyKey, requester, req)
}

func (s *Server) RequestPAMSession(ctx context.Context, tenantID, requester string, req api.PAMSessionRequest) (api.PAMApprovalRequest, error) {
	if s.pam == nil {
		return api.PAMApprovalRequest{}, api.ErrPAMUnavailable
	}
	return s.pam.RequestPAMSession(ctx, tenantID, requester, req)
}

func (s *Server) GetPAMRequestProgress(ctx context.Context, tenantID, requester, approvalID string) (api.PAMRequestProgress, error) {
	if s.pam == nil {
		return api.PAMRequestProgress{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMRequestProgress(ctx, tenantID, requester, approvalID)
}

func (s *pamService) GetPAMRequestProgress(ctx context.Context, tenantID, requester, approvalID string) (api.PAMRequestProgress, error) {
	if _, err := uuid.Parse(approvalID); err != nil || requester == "" {
		return api.PAMRequestProgress{}, store.ErrApprovalRequestNotFound
	}
	row, err := s.store.GetOperationApproval(ctx, tenantID, approvalID)
	if err != nil {
		return api.PAMRequestProgress{}, err
	}
	if row.ResourceKind != "pam" || row.Action != "activate" || row.Requester != requester || !strings.HasPrefix(row.ResourceID, "pam:") {
		return api.PAMRequestProgress{}, store.ErrApprovalRequestNotFound
	}
	status := row.Status
	if (status == store.ApprovalStatusPending || status == store.ApprovalStatusApproved) && !time.Now().Before(row.ExpiresAt) {
		status = store.ApprovalStatusExpired
	}
	return api.PAMRequestProgress{
		RequestID: strings.TrimPrefix(row.ResourceID, "pam:"), ApprovalRequestID: row.ID,
		IntentDigest: row.IntentDigest, Status: status,
		ApprovalCount: row.ApprovalCount, RequiredApprovals: row.RequiredApprovals,
		ExpiresAt: row.ExpiresAt,
	}, nil
}

// RequestPAMSession records only a reviewable intent. It performs no target
// call, credential issuance, signer operation, or session-state transition.
func (s *pamService) RequestPAMSession(ctx context.Context, tenantID, requester string, req api.PAMSessionRequest) (api.PAMApprovalRequest, error) {
	if _, err := uuid.Parse(req.RequestID); err != nil {
		return api.PAMApprovalRequest{}, fmt.Errorf("%w: request_id must be a UUID", api.ErrPAMInvalid)
	}
	if err := s.validate(ctx, tenantID, req.RequestID, requester, req); err != nil {
		return api.PAMApprovalRequest{}, err
	}
	_, att, err := s.verifyAttestation(ctx, tenantID, req)
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	if err := s.validateAttestedTarget(ctx, tenantID, req, att); err != nil {
		return api.PAMApprovalRequest{}, err
	}
	commandDigest, err := s.approvalCommandDigest(ctx, tenantID, requester, req, att)
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	targetEvidence, err := s.targetReviewEvidence(ctx, tenantID, req, att)
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	evidenceRefs := append([]string{
		"pam-command-sha256:" + commandDigest,
		"pam-attestor:" + att.Method,
		"pam-subject:" + att.Subject,
		"pam-ttl-seconds:" + fmt.Sprint(int64(s.ttl(req.TTLSeconds)/time.Second)),
	}, targetEvidence...)
	approval, err := s.orch.EnsureOperationApprovalRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "pam", ResourceID: "pam:" + req.RequestID,
		ResourceName: req.TargetType + "/" + req.TargetID + ":" + req.Role,
		Action:       "activate", Requester: requester,
		FromState: "attested", ToState: "active", TargetVersion: 0,
		Reason:            req.Reason,
		EvidenceRefs:      evidenceRefs,
		RequiredApprovals: s.requiredApprovals, TTL: s.approvalTTL,
	})
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	return api.PAMApprovalRequest{
		RequestID: req.RequestID, ApprovalRequestID: approval.ID,
		IntentDigest: approval.IntentDigest, Status: approval.Status,
		Subject: att.Subject, TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role,
		ApprovalCount: approval.ApprovalCount, RequiredApprovals: approval.RequiredApprovals,
		ExpiresAt: approval.ExpiresAt,
	}, nil
}

// Reviewers see the operator-configured destination as well as the hash that
// binds it. The administrator DSN remains private in its provider reference.
func (s *pamService) targetReviewEvidence(ctx context.Context, tenantID string, req api.PAMSessionRequest, att attest.Attestation) ([]string, error) {
	switch req.TargetType {
	case pamTargetPostgres:
		target, err := s.postgresTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return nil, err
		}
		cfg := target.cfg
		return []string{"pam-postgres-provider:" + cfg.ProviderID}, nil
	case pamTargetSSH:
		cfg, err := s.sshTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return nil, err
		}
		principal := req.SSHPrincipal
		if principal == "" {
			principal = att.Subject
		}
		return []string{
			"pam-ssh-host:" + cfg.Host + ":" + fmt.Sprint(cfg.Port),
			"pam-ssh-principal:" + principal,
		}, nil
	default:
		return nil, fmt.Errorf("%w: unknown target type", api.ErrPAMInvalid)
	}
}

func (s *pamService) approvalCommandDigest(ctx context.Context, tenantID, requester string, req api.PAMSessionRequest, att attest.Attestation) (string, error) {
	targetDigest, err := s.targetDigest(ctx, tenantID, req)
	if err != nil {
		return "", err
	}
	command := struct {
		TenantID, RequestID, Requester, TargetType, TargetID, Role, Reason             string
		Method, PayloadDigest, SSHPublicKeyDigest, SSHPrincipal, Subject, TargetDigest string
		Selectors                                                                      []string
		Claims                                                                         map[string]string
		TTLSeconds                                                                     int64
	}{
		TenantID: tenantID, RequestID: req.RequestID, Requester: requester,
		TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role, Reason: req.Reason,
		Method: req.Method, PayloadDigest: crypto.SHA256Hex(req.Payload),
		SSHPublicKeyDigest: crypto.SHA256Hex(req.SSHPublicKey), SSHPrincipal: req.SSHPrincipal,
		Subject: att.Subject, Selectors: att.Selectors, Claims: att.Claims, TargetDigest: targetDigest,
		TTLSeconds: int64(s.ttl(req.TTLSeconds) / time.Second),
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	return crypto.SHA256Hex(append([]byte("trstctl:pam-session-request:v1\x00"), raw...)), nil
}

func (s *pamService) validateAttestedTarget(ctx context.Context, tenantID string, req api.PAMSessionRequest, att attest.Attestation) error {
	if req.TargetType != pamTargetSSH {
		return nil
	}
	target, err := s.sshTarget(ctx, tenantID, req.TargetID)
	if err != nil {
		return err
	}
	principal := req.SSHPrincipal
	if principal == "" {
		principal = att.Subject
	}
	if !principalAllowed(target.Principals, principal) {
		return fmt.Errorf("%w: principal %q is not allowed on target %q", api.ErrPAMRejected, principal, req.TargetID)
	}
	return nil
}

func (s *pamService) targetDigest(ctx context.Context, tenantID string, req api.PAMSessionRequest) (string, error) {
	var target any
	switch req.TargetType {
	case pamTargetPostgres:
		configured, err := s.postgresTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return "", err
		}
		cfg := configured.cfg
		cfg.AllowedRoles = append([]string(nil), cfg.AllowedRoles...)
		sort.Strings(cfg.AllowedRoles)
		target = struct {
			Config           PAMPostgresTarget
			ProviderRevision string
		}{Config: cfg, ProviderRevision: configured.providerRevision}
	case pamTargetSSH:
		cfg, err := s.sshTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return "", err
		}
		cfg.Principals = append([]string(nil), cfg.Principals...)
		sort.Strings(cfg.Principals)
		target = cfg
	default:
		return "", fmt.Errorf("%w: unknown target type", api.ErrPAMInvalid)
	}
	raw, err := json.Marshal(target)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	return crypto.SHA256Hex(raw), nil
}

func (s *Server) GetPAMSession(ctx context.Context, tenantID, id string) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMSession(ctx, tenantID, id)
}

func (s *Server) ListPAMSessions(ctx context.Context, tenantID string, limit int, cursor string) ([]api.PAMSession, string, error) {
	if s.pam == nil {
		return nil, "", api.ErrPAMUnavailable
	}
	return s.pam.ListPAMSessions(ctx, tenantID, limit, cursor)
}

func (s *Server) RunPAMSessionExpiry(ctx context.Context) {
	if s.pam == nil {
		<-ctx.Done()
		return
	}
	s.pam.RunExpiry(ctx)
}

func (s *Server) RevokePAMSession(ctx context.Context, tenantID, id, requester, reason, idempotencyKey string) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	return s.pam.RevokePAMSession(ctx, tenantID, id, requester, reason, idempotencyKey)
}

func (s *pamService) RevokePAMSession(ctx context.Context, tenantID, id, requester, reason, idempotencyKey string) (api.PAMSession, error) {
	if _, err := uuid.Parse(id); err != nil {
		return api.PAMSession{}, pgx.ErrNoRows
	}
	rec, err := s.store.GetPAMSession(ctx, tenantID, id)
	if err != nil {
		return api.PAMSession{}, err
	}
	if rec.Status != api.PAMSessionStatusActive && rec.Status != store.PAMSessionStatusRevocationFailed {
		return api.PAMSession{}, api.ErrPAMTerminal
	}
	if requester == "" || strings.TrimSpace(reason) == "" || idempotencyKey == "" ||
		(rec.Status == store.PAMSessionStatusRevocationFailed && idempotencyKey == rec.RevocationIdempotencyKey) {
		return api.PAMSession{}, api.ErrPAMInvalid
	}
	if rec.TargetType == pamTargetSSH && (s.sshProtocol == nil || s.sshProtocol.tenantID != tenantID) {
		return api.PAMSession{}, fmt.Errorf("%w: tenant SSH revocation list is unavailable", api.ErrPAMRejected)
	}
	at := s.clock().UTC()
	if err := s.appendProject(ctx, tenantID, projections.EventPAMSessionRevocationRequested, projections.PAMSessionRevocationRequested{
		ID: id, RequestedBy: requester, Reason: reason, RequestedAt: at,
		IdempotencyKey: idempotencyKey,
		SSHSerial:      rec.SSHSerial, SSHKeyID: rec.SSHKeyID,
	}); err != nil {
		return api.PAMSession{}, err
	}
	current, err := s.GetPAMSession(ctx, tenantID, id)
	if err != nil {
		return api.PAMSession{}, err
	}
	if (current.Status != store.PAMSessionStatusRevoking && current.Status != store.PAMSessionStatusRevoked) ||
		current.RevocationRequestedBy != requester || current.RevocationReason != reason {
		return api.PAMSession{}, api.ErrPAMTerminal
	}
	return current, nil
}

func (s *pamService) OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) (api.PAMSession, error) {
	if err := s.validate(ctx, tenantID, idempotencyKey, requester, req); err != nil {
		return api.PAMSession{}, err
	}
	if _, err := uuid.Parse(req.RequestID); err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: request_id must be a UUID", api.ErrPAMInvalid)
	}
	if _, err := uuid.Parse(req.ApprovalRequestID); err != nil || req.IntentDigest == "" {
		return api.PAMSession{}, fmt.Errorf("%w: an exact approval_request_id and intent_digest are required", api.ErrPAMInvalid)
	}
	// The HTTP result cache is time-bounded, while a PAM session is retained for
	// audit. Once that cache has aged out, the same key must never mint another
	// SSH certificate or reopen a PostgreSQL grant under the old session ID.
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-session\x00"+tenantID+"\x00"+idempotencyKey)).String()
	if _, err := s.store.GetPAMSession(ctx, tenantID, id); err == nil {
		return api.PAMSession{}, fmt.Errorf("%w: PAM session already exists for this key", orchestrator.ErrIdempotencyConflict)
	} else if !store.IsNotFound(err) {
		return api.PAMSession{}, err
	}
	verifier, att, err := s.verifyAttestation(ctx, tenantID, req)
	if err != nil {
		return api.PAMSession{}, err
	}
	if err := s.validateAttestedTarget(ctx, tenantID, req, att); err != nil {
		return api.PAMSession{}, err
	}
	if req.TargetType == pamTargetSSH {
		var session api.PAMSession
		acquired, err := s.store.WithPAMSSHActivationFence(ctx, tenantID, id, func() error {
			if _, lookupErr := s.store.GetPAMSSHActivation(ctx, tenantID, id); lookupErr == nil {
				return fmt.Errorf("%w: SSH signing was already attempted for this idempotency key; inspect recovery audit and start a fresh approved request", orchestrator.ErrIdempotencyConflict)
			} else if !store.IsNotFound(lookupErr) {
				return lookupErr
			}
			var openErr error
			session, openErr = s.activatePAMSession(ctx, tenantID, idempotencyKey, requester, id, verifier, att, req)
			return openErr
		})
		if err != nil {
			return api.PAMSession{}, err
		}
		if !acquired {
			return api.PAMSession{}, fmt.Errorf("%w: SSH activation or recovery is in progress; retry the same HTTP request", api.ErrPAMRejected)
		}
		return session, nil
	}
	return s.activatePAMSession(ctx, tenantID, idempotencyKey, requester, id, verifier, att, req)
}

func (s *pamService) activatePAMSession(ctx context.Context, tenantID, idempotencyKey, requester, id string, verifier *attest.Verifier, att attest.Attestation, req api.PAMSessionRequest) (api.PAMSession, error) {
	now, err := s.authorizeActivation(ctx, tenantID, idempotencyKey, requester, id, req, att)
	if err != nil {
		return api.PAMSession{}, err
	}
	expiresAt := now.Add(s.ttl(req.TTLSeconds))
	if !s.clock().UTC().Before(expiresAt) {
		return api.PAMSession{}, fmt.Errorf("%w: approved PAM activation expired before grant completion", api.ErrPAMRejected)
	}
	if err := verifier.Bind(ctx, att, "pam:"+id); err != nil {
		return api.PAMSession{}, fmt.Errorf("server: bind PAM attestation: %w", err)
	}

	switch req.TargetType {
	case pamTargetPostgres:
		return s.openPostgres(ctx, tenantID, idempotencyKey, requester, id, now, expiresAt, att, req)
	case pamTargetSSH:
		return s.openSSH(ctx, tenantID, idempotencyKey, requester, id, now, expiresAt, att, req)
	default:
		return api.PAMSession{}, fmt.Errorf("%w: unsupported target_type %q", api.ErrPAMInvalid, req.TargetType)
	}
}

// authorizeActivation appends one canonical, non-secret command while the exact
// approval row is locked. Its projection consumes authority in the same SQL
// transaction. A crash after the append can replay that event with the same
// request and key; no target effect is attempted before this step commits.
func (s *pamService) authorizeActivation(ctx context.Context, tenantID, idempotencyKey, requester, sessionID string, req api.PAMSessionRequest, att attest.Attestation) (time.Time, error) {
	approval, err := s.store.GetOperationApproval(ctx, tenantID, req.ApprovalRequestID)
	if err != nil {
		return time.Time{}, err
	}
	if approval.ResourceKind != "pam" || approval.ResourceID != "pam:"+req.RequestID ||
		approval.Action != "activate" || approval.Requester != requester ||
		approval.IntentDigest != req.IntentDigest {
		return time.Time{}, fmt.Errorf("%w: PAM approval does not belong to this requester and session request", api.ErrPAMRejected)
	}
	digest, err := s.approvalCommandDigest(ctx, tenantID, requester, req, att)
	if err != nil {
		return time.Time{}, err
	}
	if !containsExactString(approval.EvidenceRefs, "pam-command-sha256:"+digest) {
		return time.Time{}, fmt.Errorf("%w: PAM command differs from the approved intent", api.ErrPAMRejected)
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		return time.Time{}, err
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-activation\x00"+tenantID+"\x00"+req.RequestID)).String()
	payload := projections.PAMSessionActivationRequested{
		ID: sessionID, RequestID: req.RequestID, TargetType: req.TargetType, CommandDigest: digest,
		IdempotencyKey: idempotencyKey, TTLSeconds: int64(s.ttl(req.TTLSeconds) / time.Second),
		Approval: use,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return time.Time{}, err
	}
	canonical, found, err := s.log.EventByID(ctx, eventID)
	if err != nil {
		return time.Time{}, err
	}
	if found && (canonical.Type != projections.EventPAMSessionActivationRequested || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, data)) {
		return time.Time{}, fmt.Errorf("%w: PAM request_id already belongs to a different activation", orchestrator.ErrIdempotencyConflict)
	}
	if found && req.TargetType == pamTargetSSH {
		return time.Time{}, fmt.Errorf("%w: SSH signing was already attempted for this approval; inspect recovery audit and start a fresh approved request", api.ErrPAMRejected)
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if !found {
			if _, err := s.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, use, s.clock().UTC()); err != nil {
				return err
			}
			candidate := events.Event{
				ID: eventID, Type: projections.EventPAMSessionActivationRequested,
				TenantID: tenantID, Time: s.clock().UTC().Truncate(time.Microsecond), Data: data,
			}
			if actor, ok := events.ActorFromContext(ctx); ok {
				candidate.Actor = &actor
			}
			canonical, err = s.log.Append(ctx, candidate)
			if err != nil {
				return err
			}
			if canonical.Type != candidate.Type || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, data) {
				return fmt.Errorf("%w: canonical PAM activation differs", orchestrator.ErrIdempotencyConflict)
			}
		}
		return s.projector.ApplyTx(ctx, tx, canonical)
	})
	if err != nil {
		return time.Time{}, err
	}
	return canonical.Time, nil
}

func containsExactString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func (s *pamService) verifyAttestation(ctx context.Context, tenantID string, req api.PAMSessionRequest) (*attest.Verifier, attest.Attestation, error) {
	attestors, err := resolveWorkloadAttestors(ctx, s.store, s.attestors, tenantID, req.Method)
	if err != nil {
		return nil, attest.Attestation{}, fmt.Errorf("server: resolve PAM tenant attester trust: %w", err)
	}
	if len(attestors) == 0 {
		return nil, attest.Attestation{}, fmt.Errorf("%w: tenant has no enabled trust source for method %q", api.ErrPAMRejected, req.Method)
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: attestors,
		Audit:     s.audit,
	})
	if err != nil {
		return nil, attest.Attestation{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrPAMInvalid, err)
	}
	att, err := verifier.Verify(ctx, req.Method, req.Payload)
	if err != nil {
		return nil, attest.Attestation{}, fmt.Errorf("%w: %v", api.ErrPAMRejected, err)
	}
	return verifier, att, nil
}

func (s *pamService) GetPAMSession(ctx context.Context, tenantID, id string) (api.PAMSession, error) {
	rec, err := s.store.GetPAMSession(ctx, tenantID, id)
	if err != nil {
		return api.PAMSession{}, err
	}
	return pamSessionFromStore(rec), nil
}

func (s *pamService) ListPAMSessions(ctx context.Context, tenantID string, limit int, _ string) ([]api.PAMSession, string, error) {
	recs, err := s.store.ListPAMSessions(ctx, tenantID, limit)
	if err != nil {
		return nil, "", err
	}
	out := make([]api.PAMSession, 0, len(recs))
	for _, rec := range recs {
		out = append(out, pamSessionFromStore(rec))
	}
	return out, "", nil
}

func (s *pamService) RunExpiry(ctx context.Context) {
	ticker := time.NewTicker(s.expiryInterval)
	defer ticker.Stop()
	for {
		_ = s.expireOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *pamService) expireOnce(ctx context.Context) error {
	first := s.recoverIncompleteSSHActivations(ctx)
	revoking, err := s.store.ListRevokingPAMSessions(ctx, 100)
	if err != nil {
		return errors.Join(first, err)
	}
	for _, rec := range revoking {
		if err := s.revokeSession(ctx, rec); err != nil && first == nil {
			first = err
		}
	}
	due, err := s.store.ListDuePAMSessions(ctx, s.clock().UTC(), 100)
	if err != nil {
		return errors.Join(first, err)
	}
	for _, rec := range due {
		if err := s.expireSession(ctx, rec); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// recoverIncompleteSSHActivations runs after startup and on every expiry tick.
// The per-session PostgreSQL lock distinguishes an active signer call on any
// replica from a process that died after consuming approval. The KRL command is
// durable before the read model claims recovery; failures stay revoking and are
// retried on the next tick.
func (s *pamService) recoverIncompleteSSHActivations(ctx context.Context) error {
	items, err := s.store.ListPendingPAMSSHActivations(ctx, 100)
	if err != nil {
		return err
	}
	var first error
	for _, item := range items {
		acquired, err := s.store.WithPAMSSHActivationFence(ctx, item.TenantID, item.SessionID, func() error {
			// A process may die after the event append but before its SQL
			// projection acknowledgement. Finish that canonical event before
			// deciding an unrecorded signature must be revoked.
			started, found, err := s.log.EventByID(ctx, pamSSHStartedEventID(item.TenantID, item.SessionID))
			if err != nil {
				return err
			}
			if found {
				if started.Type != projections.EventPAMSessionStarted || started.TenantID != item.TenantID {
					return orchestrator.ErrIdempotencyConflict
				}
				if err := s.projector.Apply(ctx, started); err != nil {
					return err
				}
			}
			current, err := s.store.GetPAMSSHActivation(ctx, item.TenantID, item.SessionID)
			if err != nil {
				return err
			}
			if current.Status != "pending" && current.Status != "revoking" {
				return nil
			}
			if s.sshProtocol == nil || s.sshProtocol.tenantID != item.TenantID {
				return fmt.Errorf("server: PAM SSH KRL for tenant %s is unavailable", item.TenantID)
			}
			if current.Status == "pending" {
				if err := s.appendSSHRecoveryEvent(ctx, current, projections.EventPAMSSHSigningRecoveryRequested); err != nil {
					return err
				}
			}
			if err := s.sshProtocol.syncRevocations(ctx, true); err != nil {
				return err
			}
			if !s.sshProtocol.krl.IsRevoked(0, current.KeyID) {
				return errors.New("server: recovered PAM SSH key ID is absent from the served KRL")
			}
			return s.appendSSHRecoveryEvent(ctx, current, projections.EventPAMSSHSigningRecovered)
		})
		if acquired && err != nil && first == nil {
			first = err
		}
		if !acquired {
			continue // another replica still owns the signing attempt
		}
	}
	return first
}

func pamSSHStartedEventID(tenantID, sessionID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-ssh-session-started\x00"+tenantID+"\x00"+sessionID)).String()
}

func (s *pamService) appendSSHSessionStarted(ctx context.Context, tenantID, sessionID string, payload projections.PAMSessionStarted) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e, err := s.log.Append(ctx, events.Event{
		ID: pamSSHStartedEventID(tenantID, sessionID), Type: projections.EventPAMSessionStarted,
		TenantID: tenantID, Data: data,
	})
	if err != nil {
		return err
	}
	if e.Type != projections.EventPAMSessionStarted || e.TenantID != tenantID || !bytes.Equal(e.Data, data) {
		return orchestrator.ErrIdempotencyConflict
	}
	return s.projector.Apply(ctx, e)
}

func (s *pamService) appendSSHRecoveryEvent(ctx context.Context, item store.PAMSSHActivation, eventType string) error {
	payload := projections.PAMSSHSigningRecoveryRequested{
		ID: item.SessionID, KeyID: item.KeyID,
		Reason: "approved SSH signing ended without a recorded session; deterministic key ID revoked",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(eventType+"\x00"+item.TenantID+"\x00"+item.SessionID)).String()
	e, err := s.log.Append(ctx, events.Event{
		ID: eventID, Type: eventType, TenantID: item.TenantID, Data: data,
	})
	if err != nil {
		return err
	}
	if e.Type != eventType || e.TenantID != item.TenantID || !bytes.Equal(e.Data, data) {
		return orchestrator.ErrIdempotencyConflict
	}
	return s.projector.Apply(ctx, e)
}

func (s *pamService) revokeSession(ctx context.Context, rec store.PAMSession) error {
	switch rec.TargetType {
	case pamTargetPostgres:
		lifecycle, err := s.postgresLifecycle(rec.TenantID)
		if err != nil {
			return err
		}
		lease, err := lifecycle.GetLeaseContext(ctx, rec.BackendRef)
		if err != nil {
			return err
		}
		if lease.RevocationCompletedAt == nil {
			if lease.RevocationStatus == "failed" {
				// A completed bound command means its provider attempt was
				// queued and subsequently failed. A fresh retry key has no
				// completed command yet, so it must be allowed to requeue.
				if rec.RevocationIdempotencyKey == "" {
					return s.pamRevocationFailed(ctx, rec)
				}
				op, lookupErr := s.store.GetDynamicSecretOperationByIdempotencyKey(ctx, rec.TenantID, "pam-revoke:"+rec.RevocationIdempotencyKey)
				if lookupErr != nil && !store.IsNotFound(lookupErr) {
					return lookupErr
				}
				if lookupErr == nil && op.Status == store.DynamicSecretOperationCompleted {
					return s.pamRevocationFailed(ctx, rec)
				}
			}
			if rec.RevocationIdempotencyKey != "" {
				binding := crypto.SHA256Hex([]byte("pam-revoke:v1:" + rec.TenantID + ":" + rec.ID + ":" + rec.RevocationRequestedBy + ":" + rec.RevocationReason))
				_, err = lifecycle.RevokeBound(ctx, rec.BackendRef, "pam-revoke:"+rec.RevocationIdempotencyKey, binding)
			} else {
				// Sessions requested by an older event had no attempt key.
				err = lifecycle.Revoke(ctx, rec.BackendRef)
			}
			if err != nil {
				return err
			}
			return nil
		}
	case pamTargetSSH:
		if s.sshProtocol == nil || s.sshProtocol.tenantID != rec.TenantID {
			return fmt.Errorf("server: PAM SSH KRL for tenant %s is unavailable", rec.TenantID)
		}
		if err := s.sshProtocol.syncRevocations(ctx, true); err != nil {
			return err
		}
		if !s.sshProtocol.krl.IsRevoked(rec.SSHSerial, rec.SSHKeyID) {
			return fmt.Errorf("server: PAM SSH revocation absent from served KRL")
		}
	default:
		return fmt.Errorf("server: unknown PAM target type %q", rec.TargetType)
	}
	return s.appendProject(ctx, rec.TenantID, projections.EventPAMSessionRevoked, projections.PAMSessionRevoked{ID: rec.ID, EndedAt: s.clock().UTC()})
}

func (s *pamService) pamRevocationFailed(ctx context.Context, rec store.PAMSession) error {
	return s.appendProject(ctx, rec.TenantID, projections.EventPAMSessionRevocationFailed,
		projections.PAMSessionRevocationFailed{ID: rec.ID, IdempotencyKey: rec.RevocationIdempotencyKey,
			Failure: "PostgreSQL provider removal failed; repair the target and retry revocation", FailedAt: s.clock().UTC()})
}

func (s *pamService) openPostgres(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest) (api.PAMSession, error) {
	target, err := s.postgresTarget(ctx, tenantID, req.TargetID)
	if err != nil {
		return api.PAMSession{}, err
	}
	return s.openPostgresProvider(ctx, tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, target)
}

func (s *pamService) postgresLifecycle(tenantID string) (*durableDynamicSecretLifecycle, error) {
	return newDurableDynamicSecretLifecycle(tenantID, s.providers.ForTenant(tenantID),
		s.store, s.log, s.kek, s.outbox, s.wakeOutbox, s.tenantCrypto)
}

func (s *pamService) openPostgresProvider(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest, target *pamPostgresTarget) (api.PAMSession, error) {
	lifecycle, err := s.postgresLifecycle(tenantID)
	if err != nil {
		return api.PAMSession{}, err
	}
	material, err := json.Marshal(struct {
		Tenant, Requester, Target, Role, Reason, Method, Subject, PayloadDigest string
		TTLSeconds                                                              int64
	}{tenantID, requester, req.TargetID, req.Role, req.Reason, req.Method, att.Subject,
		crypto.SHA256Hex(req.Payload), req.TTLSeconds})
	if err != nil {
		return api.PAMSession{}, err
	}
	binding := crypto.SHA256Hex(material)
	secret.Wipe(material)
	lease, credential, err := lifecycle.IssueBoundNonRenewable(ctx, target.cfg.ProviderID, req.Role,
		expiresAt.Sub(s.clock().UTC()), "pam-postgres:"+idempotencyKey, binding)
	if err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: postgres target %q refused session: %v", api.ErrPAMRejected, req.TargetID, err)
	}
	session, payload := s.startedPayload(tenantID, idempotencyKey, requester, id, now, lease.ExpiresAt, att, req, lease.ID, "", 0)
	if err := s.appendProject(ctx, tenantID, projections.EventPAMSessionStarted, payload); err != nil {
		secret.Wipe(credential)
		_ = lifecycle.Revoke(context.Background(), lease.ID)
		return api.PAMSession{}, err
	}
	session.Postgres = api.NewPAMPostgresCredential(lease.BackendRef, credential)
	return session, nil
}

func (s *pamService) openSSH(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest) (api.PAMSession, error) {
	target, err := s.sshTarget(ctx, tenantID, req.TargetID)
	if err != nil {
		return api.PAMSession{}, err
	}
	principal := req.SSHPrincipal
	if principal == "" {
		principal = att.Subject
	}
	if !principalAllowed(target.Principals, principal) {
		return api.PAMSession{}, fmt.Errorf("%w: principal %q is not allowed on target %q", api.ErrPAMRejected, principal, req.TargetID)
	}
	keyID := "pam:" + id
	issued, err := s.sshCA.IssueUserCert(ctx, sshca.Profile{
		Name:           "pam-jit",
		MaxTTL:         s.maxTTL,
		AllowUserCerts: true,
		DefaultExtensions: map[string]string{
			"permit-pty":              "",
			"permit-user-rc":          "",
			"permit-port-forwarding":  "",
			"permit-agent-forwarding": "",
		},
	}, sshca.IssueRequest{
		SubjectPublicKey: req.SSHPublicKey,
		KeyID:            keyID,
		Principals:       []string{principal},
		TTL:              expiresAt.Sub(s.clock().UTC()),
	})
	if err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: ssh target %q refused session: %v", api.ErrPAMRejected, req.TargetID, err)
	}
	if s.afterSSHSign != nil {
		if err := s.afterSSHSign(issued.Certificate, issued.Serial); err != nil {
			secret.Wipe(issued.Certificate)
			return api.PAMSession{}, err
		}
	}
	session, payload := s.startedPayload(tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, req.TargetID, keyID, issued.Serial)
	if err := s.appendSSHSessionStarted(ctx, tenantID, id, payload); err != nil {
		secret.Wipe(issued.Certificate)
		return api.PAMSession{}, err
	}
	activation, err := s.store.GetPAMSSHActivation(ctx, tenantID, id)
	if err != nil || activation.Status != "completed" {
		secret.Wipe(issued.Certificate)
		return api.PAMSession{}, fmt.Errorf("%w: SSH activation was not durably completed", api.ErrPAMRejected)
	}
	session.SSH = api.NewPAMSSHCredential(issued.Certificate, principal, keyID, issued.Serial, issued.ValidBefore)
	return session, nil
}

func (s *pamService) startedPayload(tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest, backendRef, sshKeyID string, sshSerial uint64) (api.PAMSession, projections.PAMSessionStarted) {
	audit := json.RawMessage(`{}`)
	if data, err := json.Marshal(map[string]any{
		"target_type":  req.TargetType,
		"target_id":    req.TargetID,
		"role":         req.Role,
		"requested_by": requester,
		"subject":      att.Subject,
		"method":       att.Method,
	}); err == nil {
		audit = data
	}
	session := api.PAMSession{
		ID: id, TargetID: req.TargetID, TargetType: req.TargetType, Role: req.Role,
		Status: api.PAMSessionStatusActive, Subject: att.Subject, RequestedBy: requester,
		Reason: req.Reason, StartedAt: now, ExpiresAt: expiresAt, Attestation: &att,
		Audit: jsonMap(audit),
	}
	return session, projections.PAMSessionStarted{
		ID: id, TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role,
		Status: api.PAMSessionStatusActive, Subject: att.Subject, RequestedBy: requester,
		Reason: req.Reason, AttestationID: att.ID, Attestation: &att, BackendRef: backendRef, SSHKeyID: sshKeyID,
		SSHSerial: sshSerial, IdempotencyKey: idempotencyKey, Audit: audit,
		StartedAt: now, ExpiresAt: expiresAt,
	}
}

func (s *pamService) expireSession(ctx context.Context, rec store.PAMSession) error {
	switch rec.TargetType {
	case pamTargetPostgres:
		lifecycle, err := s.postgresLifecycle(rec.TenantID)
		if err != nil {
			return err
		}
		if err := lifecycle.Revoke(ctx, rec.BackendRef); err != nil {
			return err
		}
		lease, err := lifecycle.GetLeaseContext(ctx, rec.BackendRef)
		if err != nil {
			return err
		}
		if lease.RevocationCompletedAt == nil {
			return nil // outbox has the removal intent; a later tick observes completion
		}
	case pamTargetSSH:
		// SSH user certificates auto-expire cryptographically. The read model still
		// records expiry evidence so audit and session lists do not depend on a client
		// attempting to use the cert after its ValidBefore.
	default:
		return fmt.Errorf("server: PAM session %s has unknown target_type %q", rec.ID, rec.TargetType)
	}
	endedAt := s.clock().UTC()
	return s.appendProject(ctx, rec.TenantID, projections.EventPAMSessionExpired, projections.PAMSessionExpired{
		ID: rec.ID, EndedAt: endedAt, Reason: "ttl elapsed",
	})
}

func (s *pamService) appendProject(ctx context.Context, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e, err := s.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	return s.projector.Apply(ctx, e)
}

func (s *pamService) validate(ctx context.Context, tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) error {
	if tenantID == "" {
		return fmt.Errorf("%w: tenant id is required", api.ErrPAMInvalid)
	}
	if idempotencyKey == "" {
		return fmt.Errorf("%w: idempotency key is required", api.ErrPAMInvalid)
	}
	if requester == "" {
		return fmt.Errorf("%w: requester is required", api.ErrPAMInvalid)
	}
	if req.TargetType != pamTargetPostgres && req.TargetType != pamTargetSSH {
		return fmt.Errorf("%w: target_type must be postgres or ssh", api.ErrPAMInvalid)
	}
	if req.TargetID == "" {
		return fmt.Errorf("%w: target_id is required", api.ErrPAMInvalid)
	}
	if req.Role == "" {
		return fmt.Errorf("%w: role is required", api.ErrPAMInvalid)
	}
	if req.TTLSeconds < 0 || req.TTLSeconds > int64(s.maxTTL/time.Second) {
		return fmt.Errorf("%w: ttl_seconds must be between 0 and %d", api.ErrPAMInvalid, int64(s.maxTTL/time.Second))
	}
	if req.Method == "" {
		return fmt.Errorf("%w: method is required", api.ErrPAMInvalid)
	}
	if len(req.Payload) == 0 {
		return fmt.Errorf("%w: attestation payload is required", api.ErrPAMInvalid)
	}
	switch req.TargetType {
	case pamTargetPostgres:
		target, err := s.postgresTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return err
		}
		if _, allowed := target.roles[req.Role]; !allowed {
			return fmt.Errorf("%w: role %q is not allowed on postgres target %q", api.ErrPAMInvalid, req.Role, req.TargetID)
		}
	case pamTargetSSH:
		if _, err := s.sshTarget(ctx, tenantID, req.TargetID); err != nil {
			return err
		}
		if len(req.SSHPublicKey) == 0 {
			return fmt.Errorf("%w: ssh_public_key is required for ssh targets", api.ErrPAMInvalid)
		}
		if req.Role != "user" {
			return fmt.Errorf("%w: SSH target role must be user", api.ErrPAMInvalid)
		}
	}
	return nil
}

func (s *pamService) ttl(seconds int64) time.Duration {
	if seconds <= 0 {
		return s.defaultTTL
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl <= 0 {
		return s.defaultTTL
	}
	if ttl > s.maxTTL {
		return s.maxTTL
	}
	return ttl
}

func principalAllowed(allowed []string, principal string) bool {
	if principal == "" {
		return false
	}
	for _, p := range allowed {
		if p == principal {
			return true
		}
	}
	return false
}

func pamSessionFromStore(rec store.PAMSession) api.PAMSession {
	var verified *attest.Attestation
	if len(rec.Attestation) != 0 {
		var candidate attest.Attestation
		if err := json.Unmarshal(rec.Attestation, &candidate); err == nil &&
			candidate.ID == rec.AttestationID && candidate.Subject == rec.Subject &&
			candidate.Method != "" && !candidate.VerifiedAt.IsZero() {
			verified = &candidate
		}
	}
	return api.PAMSession{
		ID: rec.ID, TargetID: rec.TargetID, TargetType: rec.TargetType, Role: rec.Role,
		Status: rec.Status, Subject: rec.Subject, RequestedBy: rec.RequestedBy, Reason: rec.Reason,
		StartedAt: rec.StartedAt, ExpiresAt: rec.ExpiresAt, EndedAt: rec.EndedAt,
		RevocationRequestedBy: rec.RevocationRequestedBy, RevocationReason: rec.RevocationReason,
		RevocationRequestedAt: rec.RevocationRequestedAt,
		RevocationFailure:     rec.RevocationFailure, RevocationFailedAt: rec.RevocationFailedAt,
		Attestation: verified,
		Audit:       jsonMap(rec.Audit),
	}
}

func jsonMap(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// pamFromConfig maps the operator's secret-free target references onto the
// broker. The provider's protected administrator ref stays in its own config;
// tenant-managed attester trust is resolved per request.
func pamFromConfig(c config.PAM) PAMConfig {
	out := PAMConfig{Enabled: c.Enabled, RequiredApprovals: c.RequiredApprovals}
	if d, err := time.ParseDuration(strings.TrimSpace(c.DefaultTTL)); err == nil {
		out.DefaultTTL = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.MaxTTL)); err == nil {
		out.MaxTTL = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.ExpiryInterval)); err == nil {
		out.ExpiryInterval = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.ApprovalTTL)); err == nil {
		out.ApprovalTTL = d
	}
	for _, target := range c.PostgresTargets {
		out.PostgresTargets = append(out.PostgresTargets, PAMPostgresTarget{
			TenantID: target.TenantID, ID: target.ID, ProviderID: target.ProviderID,
			AllowedRoles: append([]string(nil), target.AllowedRoles...),
		})
	}
	for _, target := range c.SSHTargets {
		out.SSHTargets = append(out.SSHTargets, PAMSSHTarget{
			TenantID: target.TenantID, ID: target.ID, Host: target.Host, Port: target.Port,
			Principals: append([]string(nil), target.Principals...),
		})
	}
	return out
}
