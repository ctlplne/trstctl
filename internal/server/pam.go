// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
	"trstctl.com/trstctl/internal/store"
)

const (
	pamTargetPostgres = "postgres"
	pamTargetSSH      = "ssh"

	defaultPAMTTL            = 15 * time.Minute
	defaultPAMMaxTTL         = time.Hour
	defaultPAMExpiryInterval = 30 * time.Second
)

// PAMConfig enables the served just-in-time privileged-access broker (PAM-01/F33).
// Postgres targets use real scoped login roles; SSH targets use the signer-backed
// SSH CA. Empty leaves the API fail-closed.
type PAMConfig struct {
	Enabled         bool
	DefaultTTL      time.Duration
	MaxTTL          time.Duration
	ExpiryInterval  time.Duration
	Attestors       []attest.Attestor
	PostgresTargets []PAMPostgresTarget
	SSHTargets      []PAMSSHTarget
}

type PAMPostgresTarget struct {
	ID             string
	DSN            []byte
	Database       string
	Schema         string
	UsernamePrefix string
}

type PAMSSHTarget struct {
	ID         string
	Host       string
	Port       int
	Principals []string
}

type pamService struct {
	store          *store.Store
	log            *events.Log
	projector      *projections.Projector
	audit          auditsink.Auditor
	attestors      []attest.Attestor
	methods        map[string]struct{}
	postgres       map[string]*pamPostgresTarget
	sshTargets     map[string]PAMSSHTarget
	sshCA          *sshca.CA
	defaultTTL     time.Duration
	maxTTL         time.Duration
	expiryInterval time.Duration
	clock          func() time.Time
}

type pamPostgresTarget struct {
	cfg     PAMPostgresTarget
	backend *dynsecret.PostgresBackend
}

type pamDeps struct {
	Config PAMConfig
	Store  *store.Store
	Log    *events.Log
	SSHCA  *sshca.CA
	Audit  auditsink.Auditor
	Clock  func() time.Time
}

func newPAMService(d pamDeps) (*pamService, error) {
	cfg := d.Config
	if !cfg.Enabled {
		return nil, nil
	}
	if d.Store == nil || d.Log == nil {
		return nil, errors.New("server: PAM requires store and event log")
	}
	if len(cfg.Attestors) == 0 {
		return nil, errors.New("server: PAM requires at least one attestor")
	}
	if len(cfg.PostgresTargets) == 0 && len(cfg.SSHTargets) == 0 {
		return nil, errors.New("server: PAM requires at least one target")
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
	clock := d.Clock
	if clock == nil {
		clock = time.Now
	}
	audit := d.Audit
	if audit == nil {
		audit = auditsink.Nop{}
	}
	methods := make(map[string]struct{}, len(cfg.Attestors))
	for _, a := range cfg.Attestors {
		if a == nil || strings.TrimSpace(a.Method()) == "" {
			return nil, errors.New("server: PAM attestor has empty method")
		}
		methods[a.Method()] = struct{}{}
	}
	postgresTargets := make(map[string]*pamPostgresTarget, len(cfg.PostgresTargets))
	for _, target := range cfg.PostgresTargets {
		target.ID = strings.TrimSpace(target.ID)
		if target.ID == "" {
			return nil, errors.New("server: PAM postgres target id is required")
		}
		if _, exists := postgresTargets[target.ID]; exists {
			return nil, fmt.Errorf("server: duplicate PAM postgres target %q", target.ID)
		}
		backend, err := dynsecret.NewPostgresBackend(dynsecret.PostgresConfig{
			DSN: target.DSN, Database: target.Database, Schema: target.Schema, UsernamePrefix: target.UsernamePrefix,
		})
		if err != nil {
			return nil, fmt.Errorf("server: PAM postgres target %q: %w", target.ID, err)
		}
		postgresTargets[target.ID] = &pamPostgresTarget{cfg: target, backend: backend}
	}
	sshTargets := make(map[string]PAMSSHTarget, len(cfg.SSHTargets))
	for _, target := range cfg.SSHTargets {
		target.ID = strings.TrimSpace(target.ID)
		if target.ID == "" {
			return nil, errors.New("server: PAM SSH target id is required")
		}
		if _, exists := sshTargets[target.ID]; exists {
			return nil, fmt.Errorf("server: duplicate PAM SSH target %q", target.ID)
		}
		if d.SSHCA == nil {
			return nil, errors.New("server: PAM SSH targets require the served SSH CA")
		}
		sshTargets[target.ID] = target
	}
	return &pamService{
		store: d.Store, log: d.Log, projector: projections.New(d.Store), audit: audit,
		attestors: cfg.Attestors, methods: methods, postgres: postgresTargets,
		sshTargets: sshTargets, sshCA: d.SSHCA, defaultTTL: defaultTTL,
		maxTTL: maxTTL, expiryInterval: expiryInterval, clock: clock,
	}, nil
}

func (s *Server) OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	return s.pam.OpenPAMSession(ctx, tenantID, idempotencyKey, requester, req)
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

func (s *pamService) OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) (api.PAMSession, error) {
	if err := s.validate(tenantID, idempotencyKey, requester, req); err != nil {
		return api.PAMSession{}, err
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: s.attestors,
		Audit:     s.audit,
	})
	if err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrPAMInvalid, err)
	}
	att, err := verifier.Verify(ctx, req.Method, req.Payload)
	if err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: %v", api.ErrPAMRejected, err)
	}

	id := uuid.NewString()
	now := s.clock().UTC()
	expiresAt := now.Add(s.ttl(req.TTLSeconds))
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
	due, err := s.store.ListDuePAMSessions(ctx, s.clock().UTC(), 100)
	if err != nil {
		return err
	}
	var first error
	for _, rec := range due {
		if err := s.expireSession(ctx, rec); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *pamService) openPostgres(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest) (api.PAMSession, error) {
	target := s.postgres[req.TargetID]
	ref, credential, err := target.backend.Create(ctx, req.Role)
	if err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: postgres target %q refused session: %v", api.ErrPAMRejected, req.TargetID, err)
	}
	session, payload := s.startedPayload(tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, ref, "", 0)
	if err := s.appendProject(ctx, tenantID, projections.EventPAMSessionStarted, payload); err != nil {
		secret.Wipe(credential)
		_ = target.backend.Revoke(context.Background(), ref)
		return api.PAMSession{}, err
	}
	session.Postgres = api.NewPAMPostgresCredential(ref, credential)
	return session, nil
}

func (s *pamService) openSSH(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest) (api.PAMSession, error) {
	target := s.sshTargets[req.TargetID]
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
		TTL:              expiresAt.Sub(now),
	})
	if err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: ssh target %q refused session: %v", api.ErrPAMRejected, req.TargetID, err)
	}
	session, payload := s.startedPayload(tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, req.TargetID, keyID, issued.Serial)
	if err := s.appendProject(ctx, tenantID, projections.EventPAMSessionStarted, payload); err != nil {
		secret.Wipe(issued.Certificate)
		return api.PAMSession{}, err
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
		Reason: req.Reason, StartedAt: now, ExpiresAt: expiresAt, Attestation: att,
		Audit: jsonMap(audit),
	}
	return session, projections.PAMSessionStarted{
		ID: id, TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role,
		Status: api.PAMSessionStatusActive, Subject: att.Subject, RequestedBy: requester,
		Reason: req.Reason, AttestationID: att.ID, BackendRef: backendRef, SSHKeyID: sshKeyID,
		SSHSerial: sshSerial, IdempotencyKey: idempotencyKey, Audit: audit,
		StartedAt: now, ExpiresAt: expiresAt,
	}
}

func (s *pamService) expireSession(ctx context.Context, rec store.PAMSession) error {
	switch rec.TargetType {
	case pamTargetPostgres:
		target := s.postgres[rec.TargetID]
		if target == nil {
			return fmt.Errorf("server: PAM postgres target %q not configured for expiry", rec.TargetID)
		}
		if err := target.backend.Revoke(ctx, rec.BackendRef); err != nil {
			return err
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

func (s *pamService) validate(tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) error {
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
	if req.Method == "" {
		return fmt.Errorf("%w: method is required", api.ErrPAMInvalid)
	}
	if _, ok := s.methods[req.Method]; !ok {
		return fmt.Errorf("%w: unknown attestation method %q", api.ErrPAMInvalid, req.Method)
	}
	if len(req.Payload) == 0 {
		return fmt.Errorf("%w: attestation payload is required", api.ErrPAMInvalid)
	}
	switch req.TargetType {
	case pamTargetPostgres:
		if s.postgres[req.TargetID] == nil {
			return fmt.Errorf("%w: unknown postgres target %q", api.ErrPAMInvalid, req.TargetID)
		}
	case pamTargetSSH:
		if _, ok := s.sshTargets[req.TargetID]; !ok {
			return fmt.Errorf("%w: unknown ssh target %q", api.ErrPAMInvalid, req.TargetID)
		}
		if len(req.SSHPublicKey) == 0 {
			return fmt.Errorf("%w: ssh_public_key is required for ssh targets", api.ErrPAMInvalid)
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
	if len(allowed) == 0 {
		return true
	}
	for _, p := range allowed {
		if p == principal {
			return true
		}
	}
	return false
}

func pamSessionFromStore(rec store.PAMSession) api.PAMSession {
	return api.PAMSession{
		ID: rec.ID, TargetID: rec.TargetID, TargetType: rec.TargetType, Role: rec.Role,
		Status: rec.Status, Subject: rec.Subject, RequestedBy: rec.RequestedBy, Reason: rec.Reason,
		StartedAt: rec.StartedAt, ExpiresAt: rec.ExpiresAt, EndedAt: rec.EndedAt,
		Attestation: attest.Attestation{ID: rec.AttestationID, Subject: rec.Subject},
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
