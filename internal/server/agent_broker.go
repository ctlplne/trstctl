// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/broker"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

const (
	defaultBrokerCredentialTTL = 10 * time.Minute
	maxBrokerCredentialTTL     = time.Hour
)

var brokerAgentOwnerNamespace = uuid.MustParse("d05321d7-6867-5c89-90d6-3a7b0f0a6103")

// AgentBrokerConfig turns on the served AI-agent / NHI broker (F61). It is
// explicit because it mints credentials: the operator/test harness supplies the
// attesters, trust domain, and policy module. Empty leaves the route fail-closed.
type AgentBrokerConfig struct {
	Enabled      bool
	TrustDomain  string
	DefaultTTL   time.Duration
	MaxTTL       time.Duration
	Attestors    []attest.Attestor
	PolicyModule string
}

type agentBrokerService struct {
	trustDomain string
	defaultTTL  time.Duration
	maxTTL      time.Duration
	attestors   []attest.Attestor
	methods     map[string]struct{}
	policy      broker.PolicyGate
	audit       auditsink.Auditor
	store       *store.Store
	log         *events.Log
	orch        *orchestrator.Orchestrator
	caSigner    crypto.DigestSigner
	caCertDER   []byte
	caID        string
	// issuancePrecondition is the feature-neutral chain-bound issuance precondition
	// supplied only by the tagged EE attach seam (Deps.BrokerIssuancePrecondition). It
	// is passed to broker.New via broker.WithIssuancePrecondition so the broker consults
	// it ONLY on its chain-bound issuance path (broker.IssueChainBound). Nil in
	// Community / core-only builds, leaving the seam inert and the free single-hop badge
	// (broker.Issue) unaffected (INV-A10 zero removal). The core names only the generic
	// seam type; what the precondition verifies lives entirely in the edition.
	issuancePrecondition broker.IssuancePrecondition
	// taskEnvelopeGate is the feature-neutral AGID-05 task-envelope gate (B-7),
	// supplied only by the tagged EE attach seam. Core never interprets envelope
	// bytes; it only enforces the rule that makes the binding meaningful — see
	// bindTaskEnvelope.
	taskEnvelopeGate BrokerTaskEnvelopeGate
}

type agentBrokerDeps struct {
	Config               AgentBrokerConfig
	Store                *store.Store
	Log                  *events.Log
	Orch                 *orchestrator.Orchestrator
	CASigner             crypto.DigestSigner
	CACertDER            []byte
	CAID                 string
	Audit                auditsink.Auditor
	Policy               *policy.Engine
	IssuancePrecondition broker.IssuancePrecondition
	// TaskEnvelopeGate is the AGID-05 task-envelope gate (B-7); nil in
	// Community / core-only builds, where an envelope-bearing request is
	// refused rather than downgraded.
	TaskEnvelopeGate BrokerTaskEnvelopeGate
}

func newAgentBrokerService(d agentBrokerDeps) (*agentBrokerService, error) {
	cfg := d.Config
	if !cfg.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(cfg.TrustDomain) == "" {
		return nil, errors.New("server: agent broker enabled but trust domain is empty")
	}
	if d.Store == nil || d.Log == nil || d.Orch == nil {
		return nil, errors.New("server: agent broker enabled without the event-sourced mutation spine")
	}
	if d.CASigner == nil || len(d.CACertDER) == 0 {
		return nil, errors.New("server: agent broker enabled but no signer-backed issuing CA is available")
	}
	methods := map[string]struct{}{}
	for _, a := range cfg.Attestors {
		if a == nil || a.Method() == "" {
			return nil, errors.New("server: agent broker configured with an empty attestor")
		}
		if _, dup := methods[a.Method()]; dup {
			return nil, fmt.Errorf("server: agent broker configured duplicate attestor %q", a.Method())
		}
		methods[a.Method()] = struct{}{}
	}
	if len(methods) == 0 {
		return nil, errors.New("server: agent broker enabled without attestors")
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = defaultBrokerCredentialTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = maxBrokerCredentialTTL
	}
	if cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}
	if d.Audit == nil {
		d.Audit = auditsink.Nop{}
	}
	pol := d.Policy
	if pol == nil {
		var err error
		pol, err = policy.New(policy.Config{Module: cfg.PolicyModule, Log: d.Log})
		if err != nil {
			return nil, err
		}
	}
	return &agentBrokerService{
		trustDomain: strings.TrimSpace(cfg.TrustDomain),
		defaultTTL:  cfg.DefaultTTL,
		maxTTL:      cfg.MaxTTL,
		attestors:   append([]attest.Attestor(nil), cfg.Attestors...),
		methods:     methods,
		policy:      pol,
		audit:       d.Audit,
		store:       d.Store,
		log:         d.Log,
		orch:        d.Orch,
		caSigner:    d.CASigner,
		caCertDER:   append([]byte(nil), d.CACertDER...),
		caID:        d.CAID,
		// Feature-neutral: nil unless the EE attach seam supplied a precondition. It is
		// consulted only on the chain-bound path, so a nil value leaves the free badge
		// unchanged (INV-A10).
		issuancePrecondition: d.IssuancePrecondition,
		taskEnvelopeGate:     d.TaskEnvelopeGate,
	}, nil
}

func (s *Server) IssueBrokerAgentIdentity(ctx context.Context, tenantID, idempotencyKey string, req api.BrokerAgentIdentityRequest) (api.BrokerAgentIdentity, error) {
	if s.agentBroker == nil {
		return api.BrokerAgentIdentity{}, api.ErrBrokerUnavailable
	}
	return s.agentBroker.IssueBrokerAgentIdentity(ctx, tenantID, idempotencyKey, req)
}

// BrokerTaskEnvelopeGate verifies an AGID-05 task envelope as a precondition of
// broker issuance and returns the digest the credential should bind. It is the
// feature-neutral seam: the MPL core names it and enforces when it must be
// consulted, while what a valid envelope IS lives entirely in the edition
// (ee/agentid/taskenv + the delegation gate's requester trust store).
type BrokerTaskEnvelopeGate func(ctx context.Context, tenantID string, envelope []byte, now time.Time) (digest []byte, err error)

// bindTaskEnvelope enforces the rule that makes a task binding worth anything:
// a caller who asks for a task-scoped credential must never receive an
// unscoped one. So an envelope present with no gate installed is REFUSED —
// silently ignoring it would hand back a broader credential than was asked
// for, which is the failure an attacker would engineer. No envelope means the
// ordinary single-hop badge, unchanged (INV-A10 zero removal).
func (s *agentBrokerService) bindTaskEnvelope(ctx context.Context, tenantID string, req api.BrokerAgentIdentityRequest) ([]byte, error) {
	if len(req.TaskEnvelope) == 0 {
		return nil, nil
	}
	if s.taskEnvelopeGate == nil {
		return nil, fmt.Errorf("%w: task_envelope requires the licensed agent-identity gate; refusing to issue an unscoped credential in its place", api.ErrBrokerRejected)
	}
	digest, err := s.taskEnvelopeGate(ctx, tenantID, req.TaskEnvelope, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("%w: task envelope refused: %v", api.ErrBrokerRejected, err)
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("%w: task envelope gate returned no digest", api.ErrBrokerRejected)
	}
	return digest, nil
}

func (s *agentBrokerService) IssueBrokerAgentIdentity(ctx context.Context, tenantID, idempotencyKey string, req api.BrokerAgentIdentityRequest) (api.BrokerAgentIdentity, error) {
	if err := s.validate(tenantID, idempotencyKey, req); err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	taskDigest, err := s.bindTaskEnvelope(ctx, tenantID, req)
	if err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	idemKey := "broker-issue:" + idempotencyKey
	recovered, err := recoverCertificatesByIssuanceKey(ctx, s.store, s.log, tenantID, idemKey)
	if err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	if len(recovered) > 0 {
		if len(recovered) != 1 {
			return api.BrokerAgentIdentity{}, fmt.Errorf("server: broker issuance key %q recovered %d certificates, want 1", idemKey, len(recovered))
		}
		att, err := s.verifyAndAuthorize(ctx, tenantID, req)
		if err != nil {
			return api.BrokerAgentIdentity{}, err
		}
		ownerID := brokerOwnerID(tenantID, req.AgentID)
		if _, err := s.orch.EnsureOwner(ctx, tenantID, ownerID, store.OwnerWorkload, req.AgentID, ""); err != nil {
			return api.BrokerAgentIdentity{}, err
		}
		resp, err := brokerResponseFromCertificate(req.AgentID, ownerID, req.Scopes, recovered[0], att)
		if err != nil {
			return api.BrokerAgentIdentity{}, err
		}
		// A replay of a task-scoped issuance re-reports the same binding: the
		// envelope was re-verified above, so an expired one now refuses rather
		// than silently returning the old credential.
		resp.TaskEnvelopeDigest = hex.EncodeToString(taskDigest)
		return resp, nil
	}

	ownerID := brokerOwnerID(tenantID, req.AgentID)
	bGraph := graph.New()
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: s.attestors,
		Audit:     s.audit,
		Graph:     bGraph,
	})
	if err != nil {
		return api.BrokerAgentIdentity{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrBrokerInvalid, err)
	}
	issuer, err := ephemeral.New(ephemeral.Config{
		TenantID: tenantID,
		Verifier: verifier,
		Sign:     s.sign(),
		Policy: ephemeral.TTLPolicy{
			Default: s.defaultTTL,
			Max:     s.maxTTL,
		},
		Idem:  ephemeral.NewMemoryIdempotencer(),
		Audit: s.audit,
	})
	if err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	// Attach the feature-neutral chain-bound issuance precondition when the EE seam
	// supplied one. WithIssuancePrecondition(nil) is a no-op, so Community / core-only
	// builds construct the exact single-hop broker they did before, and the served path
	// below (which calls b.Issue, the free single-hop path) never consults the
	// precondition regardless — only broker.IssueChainBound does (INV-A10 zero removal).
	b, err := broker.New(broker.Config{
		TenantID: tenantID,
		Issuer:   issuer,
		Policy:   s.policy,
		Graph:    bGraph,
		Audit:    s.audit,
	}, broker.WithIssuancePrecondition(s.issuancePrecondition))
	if err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	identity, err := b.Issue(ctx, broker.IssueRequest{
		AgentID:        req.AgentID,
		Method:         req.Method,
		Payload:        req.Payload,
		PublicKeyDER:   req.PublicKeyDER,
		Scopes:         append([]string(nil), req.Scopes...),
		IdempotencyKey: idemKey,
	})
	if err != nil {
		if strings.Contains(err.Error(), "policy denied") || strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "verification failed") {
			return api.BrokerAgentIdentity{}, fmt.Errorf("%w: %v", api.ErrBrokerRejected, err)
		}
		return api.BrokerAgentIdentity{}, err
	}
	owner, err := s.orch.EnsureOwner(ctx, tenantID, ownerID, store.OwnerWorkload, req.AgentID, "")
	if err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	info, err := certinfo.Inspect(identity.CertDER)
	if err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	nb, na := info.NotBefore, info.NotAfter
	recorded, err := s.orch.RecordCertificate(ctx, tenantID, store.Certificate{
		CAID: s.caID, OwnerID: &owner.ID, Subject: info.Subject, SANs: sansOf(info),
		Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "broker:" + identity.Attestation.Method, CertificateDER: append([]byte(nil), identity.CertDER...),
		IssuanceIdempotencyKey: idemKey,
	})
	if err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	resp := brokerResponseFromIdentity(owner.ID, identity, recorded.ID)
	if len(taskDigest) > 0 {
		resp.TaskEnvelopeDigest = hex.EncodeToString(taskDigest)
		// AN-2: the binding is durable in the audit chain, which is the record
		// of what was authorized — not a field a later read could lose.
		_ = auditsink.Emit(ctx, s.audit, nil, "broker.agent_identity.task_bound", tenantID,
			[]byte(fmt.Sprintf(`{"agent_id":%q,"credential_id":%q,"task_envelope_digest":%q}`,
				req.AgentID, identity.CredentialID, resp.TaskEnvelopeDigest)))
	}
	return resp, nil
}

func (s *agentBrokerService) validate(tenantID, idempotencyKey string, req api.BrokerAgentIdentityRequest) error {
	if tenantID == "" {
		return fmt.Errorf("%w: tenant is required", api.ErrBrokerInvalid)
	}
	if idempotencyKey == "" {
		return fmt.Errorf("%w: idempotency key is required", api.ErrBrokerInvalid)
	}
	if strings.TrimSpace(req.AgentID) == "" {
		return fmt.Errorf("%w: agent_id is required", api.ErrBrokerInvalid)
	}
	if len(req.PublicKeyDER) == 0 {
		return fmt.Errorf("%w: public key is required", api.ErrBrokerInvalid)
	}
	method := strings.TrimSpace(req.Method)
	if _, ok := s.methods[method]; !ok {
		return fmt.Errorf("%w: unknown attestation method %q", api.ErrBrokerInvalid, method)
	}
	if len(req.Scopes) == 0 {
		return fmt.Errorf("%w: at least one scope is required", api.ErrBrokerInvalid)
	}
	return nil
}

func (s *agentBrokerService) verifyAndAuthorize(ctx context.Context, tenantID string, req api.BrokerAgentIdentityRequest) (attest.Attestation, error) {
	in := policy.Input{
		Action:   policy.ActionIssue,
		TenantID: tenantID,
		Subject:  req.AgentID,
		Attrs: map[string]any{
			"agent_id":           req.AgentID,
			"scopes":             req.Scopes,
			"attestation_method": req.Method,
		},
	}
	dec, err := s.policy.Evaluate(ctx, in)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("%w: policy evaluation failed", api.ErrBrokerRejected)
	}
	if !dec.Allow {
		_ = auditsink.Emit(ctx, s.audit, nil, "agent.identity.refused", tenantID,
			[]byte(fmt.Sprintf(`{"agent_id":%q,"reason":%q}`, req.AgentID, dec.Reason)))
		return attest.Attestation{}, fmt.Errorf("%w: policy denied agent %q: %s", api.ErrBrokerRejected, req.AgentID, dec.Reason)
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: s.attestors,
		Audit:     s.audit,
	})
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrBrokerInvalid, err)
	}
	att, err := verifier.Verify(ctx, req.Method, req.Payload)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("%w: %v", api.ErrBrokerRejected, err)
	}
	return att, nil
}

func (s *agentBrokerService) sign() ephemeral.SignFunc {
	return func(ctx context.Context, att attest.Attestation, pubDER []byte, ttl time.Duration) ([]byte, error) {
		spiffeID, err := brokerSPIFFEID(s.trustDomain, att.Subject)
		if err != nil {
			return nil, err
		}
		return crypto.SignSVID(s.caCertDER, s.caSigner, pubDER, spiffeID, ttl)
	}
}

func brokerResponseFromIdentity(ownerID string, identity broker.AgentIdentity, certificateID string) api.BrokerAgentIdentity {
	return api.BrokerAgentIdentity{
		AgentID:        identity.AgentID,
		NodeID:         "wl:" + ownerID,
		Subject:        identity.Subject,
		CredentialID:   identity.CredentialID,
		CertificateID:  certificateID,
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.CertDER})),
		Scopes:         append([]string(nil), identity.Scopes...),
		NotAfter:       identity.NotAfter,
		Attestation:    identity.Attestation,
	}
}

func brokerResponseFromCertificate(agentID, ownerID string, scopes []string, cert store.Certificate, att attest.Attestation) (api.BrokerAgentIdentity, error) {
	if len(cert.CertificateDER) == 0 {
		return api.BrokerAgentIdentity{}, errors.New("server: broker recovered certificate without DER")
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil {
		return api.BrokerAgentIdentity{}, err
	}
	return api.BrokerAgentIdentity{
		AgentID:        agentID,
		NodeID:         "wl:" + ownerID,
		Subject:        att.Subject,
		CredentialID:   "cred:" + crypto.SHA256Hex(cert.CertificateDER),
		CertificateID:  cert.ID,
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CertificateDER})),
		Scopes:         append([]string(nil), scopes...),
		NotAfter:       info.NotAfter,
		Attestation:    att,
	}, nil
}

func brokerOwnerID(tenantID, agentID string) string {
	return uuid.NewSHA1(brokerAgentOwnerNamespace, []byte(tenantID+"\x00"+agentID)).String()
}

func brokerSPIFFEID(trustDomain, subject string) (string, error) {
	trustDomain = strings.TrimSpace(trustDomain)
	subject = strings.Trim(subject, "/")
	if trustDomain == "" {
		return "", errors.New("trust domain is required")
	}
	if subject == "" {
		return "", errors.New("attestation subject is required")
	}
	id := "spiffe://" + trustDomain + "/agent/" + url.PathEscape(subject)
	if _, err := crypto.ParseSPIFFEID(id); err != nil {
		return "", err
	}
	return id, nil
}

func brokerAuditor(log *events.Log) auditsink.Auditor {
	if log == nil {
		return auditsink.Nop{}
	}
	return audit.NewAuditor(log)
}
