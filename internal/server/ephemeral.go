// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	ephemerallib "trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

const (
	defaultEphemeralCredentialTTL = 10 * time.Minute
	maxEphemeralCredentialTTL     = time.Hour
	defaultEphemeralApprovalTTL   = 15 * time.Minute
)

// EphemeralIssuanceConfig turns on the served JIT credential issuer (F25/F33).
// It is explicit because it mints credentials: the operator/test harness supplies
// the trust domain and attesters. Empty leaves the route fail-closed.
type EphemeralIssuanceConfig struct {
	Enabled           bool
	TrustDomain       string
	DefaultTTL        time.Duration
	MaxTTL            time.Duration
	ApprovalTTL       time.Duration
	RequiredApprovals int
	Attestors         []attest.Attestor
}

type ephemeralIssuerService struct {
	trustDomain       string
	defaultTTL        time.Duration
	maxTTL            time.Duration
	approvalTTL       time.Duration
	requiredApprovals int
	attestors         []attest.Attestor
	methods           map[string]struct{}
	audit             auditsink.Auditor
	store             *store.Store
	log               *events.Log
	orch              *orchestrator.Orchestrator
	idem              *orchestrator.Idempotency
	outbox            *orchestrator.Outbox
	caSigner          crypto.DigestSigner
	caCertDER         []byte
	caID              string
}

type ephemeralIssuerDeps struct {
	Config    EphemeralIssuanceConfig
	Store     *store.Store
	Log       *events.Log
	Orch      *orchestrator.Orchestrator
	Idem      *orchestrator.Idempotency
	Outbox    *orchestrator.Outbox
	CASigner  crypto.DigestSigner
	CACertDER []byte
	CAID      string
	Audit     auditsink.Auditor
}

type ephemeralApprovalState struct {
	Requester string
	Required  int
	Approvals int
	CreatedAt time.Time
	ExpiresAt time.Time
}

func newEphemeralIssuerService(d ephemeralIssuerDeps) (*ephemeralIssuerService, error) {
	cfg := d.Config
	if !cfg.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(cfg.TrustDomain) == "" {
		return nil, errors.New("server: ephemeral issuance enabled but trust domain is empty")
	}
	if d.Store == nil || d.Log == nil || d.Orch == nil || d.Idem == nil || d.Outbox == nil {
		return nil, errors.New("server: ephemeral issuance enabled without the event-sourced mutation spine, idempotency, or outbox")
	}
	if d.CASigner == nil || len(d.CACertDER) == 0 {
		return nil, errors.New("server: ephemeral issuance enabled but no signer-backed issuing CA is available")
	}
	methods := map[string]struct{}{}
	for _, a := range cfg.Attestors {
		if a == nil || a.Method() == "" {
			return nil, errors.New("server: ephemeral issuance configured with an empty attestor")
		}
		if _, dup := methods[a.Method()]; dup {
			return nil, fmt.Errorf("server: ephemeral issuance configured duplicate attestor %q", a.Method())
		}
		methods[a.Method()] = struct{}{}
	}
	if len(methods) == 0 {
		return nil, errors.New("server: ephemeral issuance enabled without attestors")
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = defaultEphemeralCredentialTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = maxEphemeralCredentialTTL
	}
	if cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}
	if cfg.ApprovalTTL <= 0 {
		cfg.ApprovalTTL = defaultEphemeralApprovalTTL
	}
	if cfg.RequiredApprovals <= 0 {
		cfg.RequiredApprovals = defaultRequiredApprovals
	}
	if d.Audit == nil {
		d.Audit = auditsink.Nop{}
	}
	return &ephemeralIssuerService{
		trustDomain:       strings.TrimSpace(cfg.TrustDomain),
		defaultTTL:        cfg.DefaultTTL,
		maxTTL:            cfg.MaxTTL,
		approvalTTL:       cfg.ApprovalTTL,
		requiredApprovals: cfg.RequiredApprovals,
		attestors:         append([]attest.Attestor(nil), cfg.Attestors...),
		methods:           methods,
		audit:             d.Audit,
		store:             d.Store,
		log:               d.Log,
		orch:              d.Orch,
		idem:              d.Idem,
		outbox:            d.Outbox,
		caSigner:          d.CASigner,
		caCertDER:         append([]byte(nil), d.CACertDER...),
		caID:              d.CAID,
	}, nil
}

func (s *Server) IssueEphemeralCredential(ctx context.Context, tenantID, idempotencyKey, requester string, req api.EphemeralCredentialRequest) (api.EphemeralCredential, error) {
	if s.ephemeralIssuer == nil {
		return api.EphemeralCredential{}, api.ErrEphemeralUnavailable
	}
	return s.ephemeralIssuer.IssueEphemeralCredential(ctx, tenantID, idempotencyKey, requester, req)
}

func (s *Server) ApproveEphemeralCredential(ctx context.Context, tenantID, requestID, approver string) (api.EphemeralApproval, error) {
	if s.ephemeralIssuer == nil {
		return api.EphemeralApproval{}, api.ErrEphemeralUnavailable
	}
	return s.ephemeralIssuer.ApproveEphemeralCredential(ctx, tenantID, requestID, approver)
}

func (s *ephemeralIssuerService) IssueEphemeralCredential(ctx context.Context, tenantID, idempotencyKey, requester string, req api.EphemeralCredentialRequest) (api.EphemeralCredential, error) {
	if err := s.validate(tenantID, idempotencyKey, requester, req); err != nil {
		return api.EphemeralCredential{}, err
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: s.attestors,
		Audit:     s.audit,
	})
	if err != nil {
		return api.EphemeralCredential{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrEphemeralInvalid, err)
	}
	att, err := verifier.Verify(ctx, req.Method, req.Payload)
	if err != nil {
		return api.EphemeralCredential{}, fmt.Errorf("%w: %v", api.ErrEphemeralRejected, err)
	}
	state, requestedEvent, err := s.ensureApprovalRequest(ctx, tenantID, req.RequestID, requester, att)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	if requestedEvent {
		s.emitApprovalRequested(ctx, tenantID, req.RequestID, requester, att, state)
	}
	if state.ExpiresAt.Before(time.Now().UTC()) {
		return api.EphemeralCredential{}, fmt.Errorf("%w: request %q expired at %s", api.ErrEphemeralExpired, req.RequestID, state.ExpiresAt.Format(time.RFC3339))
	}
	if state.Approvals < state.Required {
		return api.EphemeralCredential{
			State:             api.EphemeralStateAwaitingApproval,
			RequestID:         req.RequestID,
			Subject:           att.Subject,
			RequiredApprovals: state.Required,
			Approvals:         state.Approvals,
			ExpiresAt:         state.ExpiresAt,
			Attestation:       att,
		}, nil
	}

	issueKey := "ephemeral-issue:" + idempotencyKey
	recovered, err := recoverCertificatesByIssuanceKey(ctx, s.store, s.log, tenantID, issueKey)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	if len(recovered) > 0 {
		if len(recovered) != 1 {
			return api.EphemeralCredential{}, fmt.Errorf("server: ephemeral issuance key %q recovered %d certificates, want 1", issueKey, len(recovered))
		}
		return s.responseFromCertificate(ctx, verifier, req.RequestID, att, state, recovered[0])
	}

	issuer, err := ephemerallib.New(ephemerallib.Config{
		TenantID: tenantID,
		Verifier: verifier,
		Sign:     s.sign(),
		Policy: ephemerallib.TTLPolicy{
			Default: s.ttl(req.TTLSeconds),
			Max:     s.maxTTL,
		},
		Idem:  s.idem,
		Audit: s.audit,
	})
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	issued, err := issuer.Issue(ctx, ephemerallib.Request{
		Method:         req.Method,
		Payload:        req.Payload,
		PublicKeyDER:   req.PublicKeyDER,
		IdempotencyKey: issueKey,
	})
	if err != nil {
		if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "verification failed") {
			return api.EphemeralCredential{}, fmt.Errorf("%w: %v", api.ErrEphemeralRejected, err)
		}
		return api.EphemeralCredential{}, err
	}
	info, err := certinfo.Inspect(issued.CertDER)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	nb, na := info.NotBefore, info.NotAfter
	recorded, err := s.orch.RecordCertificate(ctx, tenantID, store.Certificate{
		CAID: s.caID, Subject: info.Subject, SANs: sansOf(info), Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "ephemeral:" + issued.Attestation.Method, CertificateDER: append([]byte(nil), issued.CertDER...),
		IssuanceIdempotencyKey: issueKey,
	})
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	return api.EphemeralCredential{
		State:             api.EphemeralStateIssued,
		RequestID:         req.RequestID,
		Subject:           issued.Subject,
		CredentialID:      issued.CredentialID,
		CertificateID:     recorded.ID,
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued.CertDER})),
		RequiredApprovals: state.Required,
		Approvals:         state.Approvals,
		ExpiresAt:         state.ExpiresAt,
		NotAfter:          issued.NotAfter,
		Attestation:       issued.Attestation,
	}, nil
}

func (s *ephemeralIssuerService) ApproveEphemeralCredential(ctx context.Context, tenantID, requestID, approver string) (api.EphemeralApproval, error) {
	requestID = strings.TrimSpace(requestID)
	if tenantID == "" {
		return api.EphemeralApproval{}, fmt.Errorf("%w: tenant is required", api.ErrEphemeralInvalid)
	}
	if requestID == "" {
		return api.EphemeralApproval{}, fmt.Errorf("%w: request id is required", api.ErrEphemeralInvalid)
	}
	if strings.TrimSpace(approver) == "" {
		return api.EphemeralApproval{}, fmt.Errorf("%w: approver is required", api.ErrEphemeralInvalid)
	}
	state, err := s.loadApprovalState(ctx, tenantID, requestID)
	if err != nil {
		return api.EphemeralApproval{}, err
	}
	if state.ExpiresAt.Before(time.Now().UTC()) {
		return api.EphemeralApproval{}, fmt.Errorf("%w: request %q expired at %s", api.ErrEphemeralExpired, requestID, state.ExpiresAt.Format(time.RFC3339))
	}
	count, err := s.store.ApproveIssuance(ctx, tenantID, requestID, "issue", approver)
	if err != nil {
		if errors.Is(err, store.ErrSelfIssuanceApproval) || errors.Is(err, store.ErrAnonymousIssuanceApproval) {
			return api.EphemeralApproval{}, fmt.Errorf("%w: %v", api.ErrEphemeralRejected, err)
		}
		return api.EphemeralApproval{}, err
	}
	s.emitApprovalGranted(ctx, tenantID, requestID, approver, count)
	return api.EphemeralApproval{Resource: requestID, Action: "issue", Approver: approver, Approvals: count}, nil
}

func (s *ephemeralIssuerService) validate(tenantID, idempotencyKey, requester string, req api.EphemeralCredentialRequest) error {
	if tenantID == "" {
		return fmt.Errorf("%w: tenant is required", api.ErrEphemeralInvalid)
	}
	if idempotencyKey == "" {
		return fmt.Errorf("%w: idempotency key is required", api.ErrEphemeralInvalid)
	}
	if strings.TrimSpace(requester) == "" {
		return fmt.Errorf("%w: requester is required", api.ErrEphemeralInvalid)
	}
	if strings.TrimSpace(req.RequestID) == "" {
		return fmt.Errorf("%w: request_id is required", api.ErrEphemeralInvalid)
	}
	if len(req.PublicKeyDER) == 0 {
		return fmt.Errorf("%w: public key is required", api.ErrEphemeralInvalid)
	}
	method := strings.TrimSpace(req.Method)
	if _, ok := s.methods[method]; !ok {
		return fmt.Errorf("%w: unknown attestation method %q", api.ErrEphemeralInvalid, method)
	}
	if len(req.Payload) == 0 {
		return fmt.Errorf("%w: attestation payload is required", api.ErrEphemeralInvalid)
	}
	return nil
}

func (s *ephemeralIssuerService) ensureApprovalRequest(ctx context.Context, tenantID, requestID, requester string, att attest.Attestation) (ephemeralApprovalState, bool, error) {
	var (
		state    ephemeralApprovalState
		inserted bool
	)
	err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester, required)
			 VALUES ($1, $2, 'issue', $3, $4)
			 ON CONFLICT (tenant_id, resource, action) DO UPDATE
			    SET requester = CASE
			        WHEN issuance_approval_requests.requester = '' THEN EXCLUDED.requester
			        ELSE issuance_approval_requests.requester
			    END`,
			tenantID, requestID, requester, s.requiredApprovals)
		if err != nil {
			return err
		}
		if err := scanEphemeralApprovalState(ctx, tx, tenantID, requestID, s.approvalTTL, &state); err != nil {
			return err
		}
		if state.Requester != "" && state.Requester != requester {
			return fmt.Errorf("%w: request %q was opened by a different requester", api.ErrEphemeralRejected, requestID)
		}
		payload, err := json.Marshal(struct {
			RequestID         string   `json:"request_id"`
			Requester         string   `json:"requester"`
			Subject           string   `json:"subject"`
			Method            string   `json:"method"`
			Selectors         []string `json:"selectors"`
			RequiredApprovals int      `json:"required_approvals"`
			ExpiresAt         string   `json:"expires_at"`
		}{
			RequestID: requestID, Requester: requester, Subject: att.Subject, Method: att.Method,
			Selectors: append([]string(nil), att.Selectors...), RequiredApprovals: state.Required,
			ExpiresAt: state.ExpiresAt.Format(time.RFC3339),
		})
		if err != nil {
			return err
		}
		inserted, err = s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:       tenantID,
			Destination:    "ephemeral.approval",
			IdempotencyKey: "ephemeral-approval:" + requestID,
			Payload:        payload,
		})
		return err
	})
	if err != nil {
		return ephemeralApprovalState{}, false, err
	}
	return state, inserted, nil
}

func (s *ephemeralIssuerService) loadApprovalState(ctx context.Context, tenantID, requestID string) (ephemeralApprovalState, error) {
	var state ephemeralApprovalState
	err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanEphemeralApprovalState(ctx, tx, tenantID, requestID, s.approvalTTL, &state)
	})
	return state, err
}

func scanEphemeralApprovalState(ctx context.Context, tx pgx.Tx, tenantID, requestID string, approvalTTL time.Duration, state *ephemeralApprovalState) error {
	err := tx.QueryRow(ctx,
		`SELECT requester, required, created_at,
		        (SELECT count(*) FROM issuance_approvals ia
		          WHERE ia.tenant_id = r.tenant_id
		            AND ia.resource = r.resource
		            AND ia.action = r.action
		            AND ia.approver <> r.requester)
		   FROM issuance_approval_requests r
		  WHERE tenant_id = $1 AND resource = $2 AND action = 'issue'`,
		tenantID, requestID).Scan(&state.Requester, &state.Required, &state.CreatedAt, &state.Approvals)
	if err != nil {
		return err
	}
	state.CreatedAt = state.CreatedAt.UTC()
	state.ExpiresAt = state.CreatedAt.Add(approvalTTL).UTC()
	return nil
}

func (s *ephemeralIssuerService) responseFromCertificate(ctx context.Context, verifier *attest.Verifier, requestID string, att attest.Attestation, state ephemeralApprovalState, cert store.Certificate) (api.EphemeralCredential, error) {
	if len(cert.CertificateDER) == 0 {
		return api.EphemeralCredential{}, errors.New("server: ephemeral recovered certificate without DER")
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	credentialID := "cred:" + crypto.SHA256Hex(cert.CertificateDER)
	if err := verifier.Bind(ctx, att, credentialID); err != nil {
		return api.EphemeralCredential{}, fmt.Errorf("server: bind recovered ephemeral attestation: %w", err)
	}
	return api.EphemeralCredential{
		State:             api.EphemeralStateIssued,
		RequestID:         requestID,
		Subject:           att.Subject,
		CredentialID:      credentialID,
		CertificateID:     cert.ID,
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CertificateDER})),
		RequiredApprovals: state.Required,
		Approvals:         state.Approvals,
		ExpiresAt:         state.ExpiresAt,
		NotAfter:          info.NotAfter,
		Attestation:       att,
	}, nil
}

func (s *ephemeralIssuerService) ttl(seconds int64) time.Duration {
	if seconds <= 0 {
		return s.defaultTTL
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl <= 0 {
		return s.defaultTTL
	}
	if s.maxTTL > 0 && ttl > s.maxTTL {
		return s.maxTTL
	}
	return ttl
}

func (s *ephemeralIssuerService) sign() ephemerallib.SignFunc {
	return func(ctx context.Context, att attest.Attestation, pubDER []byte, ttl time.Duration) ([]byte, error) {
		spiffeID, err := attestedSPIFFEID(s.trustDomain, att.Subject)
		if err != nil {
			return nil, err
		}
		return crypto.SignSVID(s.caCertDER, s.caSigner, pubDER, spiffeID, ttl)
	}
}

func (s *ephemeralIssuerService) emitApprovalRequested(ctx context.Context, tenantID, requestID, requester string, att attest.Attestation, state ephemeralApprovalState) {
	payload, err := json.Marshal(struct {
		RequestID         string `json:"request_id"`
		Requester         string `json:"requester"`
		Subject           string `json:"subject"`
		Method            string `json:"method"`
		RequiredApprovals int    `json:"required_approvals"`
		ExpiresAt         string `json:"expires_at"`
	}{
		RequestID: requestID, Requester: requester, Subject: att.Subject, Method: att.Method,
		RequiredApprovals: state.Required, ExpiresAt: state.ExpiresAt.Format(time.RFC3339),
	})
	if err == nil {
		_ = auditsink.Emit(ctx, s.audit, nil, "ephemeral.approval.requested", tenantID, payload)
	}
}

func (s *ephemeralIssuerService) emitApprovalGranted(ctx context.Context, tenantID, requestID, approver string, approvals int) {
	payload, err := json.Marshal(struct {
		RequestID  string `json:"request_id"`
		Approver   string `json:"approver"`
		Approvals  int    `json:"approvals"`
		Action     string `json:"action"`
		ApprovedAt string `json:"approved_at"`
	}{
		RequestID: requestID, Approver: approver, Approvals: approvals, Action: "issue",
		ApprovedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err == nil {
		_ = auditsink.Emit(ctx, s.audit, nil, "ephemeral.approval.granted", tenantID, payload)
	}
}
