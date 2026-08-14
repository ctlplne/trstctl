// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	ephemerallib "trstctl.com/trstctl/internal/ephemeral"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
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

func (s *Server) ApproveEphemeralCredential(ctx context.Context, tenantID, requestID, intentDigest, approver string) (api.EphemeralApproval, error) {
	if s.ephemeralIssuer == nil {
		return api.EphemeralApproval{}, api.ErrEphemeralUnavailable
	}
	return s.ephemeralIssuer.ApproveEphemeralCredential(ctx, tenantID, requestID, intentDigest, approver)
}

func (s *Server) ValidateEphemeralApprovalRequest(ctx context.Context, tenantID, requestID, intentDigest string) error {
	if s.ephemeralIssuer == nil {
		return api.ErrEphemeralUnavailable
	}
	return s.ephemeralIssuer.ValidateEphemeralApprovalRequest(ctx, tenantID, requestID, intentDigest)
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
	requestBinding, err := ephemeralApprovedRequestBinding(requester, req, att)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	expectedBinding, err := s.ephemeralApprovalBinding(req, att)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	commandKey := crypto.SHA256Hex([]byte(req.RequestID))
	fence, fenceErr := s.store.GetApprovedTargetFence(ctx, tenantID,
		store.ApprovedTargetEphemeralCertificate, commandKey)
	if fenceErr == nil {
		if fence.RequestBinding != requestBinding {
			return api.EphemeralCredential{}, fmt.Errorf("%w: ephemeral request_id belongs to a different command", store.ErrIdempotencyConflict)
		}
		recorded, err := s.orch.ProjectApprovedCertificateFence(ctx, tenantID, fence)
		if err != nil {
			return api.EphemeralCredential{}, err
		}
		approvalRequest, err := s.store.GetOperationApproval(ctx, tenantID, fence.Approval.RequestID)
		if err != nil {
			return api.EphemeralCredential{}, err
		}
		return s.responseFromCertificate(ctx, verifier, req.RequestID, att, approvalRequest, recorded)
	}
	if !store.IsNotFound(fenceErr) {
		return api.EphemeralCredential{}, fenceErr
	}
	approvalRequest, err := s.ensureEphemeralApprovalRequest(ctx, tenantID, requester, req, att)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	approvalUse, err := store.OperationApprovalUseFromRequest(approvalRequest)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	issueKey := "ephemeral-issue:" + approvalRequest.ID
	if approvalRequest.Status == store.ApprovalStatusConsumed {
		if approvalRequest.ConsumedEventID != orchestrator.CertificateApprovalEventID(tenantID, approvalUse) {
			return api.EphemeralCredential{}, store.ErrApprovalConsumed
		}
		recovered, found, recoverErr := s.recoverApprovedEphemeralCertificate(ctx, tenantID, approvalRequest, expectedBinding)
		if recoverErr != nil {
			return api.EphemeralCredential{}, recoverErr
		}
		if !found {
			return api.EphemeralCredential{}, fmt.Errorf("server: consumed ephemeral approval %q has no canonical certificate event", approvalRequest.ID)
		}
		return s.responseFromCertificate(ctx, verifier, req.RequestID, att, approvalRequest, recovered)
	}
	if !time.Now().UTC().Before(approvalRequest.ExpiresAt) || approvalRequest.Status == store.ApprovalStatusExpired {
		return api.EphemeralCredential{}, store.ErrApprovalExpired
	}
	switch approvalRequest.Status {
	case store.ApprovalStatusPending:
		return api.EphemeralCredential{
			State:             api.EphemeralStateAwaitingApproval,
			RequestID:         req.RequestID,
			ApprovalRequestID: approvalRequest.ID,
			IntentDigest:      approvalRequest.IntentDigest,
			Subject:           att.Subject,
			RequiredApprovals: approvalRequest.RequiredApprovals,
			Approvals:         approvalRequest.ApprovalCount,
			ExpiresAt:         approvalRequest.ExpiresAt,
			Attestation:       att,
		}, nil
	case store.ApprovalStatusApproved:
		if approvalRequest.ApprovalCount < approvalRequest.RequiredApprovals {
			return api.EphemeralCredential{}, store.ErrApprovalNotReady
		}
	case store.ApprovalStatusSuperseded:
		return api.EphemeralCredential{}, store.ErrApprovalSuperseded
	case store.ApprovalStatusDenied:
		return api.EphemeralCredential{}, fmt.Errorf("%w: approval request %q was denied", api.ErrEphemeralRejected, approvalRequest.ID)
	default:
		return api.EphemeralCredential{}, store.ErrApprovalNotReady
	}

	recovered, found, err := s.recoverApprovedEphemeralCertificate(ctx, tenantID, approvalRequest, expectedBinding)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	if found {
		return s.responseFromCertificate(ctx, verifier, req.RequestID, att, approvalRequest, recovered)
	}

	return s.issueApprovedEphemeralCredential(
		ctx, tenantID, req, verifier, approvalRequest, approvalUse, requestBinding, issueKey,
	)
}

// issueApprovedEphemeralCredential mints and records the certificate only after
// the caller has proved the approval is current, ready, and has no canonical
// target event to recover. The deterministic issue key and approval capability
// cross this stage together so minting cannot drift away from event authority.
func (s *ephemeralIssuerService) issueApprovedEphemeralCredential(
	ctx context.Context,
	tenantID string,
	req api.EphemeralCredentialRequest,
	verifier *attest.Verifier,
	approvalRequest store.OperationApprovalRequest,
	approvalUse store.OperationApprovalUse,
	requestBinding, issueKey string,
) (api.EphemeralCredential, error) {
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
	approvalBinding, err := s.ephemeralApprovalBinding(req, issued.Attestation)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	nb, na := info.NotBefore, info.NotAfter
	recorded, err := s.orch.RecordCertificateWithApproval(ctx, tenantID, store.Certificate{
		CAID: s.caID, Subject: info.Subject, SANs: sansOf(info), Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "ephemeral:" + issued.Attestation.Method, CertificateDER: append([]byte(nil), issued.CertDER...),
		IssuanceIdempotencyKey: issueKey,
		// B5: the workload presented its own public key, so the control plane
		// signed for a key it never saw the private half of. Storage stays
		// unrecorded — the key lives wherever the attested workload put it, and
		// this side has no basis for a claim about that.
		KeyOrigin: string(custody.OriginRequester),
	}, approvalUse, approvalBinding, requestBinding)
	if err != nil {
		return api.EphemeralCredential{}, err
	}
	if len(recorded.CertificateDER) == 0 || recorded.NotAfter == nil {
		return api.EphemeralCredential{}, errors.New("server: canonical ephemeral certificate is incomplete")
	}
	return api.EphemeralCredential{
		State:             api.EphemeralStateIssued,
		RequestID:         req.RequestID,
		ApprovalRequestID: approvalRequest.ID,
		IntentDigest:      approvalRequest.IntentDigest,
		Subject:           issued.Attestation.Subject,
		CredentialID:      "cred:" + crypto.SHA256Hex(recorded.CertificateDER),
		CertificateID:     recorded.ID,
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: recorded.CertificateDER})),
		RequiredApprovals: approvalRequest.RequiredApprovals,
		Approvals:         approvalRequest.ApprovalCount,
		ExpiresAt:         approvalRequest.ExpiresAt,
		NotAfter:          *recorded.NotAfter,
		Attestation:       issued.Attestation,
	}, nil
}

// recoverApprovedEphemeralCertificate accepts only the one deterministic target
// event for this exact approval capability. Looking up an arbitrary row by the
// issuance key is not authority: a legacy/corrupt row with that text must never
// turn a still-approved grant into a successful response.
func (s *ephemeralIssuerService) recoverApprovedEphemeralCertificate(
	ctx context.Context,
	tenantID string,
	approval store.OperationApprovalRequest,
	expectedBinding ephemerallib.ApprovalBinding,
) (store.Certificate, bool, error) {
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		return store.Certificate{}, false, err
	}
	eventID := orchestrator.CertificateApprovalEventID(tenantID, use)
	event, found, err := s.log.EventByID(ctx, eventID)
	if err != nil || !found {
		return store.Certificate{}, found, err
	}
	if event.Type != projections.EventCertificateRecorded || event.TenantID != tenantID ||
		event.SchemaVersion != projections.CertificateApprovalEventSchemaVersion {
		return store.Certificate{}, false, fmt.Errorf("%w: recovered ephemeral target envelope differs", store.ErrIdempotencyConflict)
	}
	var payload projections.CertificateRecorded
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		return store.Certificate{}, false, fmt.Errorf("server: decode recovered ephemeral target: %w", err)
	}
	if err := projections.ValidateApprovedCertificatePayload(event, payload); err != nil {
		return store.Certificate{}, false, err
	}
	wantUse, err := json.Marshal(use)
	if err != nil {
		return store.Certificate{}, false, err
	}
	gotUse, err := json.Marshal(payload.Approval)
	if err != nil {
		return store.Certificate{}, false, err
	}
	wantBinding, err := expectedBinding.Digest()
	if err != nil {
		return store.Certificate{}, false, err
	}
	gotBinding, err := payload.ApprovalBinding.Digest()
	if err != nil {
		return store.Certificate{}, false, err
	}
	if !bytes.Equal(wantUse, gotUse) || wantBinding != gotBinding ||
		payload.ID != projections.CertificateApprovalRowID(tenantID, use) {
		return store.Certificate{}, false, fmt.Errorf("%w: recovered ephemeral target capability differs", store.ErrIdempotencyConflict)
	}
	if err := projections.New(s.store).Apply(ctx, event); err != nil {
		return store.Certificate{}, false, fmt.Errorf("server: project recovered ephemeral target: %w", err)
	}
	cert, err := s.store.GetCertificate(ctx, tenantID, payload.ID)
	if err != nil {
		return store.Certificate{}, false, err
	}
	if cert.ID != payload.ID || cert.Fingerprint != payload.Fingerprint ||
		cert.IssuanceIdempotencyKey != payload.IssuanceIdempotencyKey ||
		!bytes.Equal(cert.CertificateDER, payload.CertificateDER) {
		return store.Certificate{}, false, fmt.Errorf("%w: recovered ephemeral projection differs from canonical event", store.ErrIdempotencyConflict)
	}
	return cert, true, nil
}

func ephemeralApprovedRequestBinding(requester string, req api.EphemeralCredentialRequest, att attest.Attestation) (string, error) {
	basis := struct {
		Requester string                         `json:"requester"`
		Request   api.EphemeralCredentialRequest `json:"request"`
		Attested  struct {
			ID        string            `json:"id"`
			Method    string            `json:"method"`
			Subject   string            `json:"subject"`
			Selectors []string          `json:"selectors"`
			Claims    map[string]string `json:"claims"`
		} `json:"attested"`
	}{Requester: requester, Request: req}
	basis.Attested.ID = att.ID
	basis.Attested.Method = att.Method
	basis.Attested.Subject = att.Subject
	basis.Attested.Selectors = append([]string(nil), att.Selectors...)
	basis.Attested.Claims = att.Claims
	raw, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl:ephemeral-approved-request:v1\x00"), raw...)), nil
}

func (s *ephemeralIssuerService) ApproveEphemeralCredential(ctx context.Context, tenantID, requestID, intentDigest, approver string) (api.EphemeralApproval, error) {
	requestID = strings.TrimSpace(requestID)
	intentDigest = strings.TrimSpace(intentDigest)
	if tenantID == "" {
		return api.EphemeralApproval{}, fmt.Errorf("%w: tenant is required", api.ErrEphemeralInvalid)
	}
	if requestID == "" || intentDigest == "" {
		return api.EphemeralApproval{}, store.ErrApprovalRequestNotFound
	}
	if strings.TrimSpace(approver) == "" {
		return api.EphemeralApproval{}, fmt.Errorf("%w: approver is required", api.ErrEphemeralInvalid)
	}
	request, err := s.orch.RecordOperationApprovalDecision(ctx, tenantID, orchestrator.OperationApprovalDecision{
		RequestID: requestID, IntentDigest: intentDigest,
		Approver: approver, Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: "ephemeral", ExpectedAction: "issue",
	})
	if err != nil {
		return api.EphemeralApproval{}, err
	}
	return api.EphemeralApproval{
		ID: request.ID, IntentDigest: request.IntentDigest,
		Resource: request.ResourceID, Action: request.Action, Approver: approver,
		Approvals: request.ApprovalCount, ApprovalCount: request.ApprovalCount,
		RequiredApprovals: request.RequiredApprovals, Status: request.Status,
	}, nil
}

func (s *ephemeralIssuerService) ValidateEphemeralApprovalRequest(ctx context.Context, tenantID, requestID, intentDigest string) error {
	request, err := s.store.GetOperationApproval(ctx, tenantID, strings.TrimSpace(requestID))
	if err != nil {
		return err
	}
	if request.IntentDigest != strings.TrimSpace(intentDigest) || request.ResourceKind != "ephemeral" || request.Action != "issue" {
		return store.ErrApprovalDigestMismatch
	}
	return nil
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

func (s *ephemeralIssuerService) ensureEphemeralApprovalRequest(ctx context.Context, tenantID, requester string, req api.EphemeralCredentialRequest, att attest.Attestation) (store.OperationApprovalRequest, error) {
	binding, err := s.ephemeralApprovalBinding(req, att)
	if err != nil {
		return store.OperationApprovalRequest{}, err
	}
	toState, err := binding.ToState()
	if err != nil {
		return store.OperationApprovalRequest{}, err
	}
	evidenceRefs, err := binding.EvidenceRefs()
	if err != nil {
		return store.OperationApprovalRequest{}, err
	}
	return s.orch.EnsureOperationApprovalRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "ephemeral", ResourceID: "ephemeral:" + req.RequestID,
		ResourceName: att.Subject, Action: "issue", Requester: requester,
		FromState: "attested", ToState: toState, TargetVersion: 0,
		Reason:            "authorize one exact attested ephemeral credential issuance",
		EvidenceRefs:      evidenceRefs,
		RequiredApprovals: s.requiredApprovals, TTL: s.approvalTTL,
	})
}

func (s *ephemeralIssuerService) ephemeralApprovalBinding(req api.EphemeralCredentialRequest, att attest.Attestation) (ephemerallib.ApprovalBinding, error) {
	spiffeID, err := attestedSPIFFEID(s.trustDomain, att.Subject)
	if err != nil {
		return ephemerallib.ApprovalBinding{}, err
	}
	return ephemerallib.NewApprovalBinding(s.caID, s.caCertDER, req.RequestID, att.Method, att.Subject,
		att.Selectors, req.PublicKeyDER, spiffeID, s.ttl(req.TTLSeconds))
}

func (s *ephemeralIssuerService) responseFromCertificate(ctx context.Context, verifier *attest.Verifier, requestID string, att attest.Attestation, approval store.OperationApprovalRequest, cert store.Certificate) (api.EphemeralCredential, error) {
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
		ApprovalRequestID: approval.ID,
		IntentDigest:      approval.IntentDigest,
		Subject:           att.Subject,
		CredentialID:      credentialID,
		CertificateID:     cert.ID,
		CertificatePEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CertificateDER})),
		RequiredApprovals: approval.RequiredApprovals,
		Approvals:         approval.ApprovalCount,
		ExpiresAt:         approval.ExpiresAt,
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
