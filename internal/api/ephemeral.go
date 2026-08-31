// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

const (
	EphemeralStateAwaitingApproval = "awaiting_approval"
	EphemeralStateIssued           = "issued"
	ephemeralAPIKeyMaxTTL          = time.Hour
)

var (
	ErrEphemeralUnavailable = errors.New("api: ephemeral issuance is not enabled")
	ErrEphemeralInvalid     = errors.New("api: invalid ephemeral issuance request")
	ErrEphemeralRejected    = errors.New("api: ephemeral issuance rejected")
	ErrEphemeralExpired     = errors.New("api: ephemeral approval request expired")
)

// EphemeralIssuerService is the served JIT credential surface (F25/F33). The API
// owns the tenant-scoped HTTP contract; the server implementation owns the
// attestation verifier, approval state, outbox enqueue, signer-backed CA, and
// event-sourced certificate record.
type EphemeralIssuerService interface {
	PreviewEphemeralCredential(ctx context.Context, tenantID, requester string, req EphemeralCredentialRequest) (EphemeralCredentialPreview, error)
	IssueEphemeralCredential(ctx context.Context, tenantID, idempotencyKey, requester string, req EphemeralCredentialRequest) (EphemeralCredential, error)
	ValidateEphemeralApprovalRequest(ctx context.Context, tenantID, requestID, intentDigest string) error
	ApproveEphemeralCredential(ctx context.Context, tenantID, requestID, intentDigest, approver string) (EphemeralApproval, error)
}

// WithEphemeralIssuer wires the served ephemeral/JIT issuer. When unset, the
// route fails closed with 503.
func WithEphemeralIssuer(svc EphemeralIssuerService) Option {
	return func(c *config) { c.ephemeral = svc }
}

type EphemeralCredentialRequest struct {
	RequestID    string
	Method       string
	Payload      []byte
	PublicKeyDER []byte
	TTLSeconds   int64
}

type ephemeralCredentialJSON struct {
	RequestID     string `json:"request_id"`
	Method        string `json:"method"`
	PayloadBase64 string `json:"payload_base64"`
	PublicKeyPEM  string `json:"public_key_pem"`
	TTLSeconds    int64  `json:"ttl_seconds"`
}

type EphemeralCredential struct {
	State             string             `json:"state"`
	RequestID         string             `json:"request_id"`
	ApprovalRequestID string             `json:"approval_request_id"`
	IntentDigest      string             `json:"intent_digest"`
	Subject           string             `json:"subject"`
	CredentialID      string             `json:"credential_id,omitempty"`
	CertificateID     string             `json:"certificate_id,omitempty"`
	CertificatePEM    string             `json:"certificate_pem,omitempty"`
	SPIFFEID          string             `json:"spiffe_id,omitempty"`
	RequiredApprovals int                `json:"required_approvals"`
	Approvals         int                `json:"approvals"`
	ExpiresAt         time.Time          `json:"expires_at"`
	NotAfter          time.Time          `json:"not_after,omitempty"`
	Attestation       attest.Attestation `json:"attestation"`
}

// EphemeralCredentialPreview is the effect-free answer to "what exactly will
// happen if I submit this JIT credential request?" It deliberately returns only
// digests and operational metadata: raw attestation evidence and public-key
// bytes never enter the response or retained evidence.
type EphemeralCredentialPreview struct {
	Capability                string   `json:"capability"`
	Ready                     bool     `json:"ready"`
	EffectFree                bool     `json:"effect_free"`
	RequestID                 string   `json:"request_id"`
	Method                    string   `json:"method"`
	Requester                 string   `json:"requester"`
	TrustDomain               string   `json:"trust_domain"`
	SupportedMethods          []string `json:"supported_methods"`
	RequestedTTLSeconds       int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds       int64    `json:"effective_ttl_seconds"`
	DefaultTTLSeconds         int64    `json:"default_ttl_seconds"`
	MaxTTLSeconds             int64    `json:"max_ttl_seconds"`
	TTLDefaulted              bool     `json:"ttl_defaulted"`
	TTLClamped                bool     `json:"ttl_clamped"`
	ApprovalRequired          bool     `json:"approval_required"`
	RequiredApprovals         int      `json:"required_approvals"`
	ApprovalTTLSeconds        int64    `json:"approval_ttl_seconds"`
	RequestPermission         string   `json:"request_permission"`
	ApprovalPermission        string   `json:"approval_permission"`
	AttestationVerification   string   `json:"attestation_verification"`
	PayloadSHA256             string   `json:"payload_sha256"`
	PublicKeySHA256           string   `json:"public_key_sha256"`
	PreviewWrites             []string `json:"preview_writes"`
	PreviewExternalEffects    []string `json:"preview_external_effects"`
	PreviewSignerCalls        []string `json:"preview_signer_calls"`
	SubmissionWrites          []string `json:"submission_writes"`
	SubmissionExternalEffects []string `json:"submission_external_effects"`
	SubmissionSignerCalls     []string `json:"submission_signer_calls"`
	IssuanceWrites            []string `json:"issuance_writes"`
	IssuanceExternalEffects   []string `json:"issuance_external_effects"`
	IssuanceSignerCalls       []string `json:"issuance_signer_calls"`
	Steps                     []string `json:"steps"`
	Blockers                  []string `json:"blockers"`
	RecoverySteps             []string `json:"recovery_steps"`
	DataHandling              []string `json:"data_handling"`
}

type ephemeralApprovalJSON struct {
	Action       string `json:"action"`
	RequestID    string `json:"request_id"`
	IntentDigest string `json:"intent_digest"`
}

type EphemeralApproval struct {
	ID                string `json:"id"`
	IntentDigest      string `json:"intent_digest"`
	Resource          string `json:"resource"`
	Action            string `json:"action"`
	Approver          string `json:"approver"`
	Approvals         int    `json:"approvals"`
	ApprovalCount     int    `json:"approval_count"`
	RequiredApprovals int    `json:"required_approvals"`
	Status            string `json:"status"`
}

type ephemeralAPIKeyJSON struct {
	Subject    string   `json:"subject"`
	Scopes     []string `json:"scopes"`
	TTLSeconds int64    `json:"ttl_seconds"`
}

func ephemeralCredentialRequestFromJSON(wire ephemeralCredentialJSON) (EphemeralCredentialRequest, error) {
	requestID := strings.TrimSpace(wire.RequestID)
	method := strings.TrimSpace(wire.Method)
	if requestID == "" {
		return EphemeralCredentialRequest{}, errStatus(http.StatusBadRequest, "request_id is required")
	}
	if method == "" {
		return EphemeralCredentialRequest{}, errStatus(http.StatusBadRequest, "method is required")
	}
	payload, err := base64.StdEncoding.DecodeString(wire.PayloadBase64)
	if err != nil || len(payload) == 0 {
		return EphemeralCredentialRequest{}, errStatus(http.StatusBadRequest, "payload_base64 must be non-empty standard base64")
	}
	block, _ := pem.Decode([]byte(wire.PublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Bytes) == 0 {
		secret.Wipe(payload)
		return EphemeralCredentialRequest{}, errStatus(http.StatusBadRequest, "public_key_pem must contain one PUBLIC KEY PEM block")
	}
	return EphemeralCredentialRequest{
		RequestID: requestID, Method: method, Payload: payload,
		PublicKeyDER: append([]byte(nil), block.Bytes...), TTLSeconds: wire.TTLSeconds,
	}, nil
}

// previewEphemeralCredential returns the exact, effect-free plan for an
// approval-gated JIT issuance. The attestation proof is structurally parsed and
// hashed here, but verification is deliberately deferred to execution so a
// preview can never consume a nonce or call an external verifier.
func (a *API) previewEphemeralCredential(w http.ResponseWriter, r *http.Request) {
	if a.ephemeral == nil {
		a.writeError(w, ErrEphemeralUnavailable)
		return
	}
	var wire ephemeralCredentialJSON
	if err := decodeJSON(r, &wire); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	command, err := ephemeralCredentialRequestFromJSON(wire)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(command.Payload)
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		a.writeError(w, errStatus(http.StatusUnauthorized, "an authenticated requester is required"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	preview, err := a.ephemeral.PreviewEphemeralCredential(r.Context(), tenantID, principal.Subject, command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

// issueEphemeralAPIKey mints a short-TTL bearer token for machine workflows. It
// delegates to the same event-sourced API-token command as the admin token route:
// the immutable event carries only the lookup hash, while the raw token is returned
// once and wiped by writeJSON after the response is encoded.
//
//trstctl:mutation
func (a *API) issueEphemeralAPIKey(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("ephemeral", "issue_api_key", start, opErr) }()
		var req ephemeralAPIKeyJSON
		if err := decodeJSON(r, &req); err != nil {
			opErr = err
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Subject = strings.TrimSpace(req.Subject)
		if req.Subject == "" {
			principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
			req.Subject = strings.TrimSpace(principal.Subject)
		}
		if req.Subject == "" {
			opErr = errors.New("subject is required")
			return 0, nil, errStatus(http.StatusBadRequest, "subject is required")
		}
		if len(req.Scopes) == 0 {
			opErr = errors.New("at least one scope is required")
			return 0, nil, errStatus(http.StatusBadRequest, "at least one scope is required")
		}
		if err := a.validatePermissionScopes(req.Scopes); err != nil {
			opErr = err
			return 0, nil, err
		}
		if req.TTLSeconds <= 0 {
			opErr = errors.New("ttl_seconds must be positive")
			return 0, nil, errStatus(http.StatusBadRequest, "ttl_seconds must be positive")
		}
		if req.TTLSeconds > int64(ephemeralAPIKeyMaxTTL/time.Second) {
			opErr = errors.New("ttl_seconds exceeds the ephemeral API-key maximum")
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "ttl_seconds must be 3600 or less")
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		expiresAt := time.Now().UTC().Add(ttl)
		rec, raw, err := a.orch.CreateAPIToken(ctx, tenantID, req.Subject, req.Scopes, &expiresAt)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusCreated, &apiTokenCreateResponse{apiTokenResponse: toAPITokenResponse(rec), Token: secretJSONBytes(raw)}, nil
	})
}

// issueEphemeralCredential opens or completes an approval-gated JIT issuance. A
// valid attestation opens the approval request and returns 202 until a distinct
// approver records approval; after approval, a fresh idempotent call mints and
// records the short-TTL credential.
//
//trstctl:mutation
func (a *API) issueEphemeralCredential(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if a.ephemeral == nil {
		a.writeError(w, ErrEphemeralUnavailable)
		return
	}
	var wire ephemeralCredentialJSON
	if err := decodeJSON(r, &wire); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	command, err := ephemeralCredentialRequestFromJSON(wire)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(command.Payload)
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		a.writeError(w, errStatus(http.StatusUnauthorized, "an authenticated requester is required"))
		return
	}
	binding, err := ephemeralIssueRequestBinding(idempotencyKey, principal.Subject, command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("ephemeral", "issue_jit", start, opErr) }()
		issued, err := a.ephemeral.IssueEphemeralCredential(ctx, tenantID, idempotencyKey, principal.Subject, command)
		if err != nil {
			opErr = approvalAPIError(err)
			return 0, nil, opErr
		}
		if issued.State == EphemeralStateAwaitingApproval {
			return http.StatusAccepted, issued, nil
		}
		return http.StatusCreated, issued, nil
	})
}

// approveEphemeralCredential records a distinct approver for a pending JIT issue
// request. The route guard requires certs:issue, so the RA split keeps requesters
// on certs:request and approvers on certs:issue.
//
//trstctl:mutation
func (a *API) approveEphemeralCredential(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	requestID := strings.TrimSpace(r.PathValue("id"))
	if a.ephemeral == nil {
		a.writeError(w, ErrEphemeralUnavailable)
		return
	}
	var req ephemeralApprovalJSON
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.Action != "issue" {
		a.writeError(w, errStatus(http.StatusBadRequest, `action must be "issue"`))
		return
	}
	if requestID == "" || strings.TrimSpace(req.RequestID) != requestID || strings.TrimSpace(req.IntentDigest) == "" {
		a.writeError(w, approvalAPIError(store.ErrApprovalRequestNotFound))
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		a.writeError(w, errStatus(http.StatusUnauthorized, "an authenticated approver is required"))
		return
	}
	if _, err := googleuuid.Parse(requestID); err != nil {
		a.writeError(w, approvalAPIError(store.ErrApprovalRequestNotFound))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeError(w, errStatus(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	if err := a.ephemeral.ValidateEphemeralApprovalRequest(r.Context(), tenantID, requestID, strings.TrimSpace(req.IntentDigest)); err != nil {
		a.writeError(w, approvalAPIError(err))
		return
	}
	command := ApprovalDecisionCommand{
		RequestID: requestID, IntentDigest: strings.TrimSpace(req.IntentDigest),
		Approver: principal.Subject, Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: "ephemeral", ExpectedAction: "issue",
	}
	binding, err := approvalDecisionBinding(command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		approval, err := a.ephemeral.ApproveEphemeralCredential(ctx, tenantID, requestID, command.IntentDigest, principal.Subject)
		if err != nil {
			return 0, nil, approvalAPIError(err)
		}
		return http.StatusOK, approval, nil
	})
}

func ephemeralIssueRequestBinding(idempotencyKey, requester string, req EphemeralCredentialRequest) (string, error) {
	raw, err := json.Marshal(struct {
		Domain    string                     `json:"domain"`
		Requester string                     `json:"requester"`
		Request   EphemeralCredentialRequest `json:"request"`
	}{Domain: "trstctl.api.ephemeral-issue.v1", Requester: requester, Request: req})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	key := []byte(idempotencyKey)
	defer secret.Wipe(key)
	mac := crypto.HMACSHA256(key, raw)
	defer secret.Wipe(mac)
	return hex.EncodeToString(mac), nil
}

func (a *API) writeEphemeralError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrEphemeralUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "ephemeral issuance is not enabled"))
	case errors.Is(err, ErrEphemeralInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrEphemeralInvalid.Error()+": ")))
	case errors.Is(err, ErrEphemeralRejected):
		a.writeProblem(w, problem.New(http.StatusForbidden, strings.TrimPrefix(err.Error(), ErrEphemeralRejected.Error()+": ")))
	case errors.Is(err, ErrEphemeralExpired):
		a.writeProblem(w, problem.New(http.StatusGone, strings.TrimPrefix(err.Error(), ErrEphemeralExpired.Error()+": ")))
	default:
		return false
	}
	return true
}
