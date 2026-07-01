package api

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/authz"
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
	IssueEphemeralCredential(ctx context.Context, tenantID, idempotencyKey, requester string, req EphemeralCredentialRequest) (EphemeralCredential, error)
	ApproveEphemeralCredential(ctx context.Context, tenantID, requestID, approver string) (EphemeralApproval, error)
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
	Subject           string             `json:"subject"`
	CredentialID      string             `json:"credential_id,omitempty"`
	CertificateID     string             `json:"certificate_id,omitempty"`
	CertificatePEM    string             `json:"certificate_pem,omitempty"`
	RequiredApprovals int                `json:"required_approvals"`
	Approvals         int                `json:"approvals"`
	ExpiresAt         time.Time          `json:"expires_at"`
	NotAfter          time.Time          `json:"not_after,omitempty"`
	Attestation       attest.Attestation `json:"attestation"`
}

type ephemeralApprovalJSON struct {
	Action string `json:"action"`
}

type EphemeralApproval struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Approver  string `json:"approver"`
	Approvals int    `json:"approvals"`
}

type ephemeralAPIKeyJSON struct {
	Subject    string   `json:"subject"`
	Scopes     []string `json:"scopes"`
	TTLSeconds int64    `json:"ttl_seconds"`
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("ephemeral", "issue_jit", start, opErr) }()
		if a.ephemeral == nil {
			opErr = ErrEphemeralUnavailable
			return 0, nil, ErrEphemeralUnavailable
		}
		var req ephemeralCredentialJSON
		if err := decodeJSON(r, &req); err != nil {
			opErr = err
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		requestID := strings.TrimSpace(req.RequestID)
		method := strings.TrimSpace(req.Method)
		if requestID == "" {
			opErr = errors.New("request_id is required")
			return 0, nil, errStatus(http.StatusBadRequest, "request_id is required")
		}
		if method == "" {
			opErr = errors.New("method is required")
			return 0, nil, errStatus(http.StatusBadRequest, "method is required")
		}
		payload, err := base64.StdEncoding.DecodeString(req.PayloadBase64)
		if err != nil || len(payload) == 0 {
			opErr = errors.New("payload_base64 must be non-empty standard base64")
			return 0, nil, errStatus(http.StatusBadRequest, "payload_base64 must be non-empty standard base64")
		}
		block, _ := pem.Decode([]byte(req.PublicKeyPEM))
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Bytes) == 0 {
			opErr = errors.New("public_key_pem must contain one PUBLIC KEY PEM block")
			return 0, nil, errStatus(http.StatusBadRequest, "public_key_pem must contain one PUBLIC KEY PEM block")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			opErr = errors.New("an authenticated requester is required")
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated requester is required")
		}
		issued, err := a.ephemeral.IssueEphemeralCredential(ctx, tenantID, idempotencyKey, principal.Subject, EphemeralCredentialRequest{
			RequestID:    requestID,
			Method:       method,
			Payload:      payload,
			PublicKeyDER: block.Bytes,
			TTLSeconds:   req.TTLSeconds,
		})
		if err != nil {
			opErr = err
			return 0, nil, err
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
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.ephemeral == nil {
			return 0, nil, ErrEphemeralUnavailable
		}
		if requestID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "request id is required")
		}
		var req ephemeralApprovalJSON
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.Action != "issue" {
			return 0, nil, errStatus(http.StatusBadRequest, `action must be "issue"`)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated approver is required")
		}
		approval, err := a.ephemeral.ApproveEphemeralCredential(ctx, tenantID, requestID, principal.Subject)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, approval, nil
	})
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
