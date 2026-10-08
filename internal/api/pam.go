// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

const PAMSessionStatusActive = "active"

var (
	ErrPAMUnavailable = errors.New("api: PAM broker is not enabled")
	ErrPAMInvalid     = errors.New("api: invalid PAM session request")
	ErrPAMRejected    = errors.New("api: PAM session rejected")
	ErrPAMTerminal    = errors.New("api: PAM session already ending or ended")
)

// PAMService is the served privileged-access broker. The API owns the
// tenant-scoped HTTP contract; the server implementation owns the attestation
// verifier, target adapters, SSH CA, event append, projection, and expiry worker.
type PAMService interface {
	RequestPAMSession(ctx context.Context, tenantID, requester string, req PAMSessionRequest) (PAMApprovalRequest, error)
	GetPAMRequestProgress(ctx context.Context, tenantID, requester, approvalID string) (PAMRequestProgress, error)
	OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req PAMSessionRequest) (PAMSession, error)
	GetPAMSession(ctx context.Context, tenantID, id string) (PAMSession, error)
	ListPAMSessions(ctx context.Context, tenantID string, limit int, cursor string) ([]PAMSession, string, error)
	RevokePAMSession(ctx context.Context, tenantID, id, requester, reason string) (PAMSession, error)
}

// WithPAM wires the served PAM broker. When unset, routes fail closed with 503.
func WithPAM(svc PAMService) Option {
	return func(c *config) { c.pam = svc }
}

type PAMSessionRequest struct {
	RequestID         string
	ApprovalRequestID string
	IntentDigest      string
	TargetType        string
	TargetID          string
	Role              string
	Reason            string
	Method            string
	Payload           []byte
	TTLSeconds        int64
	SSHPublicKey      []byte
	SSHPrincipal      string
}

type pamSessionJSON struct {
	RequestID         string `json:"request_id"`
	ApprovalRequestID string `json:"approval_request_id"`
	IntentDigest      string `json:"intent_digest"`
	TargetType        string `json:"target_type"`
	TargetID          string `json:"target_id"`
	Role              string `json:"role"`
	Reason            string `json:"reason"`
	Method            string `json:"method"`
	PayloadBase64     string `json:"payload_base64"`
	TTLSeconds        int64  `json:"ttl_seconds"`
	SSHPublicKey      string `json:"ssh_public_key,omitempty"`
	SSHPrincipal      string `json:"ssh_principal,omitempty"`
}

// PAMApprovalRequest is the non-secret result of proposing one exact privileged
// access command. A reviewer must decide the returned digest before activation.
type PAMApprovalRequest struct {
	RequestID         string    `json:"request_id"`
	ApprovalRequestID string    `json:"approval_request_id"`
	IntentDigest      string    `json:"intent_digest"`
	Status            string    `json:"status"`
	Subject           string    `json:"subject"`
	TargetType        string    `json:"target_type"`
	TargetID          string    `json:"target_id"`
	Role              string    `json:"role"`
	ApprovalCount     int       `json:"approval_count"`
	RequiredApprovals int       `json:"required_approvals"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// PAMRequestProgress is the current non-secret review state of one request.
// Only its original requester can read it through the PAM route.
type PAMRequestProgress struct {
	RequestID         string    `json:"request_id"`
	ApprovalRequestID string    `json:"approval_request_id"`
	IntentDigest      string    `json:"intent_digest"`
	Status            string    `json:"status"`
	ApprovalCount     int       `json:"approval_count"`
	RequiredApprovals int       `json:"required_approvals"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type PAMSession struct {
	ID                    string     `json:"id"`
	TargetID              string     `json:"target_id"`
	TargetType            string     `json:"target_type"`
	Role                  string     `json:"role"`
	Status                string     `json:"status"`
	Subject               string     `json:"subject"`
	RequestedBy           string     `json:"requested_by"`
	Reason                string     `json:"reason,omitempty"`
	StartedAt             time.Time  `json:"started_at"`
	ExpiresAt             time.Time  `json:"expires_at"`
	EndedAt               *time.Time `json:"ended_at,omitempty"`
	RevocationRequestedBy string     `json:"revocation_requested_by,omitempty"`
	RevocationReason      string     `json:"revocation_reason,omitempty"`
	RevocationRequestedAt *time.Time `json:"revocation_requested_at,omitempty"`
	// Older sessions did not retain verified facts. Omit their attestation
	// instead of presenting a zero verification time as evidence.
	Attestation *attest.Attestation    `json:"attestation,omitempty"`
	Postgres    *PAMPostgresCredential `json:"postgres,omitempty"`
	SSH         *PAMSSHCredential      `json:"ssh,omitempty"`
	Audit       map[string]any         `json:"audit,omitempty"`
}

type PAMPostgresCredential struct {
	Username string          `json:"username"`
	DSN      secretJSONBytes `json:"dsn"`
}

func NewPAMPostgresCredential(username string, dsn []byte) *PAMPostgresCredential {
	return &PAMPostgresCredential{Username: username, DSN: secretJSONBytes(dsn)}
}

type PAMSSHCredential struct {
	Certificate secretJSONBytes `json:"certificate"`
	Principal   string          `json:"principal"`
	KeyID       string          `json:"key_id"`
	Serial      uint64          `json:"serial"`
	ValidBefore time.Time       `json:"valid_before"`
}

func NewPAMSSHCredential(certificate []byte, principal, keyID string, serial uint64, validBefore time.Time) *PAMSSHCredential {
	return &PAMSSHCredential{
		Certificate: secretJSONBytes(certificate),
		Principal:   principal,
		KeyID:       keyID,
		Serial:      serial,
		ValidBefore: validBefore,
	}
}

func (r *PAMSession) wipeSecrets() {
	if r == nil {
		return
	}
	if r.Postgres != nil {
		r.Postgres.DSN.wipe()
	}
	if r.SSH != nil {
		r.SSH.Certificate.wipe()
	}
}

//trstctl:mutation
func (a *API) requestPAMSession(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.pam == nil {
			return 0, nil, ErrPAMUnavailable
		}
		req, err := decodePAMSessionRequest(r)
		if err != nil {
			return 0, nil, err
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated requester is required")
		}
		pending, err := a.pam.RequestPAMSession(ctx, tenantID, principal.Subject, req)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, pending, nil
	})
}

func (a *API) getPAMRequestProgress(w http.ResponseWriter, r *http.Request) {
	if a.pam == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "PAM broker is not enabled"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	if principal.Subject == "" {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	progress, err := a.pam.GetPAMRequestProgress(r.Context(), tenantID, principal.Subject, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		if errors.Is(err, store.ErrApprovalRequestNotFound) {
			a.writeError(w, approvalAPIError(err))
			return
		}
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, progress)
}

func decodePAMSessionRequest(r *http.Request) (PAMSessionRequest, error) {
	var body pamSessionJSON
	if err := decodeJSON(r, &body); err != nil {
		return PAMSessionRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	payload, err := base64.StdEncoding.DecodeString(body.PayloadBase64)
	if err != nil || len(payload) == 0 {
		return PAMSessionRequest{}, errStatus(http.StatusBadRequest, "payload_base64 must be non-empty standard base64")
	}
	return PAMSessionRequest{
		RequestID:         strings.TrimSpace(body.RequestID),
		ApprovalRequestID: strings.TrimSpace(body.ApprovalRequestID),
		IntentDigest:      strings.TrimSpace(body.IntentDigest),
		TargetType:        strings.TrimSpace(body.TargetType), TargetID: strings.TrimSpace(body.TargetID),
		Role: strings.TrimSpace(body.Role), Reason: strings.TrimSpace(body.Reason),
		Method: strings.TrimSpace(body.Method), Payload: payload, TTLSeconds: body.TTLSeconds,
		SSHPublicKey: []byte(strings.TrimSpace(body.SSHPublicKey)), SSHPrincipal: strings.TrimSpace(body.SSHPrincipal),
	}, nil
}

// openPAMSession opens a short-lived brokered access session for a configured
// target. Mutations run through mutate(), so AN-5 replay returns the identical
// credential response without re-running backend grant creation.
//
//trstctl:mutation
func (a *API) openPAMSession(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("pam", "open_session", start, opErr) }()
		if a.pam == nil {
			opErr = ErrPAMUnavailable
			return 0, nil, ErrPAMUnavailable
		}
		req, err := decodePAMSessionRequest(r)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			opErr = errors.New("an authenticated requester is required")
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated requester is required")
		}
		session, err := a.pam.OpenPAMSession(ctx, tenantID, idempotencyKey, principal.Subject, req)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusCreated, &session, nil
	})
}

func (a *API) listPAMSessions(w http.ResponseWriter, r *http.Request) {
	if a.pam == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "PAM broker is not enabled"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusBadRequest, err.Error()))
		return
	}
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	sessions, next, err := a.pam.ListPAMSessions(r.Context(), tenantID, limit, cursor)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, struct {
		Items      []PAMSession `json:"items"`
		NextCursor string       `json:"next_cursor,omitempty"`
	}{Items: sessions, NextCursor: next})
}

func (a *API) getPAMSession(w http.ResponseWriter, r *http.Request) {
	if a.pam == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "PAM broker is not enabled"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	session, err := a.pam.GetPAMSession(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, session)
}

//trstctl:mutation
func (a *API) revokePAMSession(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.pam == nil {
			return 0, nil, ErrPAMUnavailable
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		body.Reason = strings.TrimSpace(body.Reason)
		if body.Reason == "" || len(body.Reason) > 1000 {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "a revocation reason of 1-1000 characters is required")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated revoker is required")
		}
		session, err := a.pam.RevokePAMSession(ctx, tenantID, strings.TrimSpace(r.PathValue("id")), principal.Subject, body.Reason)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, session, nil
	})
}

func (a *API) writePAMError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrPAMUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "PAM broker is not enabled"))
	case errors.Is(err, ErrPAMInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrPAMInvalid.Error()+": ")))
	case errors.Is(err, ErrPAMRejected):
		a.writeProblem(w, problem.New(http.StatusForbidden, strings.TrimPrefix(err.Error(), ErrPAMRejected.Error()+": ")))
	case errors.Is(err, ErrPAMTerminal):
		a.writeProblem(w, problem.New(http.StatusConflict, "PAM session is already ending or ended"))
	case errors.Is(err, store.ErrApprovalNotReady):
		a.writeProblem(w, problem.New(http.StatusConflict, "PAM session is awaiting distinct approval"))
	case errors.Is(err, store.ErrApprovalExpired):
		a.writeProblem(w, problem.New(http.StatusConflict, "PAM approval expired; request a new review"))
	case errors.Is(err, store.ErrApprovalSuperseded), errors.Is(err, store.ErrApprovalConsumed):
		a.writeProblem(w, problem.New(http.StatusConflict, "PAM approval can no longer activate this session"))
	case errors.Is(err, store.ErrApprovalDrifted), errors.Is(err, store.ErrApprovalDigestMismatch):
		a.writeProblem(w, problem.New(http.StatusForbidden, "PAM command differs from the approved intent"))
	default:
		return false
	}
	return true
}
