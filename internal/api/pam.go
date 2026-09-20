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
)

const PAMSessionStatusActive = "active"

var (
	ErrPAMUnavailable = errors.New("api: PAM broker is not enabled")
	ErrPAMInvalid     = errors.New("api: invalid PAM session request")
	ErrPAMRejected    = errors.New("api: PAM session rejected")
)

// PAMService is the served privileged-access broker. The API owns the
// tenant-scoped HTTP contract; the server implementation owns the attestation
// verifier, target adapters, SSH CA, event append, projection, and expiry worker.
type PAMService interface {
	OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req PAMSessionRequest) (PAMSession, error)
	GetPAMSession(ctx context.Context, tenantID, id string) (PAMSession, error)
	ListPAMSessions(ctx context.Context, tenantID string, limit int, cursor string) ([]PAMSession, string, error)
}

// WithPAM wires the served PAM broker. When unset, routes fail closed with 503.
func WithPAM(svc PAMService) Option {
	return func(c *config) { c.pam = svc }
}

type PAMSessionRequest struct {
	TargetType   string
	TargetID     string
	Role         string
	Reason       string
	Method       string
	Payload      []byte
	TTLSeconds   int64
	SSHPublicKey []byte
	SSHPrincipal string
}

type pamSessionJSON struct {
	TargetType    string `json:"target_type"`
	TargetID      string `json:"target_id"`
	Role          string `json:"role"`
	Reason        string `json:"reason"`
	Method        string `json:"method"`
	PayloadBase64 string `json:"payload_base64"`
	TTLSeconds    int64  `json:"ttl_seconds"`
	SSHPublicKey  string `json:"ssh_public_key,omitempty"`
	SSHPrincipal  string `json:"ssh_principal,omitempty"`
}

type PAMSession struct {
	ID          string                 `json:"id"`
	TargetID    string                 `json:"target_id"`
	TargetType  string                 `json:"target_type"`
	Role        string                 `json:"role"`
	Status      string                 `json:"status"`
	Subject     string                 `json:"subject"`
	RequestedBy string                 `json:"requested_by"`
	Reason      string                 `json:"reason,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	EndedAt     *time.Time             `json:"ended_at,omitempty"`
	Attestation attest.Attestation     `json:"attestation"`
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
		var req pamSessionJSON
		if err := decodeJSON(r, &req); err != nil {
			opErr = err
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		payload, err := base64.StdEncoding.DecodeString(req.PayloadBase64)
		if err != nil || len(payload) == 0 {
			opErr = errors.New("payload_base64 must be non-empty standard base64")
			return 0, nil, errStatus(http.StatusBadRequest, "payload_base64 must be non-empty standard base64")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if principal.Subject == "" {
			opErr = errors.New("an authenticated requester is required")
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated requester is required")
		}
		session, err := a.pam.OpenPAMSession(ctx, tenantID, idempotencyKey, principal.Subject, PAMSessionRequest{
			TargetType:   strings.TrimSpace(req.TargetType),
			TargetID:     strings.TrimSpace(req.TargetID),
			Role:         strings.TrimSpace(req.Role),
			Reason:       strings.TrimSpace(req.Reason),
			Method:       strings.TrimSpace(req.Method),
			Payload:      payload,
			TTLSeconds:   req.TTLSeconds,
			SSHPublicKey: []byte(strings.TrimSpace(req.SSHPublicKey)),
			SSHPrincipal: strings.TrimSpace(req.SSHPrincipal),
		})
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

func (a *API) writePAMError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrPAMUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "PAM broker is not enabled"))
	case errors.Is(err, ErrPAMInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrPAMInvalid.Error()+": ")))
	case errors.Is(err, ErrPAMRejected):
		a.writeProblem(w, problem.New(http.StatusForbidden, strings.TrimPrefix(err.Error(), ErrPAMRejected.Error()+": ")))
	default:
		return false
	}
	return true
}
