// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

const PAMSessionStatusActive = "active"

var (
	ErrPAMUnavailable    = errors.New("api: PAM broker is not enabled")
	ErrPAMInvalid        = errors.New("api: invalid PAM session request")
	ErrPAMRejected       = errors.New("api: PAM session rejected")
	ErrPAMTerminal       = errors.New("api: PAM session already ending or ended")
	ErrPAMTargetConflict = errors.New("api: PAM target conflicts with existing registration")
)

// PAMService is the served privileged-access broker. The API owns the
// tenant-scoped HTTP contract; the server implementation owns the attestation
// verifier, target adapters, SSH CA, event append, projection, and expiry worker.
type PAMService interface {
	RegisterPAMTarget(ctx context.Context, tenantID, actor string, target PAMTarget) (PAMTarget, error)
	ListPAMTargets(ctx context.Context, tenantID string) ([]PAMTarget, error)
	GetPAMTarget(ctx context.Context, tenantID, targetType, id string) (PAMTarget, error)
	DisablePAMTarget(ctx context.Context, tenantID, targetType, id, actor, reason string) (PAMTarget, error)
	RequestPAMSession(ctx context.Context, tenantID, requester string, req PAMSessionRequest) (PAMApprovalRequest, error)
	GetPAMRequestProgress(ctx context.Context, tenantID, requester, approvalID string) (PAMRequestProgress, error)
	OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req PAMSessionRequest) (PAMSession, error)
	GetPAMSession(ctx context.Context, tenantID, id string) (PAMSession, error)
	ListPAMSessions(ctx context.Context, tenantID string, limit int, cursor string) ([]PAMSession, string, error)
	RevokePAMSession(ctx context.Context, tenantID, id, requester, reason, idempotencyKey string) (PAMSession, error)
}

// PAMAgentSessionRevoker ends the live privileged sessions an agent opened,
// itself or through an access bundle run that acts as it (A257). The served
// PAM broker implements it beside PAMService; Q4's one-call revoke of the
// agent's identity calls it.
type PAMAgentSessionRevoker interface {
	RevokeAgentPAMSessions(ctx context.Context, tenantID, agent, actor, reason, idempotencyKey string) ([]PAMSession, error)
}

// PAMRecordingService reads gateway session recordings (A255). The served
// PAM broker implements it beside PAMService.
type PAMRecordingService interface {
	GetPAMRecording(ctx context.Context, tenantID, sessionID string) (PAMRecording, error)
	VerifyPAMRecording(ctx context.Context, tenantID, sessionID string) (PAMRecordingVerification, error)
	ReadPAMRecordingFrames(ctx context.Context, tenantID, sessionID, actor string, from, limit int, wait time.Duration) (PAMRecordingFrames, error)
	ExportPAMRecording(ctx context.Context, tenantID, sessionID, actor string) (PAMRecordingExport, error)
	SetPAMRecordingLegalHold(ctx context.Context, tenantID, sessionID, actor string, hold bool, reason string) (PAMRecording, error)
	TerminatePAMSession(ctx context.Context, tenantID, id, actor, reason, idempotencyKey string) (PAMSession, error)
}

// PAMRecordingFrames is one page of a recording's frames, each a JSON object
// as the gateway recorded it (already masked); Next is where the next page
// starts. A recording still being made may have more pages later.
type PAMRecordingFrames struct {
	SessionID string            `json:"session_id"`
	Status    string            `json:"status"`
	Next      int               `json:"next"`
	Frames    []json.RawMessage `json:"frames"`
}

// PAMRecordingExport is a sealed recording whole: its manifest, the audit
// key's JWS over it, and every frame.
type PAMRecordingExport struct {
	SessionID         string            `json:"session_id"`
	Manifest          json.RawMessage   `json:"manifest"`
	ManifestSignature string            `json:"manifest_signature"`
	Frames            []json.RawMessage `json:"frames"`
}

// PAMRecording is a gateway session's recording index (A255): how much is
// stored and whether it is sealed. The frames themselves are read separately.
type PAMRecording struct {
	SessionID      string     `json:"session_id"`
	Status         string     `json:"status"`
	Chunks         int        `json:"chunks"`
	Bytes          int64      `json:"bytes"`
	StartedAt      time.Time  `json:"started_at"`
	LastChunkAt    time.Time  `json:"last_chunk_at"`
	SealedAt       *time.Time `json:"sealed_at,omitempty"`
	FinalReceived  bool       `json:"final_received"`
	ChainHead      string     `json:"chain_head"`
	ManifestSHA256 string     `json:"manifest_sha256,omitempty"`
	// LegalHold keeps the recording past retention; DeletedAt is when
	// retention removed its objects.
	LegalHold       bool       `json:"legal_hold"`
	LegalHoldReason string     `json:"legal_hold_reason,omitempty"`
	DeletedAt       *time.Time `json:"deleted_at,omitempty"`
}

// PAMRecordingVerification is the outcome of verifying a sealed recording
// against its signed manifest.
type PAMRecordingVerification struct {
	Verified bool     `json:"verified"`
	Chunks   int      `json:"chunks"`
	Problems []string `json:"problems,omitempty"`
}

// PAMTarget is routing policy, never a credential. PostgreSQL administrator
// material stays in the tenant-bound dynamic-secret provider's protected ref.
type PAMTarget struct {
	ID             string     `json:"id"`
	TargetType     string     `json:"target_type"`
	ProviderID     string     `json:"provider_id,omitempty"`
	AllowedRoles   []string   `json:"allowed_roles,omitempty"`
	Host           string     `json:"host,omitempty"`
	Port           int        `json:"port,omitempty"`
	Principals     []string   `json:"principals,omitempty"`
	Enabled        bool       `json:"enabled"`
	Source         string     `json:"source"`
	RegisteredBy   string     `json:"registered_by,omitempty"`
	RegisteredAt   *time.Time `json:"registered_at,omitempty"`
	DisabledBy     string     `json:"disabled_by,omitempty"`
	DisabledReason string     `json:"disabled_reason,omitempty"`
	DisabledAt     *time.Time `json:"disabled_at,omitempty"`
	// GatewayAgentID and GatewayAddress (A254): the gateway-role agent that
	// serves this target and where clients reach it. A session to a bound
	// target is delivered through that gateway; the requester never receives
	// the upstream credential.
	GatewayAgentID string `json:"gateway_agent_id,omitempty"`
	GatewayAddress string `json:"gateway_address,omitempty"`
	// HostKeyFingerprints pin the host keys the gateway accepts from an SSH
	// target (SHA256:...); a gateway-bound SSH target names at least one.
	HostKeyFingerprints []string `json:"host_key_fingerprints,omitempty"`
	// Health (A258) is the last read-only sign-in check of the credential a
	// provider-backed target's provider holds; absent before its first check.
	Health *PAMAccountHealth `json:"health,omitempty"`
}

// PAMAccountHealth is a brokered account's credential health (A258).
type PAMAccountHealth struct {
	Status       string     `json:"status"`
	Attempts     int        `json:"attempts"`
	CheckedAt    time.Time  `json:"checked_at"`
	FailingSince *time.Time `json:"failing_since,omitempty"`
	// NotRetried says the server judged and refused the credential: no
	// scheduled check signs in with it again until it changes.
	NotRetried bool `json:"not_retried"`
}

// PAMAccountHealthChecker checks one brokered account's credential now
// (A258); the served PAM broker implements it beside PAMService.
type PAMAccountHealthChecker interface {
	CheckPAMAccountHealth(ctx context.Context, tenantID, targetType, id string) (PAMTarget, error)
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
	TemplateID        string
	// Browser is set on an open for the browser (A259); it is not part of
	// the reviewed command.
	Browser bool
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
	// TemplateID names an access template (A258): its reason is recorded,
	// its approvals raise the quorum and its maximum length bounds the
	// session.
	TemplateID string `json:"template_id,omitempty"`
	// Browser (A259) opens the session for the browser: the control plane
	// keeps its ticket and the reply carries none.
	Browser bool `json:"browser,omitempty"`
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
	RevocationFailure     string     `json:"revocation_failure,omitempty"`
	RevocationFailedAt    *time.Time `json:"revocation_failed_at,omitempty"`
	// Older sessions did not retain verified facts. Omit their attestation
	// instead of presenting a zero verification time as evidence.
	Attestation *attest.Attestation    `json:"attestation,omitempty"`
	Postgres    *PAMPostgresCredential `json:"postgres,omitempty"`
	SSH         *PAMSSHCredential      `json:"ssh,omitempty"`
	// Gateway (A254) is how to reach a session delivered through a gateway;
	// its ticket is returned once, by the open. Such a session never carries
	// Postgres or SSH credentials.
	Gateway *PAMGatewayDelivery `json:"gateway,omitempty"`
	// Delivery is "direct" or "gateway".
	Delivery string `json:"delivery,omitempty"`
	// GatewayEnd (A255) is the gateway's own report that it ended the
	// session. A revoked or terminated gateway session without one is
	// uncertain until UncertainUntil, its native deadline: the gateway may be
	// cut off, and the credential stops working then regardless.
	GatewayEnd     *PAMGatewayEnd `json:"gateway_end,omitempty"`
	UncertainUntil *time.Time     `json:"uncertain_until,omitempty"`
	Audit          map[string]any `json:"audit,omitempty"`
	// Emergency (A258) marks a session a named responder opened without
	// approval, with its post-incident review.
	Emergency *PAMEmergencyGrant `json:"emergency,omitempty"`
}

// PAMGatewayEnd is how and when the gateway ended a session: "deadline" or
// "recalled" (by a revocation or termination).
type PAMGatewayEnd struct {
	Ended   string    `json:"ended"`
	EndedAt time.Time `json:"ended_at"`
}

// PAMGatewayDelivery names the gateway a session is delivered through and how
// a client verifies it: the gateway's agent certificate chains to CAPEM and
// carries exactly SPIFFEID. Ticket admits the client's connections; it is
// shown once and is not the upstream credential.
type PAMGatewayDelivery struct {
	AgentID  string          `json:"agent_id"`
	Address  string          `json:"address"`
	SPIFFEID string          `json:"spiffe_id"`
	CAPEM    string          `json:"ca_pem,omitempty"`
	Ticket   secretJSONBytes `json:"ticket,omitempty"`
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
		if err := a.requireDelegatedAccount(ctx, tenantID, principal, req); err != nil {
			return 0, nil, err
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
		TemplateID: strings.TrimSpace(body.TemplateID),
		Browser:    body.Browser,
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
		if err := a.requireDelegatedAccount(ctx, tenantID, principal, req); err != nil {
			opErr = err
			return 0, nil, err
		}
		session, err := a.pam.OpenPAMSession(ctx, tenantID, idempotencyKey, principal.Subject, req)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		if req.Browser {
			// A259: the control plane keeps a browser session's ticket for
			// its opener; the reply, and its cached replay, carry none.
			if err := a.holdBrowserTicket(tenantID, principal.Subject, &session); err != nil {
				opErr = err
				return 0, nil, err
			}
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
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
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

// getPAMRecording and verifyPAMRecording read a session's recording index
// and check its seal (A255).
func (a *API) getPAMRecording(w http.ResponseWriter, r *http.Request) {
	a.pamRecordingRead(w, r, func(svc PAMRecordingService, tenantID, id string) (any, error) {
		return svc.GetPAMRecording(r.Context(), tenantID, id)
	})
}

func (a *API) verifyPAMRecording(w http.ResponseWriter, r *http.Request) {
	a.pamRecordingRead(w, r, func(svc PAMRecordingService, tenantID, id string) (any, error) {
		return svc.VerifyPAMRecording(r.Context(), tenantID, id)
	})
}

// readPAMRecordingFrames plays a recording back by pages; with wait (seconds,
// at most 25) it long-polls for frames still being recorded — live watching.
func (a *API) readPAMRecordingFrames(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, _ := strconv.Atoi(q.Get("from"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	waitSeconds, _ := strconv.Atoi(q.Get("wait"))
	a.pamRecordingRead(w, r, func(svc PAMRecordingService, tenantID, id string) (any, error) {
		return svc.ReadPAMRecordingFrames(r.Context(), tenantID, id, principalSubject(r.Context()), from, limit, time.Duration(waitSeconds)*time.Second)
	})
}

func (a *API) exportPAMRecording(w http.ResponseWriter, r *http.Request) {
	a.pamRecordingRead(w, r, func(svc PAMRecordingService, tenantID, id string) (any, error) {
		return svc.ExportPAMRecording(r.Context(), tenantID, id, principalSubject(r.Context()))
	})
}

//trstctl:mutation
func (a *API) placePAMRecordingLegalHold(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), a.pamRecordingLegalHold(r, true))
}

//trstctl:mutation
func (a *API) releasePAMRecordingLegalHold(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), a.pamRecordingLegalHold(r, false))
}

// pamRecordingLegalHold places (hold) or releases a recording's legal hold.
func (a *API) pamRecordingLegalHold(r *http.Request, hold bool) func(ctx context.Context, tenantID string) (int, any, error) {
	return func(ctx context.Context, tenantID string) (int, any, error) {
		svc, ok := a.pam.(PAMRecordingService)
		if a.pam == nil || !ok {
			return 0, nil, ErrPAMUnavailable
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if hold {
			if err := decodeJSON(r, &body); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
		}
		actor := principalSubject(r.Context())
		if actor == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "authenticated actor required")
		}
		out, err := svc.SetPAMRecordingLegalHold(ctx, tenantID, strings.TrimSpace(r.PathValue("id")), actor, hold, body.Reason)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, out, nil
	}
}

// terminatePAMSession ends another principal's live gateway session (A255).
//
//trstctl:mutation
func (a *API) terminatePAMSession(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, ok := a.pam.(PAMRecordingService)
		if a.pam == nil || !ok {
			return 0, nil, ErrPAMUnavailable
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		actor := principalSubject(r.Context())
		if actor == "" {
			return 0, nil, errStatus(http.StatusUnauthorized, "authenticated actor required")
		}
		session, err := svc.TerminatePAMSession(ctx, tenantID, strings.TrimSpace(r.PathValue("id")), actor, body.Reason, r.Header.Get("Idempotency-Key"))
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, session, nil
	})
}

func (a *API) pamRecordingRead(w http.ResponseWriter, r *http.Request, read func(PAMRecordingService, string, string) (any, error)) {
	svc, ok := a.pam.(PAMRecordingService)
	if a.pam == nil || !ok {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "session recordings are not enabled"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	out, err := read(svc, tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, out)
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
		id := strings.TrimSpace(r.PathValue("id"))
		if !principal.Can(authz.AccessWrite, authz.Scope{TenantID: tenantID}) {
			// access:sessions.open (A257) revokes the caller's own sessions
			// only; another principal's needs access:write.
			current, err := a.pam.GetPAMSession(ctx, tenantID, id)
			if err != nil {
				return 0, nil, err
			}
			if current.RequestedBy != principal.Subject {
				return 0, nil, errStatus(http.StatusForbidden, "access:sessions.open revokes your own sessions; another principal's needs access:write")
			}
		}
		session, err := a.pam.RevokePAMSession(ctx, tenantID, id, principal.Subject, body.Reason, r.Header.Get("Idempotency-Key"))
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, session, nil
	})
}

// requireDelegatedAccount refuses an access bundle run's session request for
// an account its bundles do not delegate (A257): a run may reach only the
// (target type, target, role) its live grants' bundles name. A principal
// that is not a run is limited by its permissions alone, as before.
func (a *API) requireDelegatedAccount(ctx context.Context, tenantID string, principal authz.Principal, req PAMSessionRequest) error {
	if principal.RunID == "" {
		return nil
	}
	targets, err := a.store.RunAccessTargets(ctx, tenantID, principal.RunID, time.Now())
	if err != nil {
		return err
	}
	for _, t := range targets {
		if t.TargetType == req.TargetType && t.TargetID == req.TargetID && slices.Contains(t.Roles, req.Role) {
			return nil
		}
	}
	return errStatus(http.StatusForbidden, fmt.Sprintf("%s/%s as %s is not among the accounts this run's access bundles delegate", req.TargetType, req.TargetID, req.Role))
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
	case errors.Is(err, ErrPAMTargetConflict):
		a.writeProblem(w, problem.New(http.StatusConflict, strings.TrimPrefix(err.Error(), ErrPAMTargetConflict.Error()+": ")))
	case errors.Is(err, store.ErrApprovalNotReady):
		a.writeProblem(w, problem.New(http.StatusConflict, "PAM session is awaiting distinct approval"))
	case errors.Is(err, store.ErrApprovalExpired):
		a.writeProblem(w, problem.New(http.StatusConflict, "PAM approval expired; request a new review"))
	case errors.Is(err, store.ErrApprovalSuperseded), errors.Is(err, store.ErrApprovalConsumed):
		a.writeProblem(w, problem.New(http.StatusConflict, "PAM approval can no longer activate this session"))
	case errors.Is(err, store.ErrApprovalDrifted), errors.Is(err, store.ErrApprovalDigestMismatch):
		a.writeProblem(w, problem.New(http.StatusForbidden, "PAM command differs from the approved intent"))
	case errors.Is(err, store.ErrPAMTargetNotFound):
		a.writeProblem(w, problem.New(http.StatusNotFound, "PAM target not found"))
	default:
		return false
	}
	return true
}
