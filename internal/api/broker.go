// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

var (
	ErrBrokerUnavailable = errors.New("api: agent broker is not enabled")
	ErrBrokerInvalid     = errors.New("api: invalid agent broker request")
	ErrBrokerRejected    = errors.New("api: agent broker request rejected")
)

// BrokerService is the served AI-agent / NHI broker surface (F61). The API owns
// the tenant-scoped HTTP contract; the server implementation owns policy,
// attestation, signing, and event-sourced graph projection.
type BrokerService interface {
	PreviewBrokerAgentIdentity(ctx context.Context, tenantID, requester string, req BrokerAgentIdentityRequest) (BrokerAgentIdentityPreview, error)
	IssueBrokerAgentIdentity(ctx context.Context, tenantID, idempotencyKey string, req BrokerAgentIdentityRequest) (BrokerAgentIdentity, error)
}

// WithBroker wires the served AI-agent / NHI broker. When unset, the route fails
// closed with 503.
func WithBroker(svc BrokerService) Option {
	return func(c *config) { c.broker = svc }
}

type BrokerAgentIdentityRequest struct {
	AgentID      string
	Method       string
	Payload      []byte
	PublicKeyDER []byte
	Scopes       []string
	TTLSeconds   int64
	// TaskEnvelope is the optional opaque AGID-05 task envelope binding this
	// credential to one authorized task (B-7). The chain-bound delegation path
	// has carried one since AGID-05; the broker's single-hop path could not,
	// so a broker-issued agent credential could not be task-scoped at all.
	// Core never interprets these bytes: verification is the licensed AGID
	// gate's job, reached through BrokerTaskEnvelopeGate.
	TaskEnvelope []byte
}

type brokerAgentIdentityJSON struct {
	AgentID            string          `json:"agent_id"`
	Method             string          `json:"method"`
	PayloadBase64      secretJSONBytes `json:"payload_base64"`
	PublicKeyPEM       string          `json:"public_key_pem"`
	Scopes             []string        `json:"scopes"`
	TTLSeconds         int64           `json:"ttl_seconds"`
	TaskEnvelopeBase64 secretJSONBytes `json:"task_envelope_base64,omitempty"`
}

func (r *brokerAgentIdentityJSON) wipeSecrets() {
	r.PayloadBase64.wipe()
	r.TaskEnvelopeBase64.wipe()
	r.PayloadBase64 = nil
	r.TaskEnvelopeBase64 = nil
}

func brokerRequestFromJSON(req brokerAgentIdentityJSON) (BrokerAgentIdentityRequest, error) {
	defer req.PayloadBase64.wipe()
	defer req.TaskEnvelopeBase64.wipe()
	agentID, method := strings.TrimSpace(req.AgentID), strings.TrimSpace(req.Method)
	if agentID == "" {
		return BrokerAgentIdentityRequest{}, errStatus(http.StatusBadRequest, "agent_id is required")
	}
	if method == "" {
		return BrokerAgentIdentityRequest{}, errStatus(http.StatusBadRequest, "method is required")
	}
	if len(req.Scopes) == 0 {
		return BrokerAgentIdentityRequest{}, errStatus(http.StatusBadRequest, "at least one scope is required")
	}
	payload := make([]byte, base64.StdEncoding.DecodedLen(len(req.PayloadBase64)))
	n, err := base64.StdEncoding.Decode(payload, req.PayloadBase64)
	if err != nil || n == 0 {
		secret.Wipe(payload)
		return BrokerAgentIdentityRequest{}, errStatus(http.StatusBadRequest, "payload_base64 must be non-empty standard base64")
	}
	payload = payload[:n]
	key, err := crypto.ParsePublicKeyPEM([]byte(req.PublicKeyPEM))
	if err != nil {
		secret.Wipe(payload)
		return BrokerAgentIdentityRequest{}, errStatus(http.StatusBadRequest, "public_key_pem must contain exactly one valid PUBLIC KEY PEM block")
	}
	var envelope []byte
	if len(req.TaskEnvelopeBase64) > 0 {
		raw := bytes.TrimSpace(req.TaskEnvelopeBase64)
		envelope = make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
		n, err := base64.StdEncoding.Decode(envelope, raw)
		if err != nil || n == 0 {
			secret.Wipe(payload)
			secret.Wipe(envelope)
			return BrokerAgentIdentityRequest{}, errStatus(http.StatusBadRequest, "task_envelope_base64 must be non-empty standard base64")
		}
		envelope = envelope[:n]
	}
	return BrokerAgentIdentityRequest{AgentID: agentID, Method: method, Payload: payload,
		PublicKeyDER: key.DER, Scopes: append([]string(nil), req.Scopes...),
		TTLSeconds: req.TTLSeconds, TaskEnvelope: envelope}, nil
}

type BrokerAgentIdentity struct {
	// TaskEnvelopeDigest is the digest of the verified AGID-05 task envelope
	// this credential is bound to (B-7). Empty when the caller supplied none:
	// the credential is then the ordinary single-hop agent badge. A caller
	// that DID supply an envelope can compare this to its own digest and
	// confirm the credential is scoped to the task it authorized.
	TaskEnvelopeDigest string             `json:"task_envelope_digest,omitempty"`
	AgentID            string             `json:"agent_id"`
	NodeID             string             `json:"node_id"`
	Subject            string             `json:"subject"`
	CredentialID       string             `json:"credential_id"`
	CertificateID      string             `json:"certificate_id"`
	CertificatePEM     string             `json:"certificate_pem"`
	SPIFFEID           string             `json:"spiffe_id,omitempty"`
	Scopes             []string           `json:"scopes"`
	NotAfter           time.Time          `json:"not_after"`
	Attestation        attest.Attestation `json:"attestation"`
}

// BrokerAgentIdentityPreview describes the exact command without consuming
// attestation or task proof. Ready means configured, never proof-verified.
type BrokerAgentIdentityPreview struct {
	Capability               string   `json:"capability"`
	Ready                    bool     `json:"ready"`
	EffectFree               bool     `json:"effect_free"`
	AgentID                  string   `json:"agent_id"`
	Method                   string   `json:"method"`
	Requester                string   `json:"requester"`
	TrustDomain              string   `json:"trust_domain"`
	Scopes                   []string `json:"scopes"`
	SupportedMethods         []string `json:"supported_methods"`
	RequestedTTLSeconds      int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds      int64    `json:"effective_ttl_seconds"`
	DefaultTTLSeconds        int64    `json:"default_ttl_seconds"`
	MaxTTLSeconds            int64    `json:"max_ttl_seconds"`
	TTLDefaulted             bool     `json:"ttl_defaulted"`
	TTLClamped               bool     `json:"ttl_clamped"`
	RequiredPermission       string   `json:"required_permission"`
	AttestationVerification  string   `json:"attestation_verification"`
	PolicyEvaluation         string   `json:"policy_evaluation"`
	TaskEnvelopeVerification string   `json:"task_envelope_verification"`
	PayloadSHA256            string   `json:"payload_sha256"`
	PublicKeySHA256          string   `json:"public_key_sha256"`
	TaskEnvelopeSHA256       string   `json:"task_envelope_sha256"`
	PreviewWrites            []string `json:"preview_writes"`
	PreviewExternalEffects   []string `json:"preview_external_effects"`
	PreviewSignerCalls       []string `json:"preview_signer_calls"`
	ExecutionWrites          []string `json:"execution_writes"`
	ExecutionExternalEffects []string `json:"execution_external_effects"`
	ExecutionSignerCalls     []string `json:"execution_signer_calls"`
	Steps                    []string `json:"steps"`
	Blockers                 []string `json:"blockers"`
	RecoverySteps            []string `json:"recovery_steps"`
	DataHandling             []string `json:"data_handling"`
}

func (a *API) previewBrokerAgentIdentity(w http.ResponseWriter, r *http.Request) {
	if a.broker == nil {
		a.writeError(w, ErrBrokerUnavailable)
		return
	}
	var wire brokerAgentIdentityJSON
	defer wire.wipeSecrets()
	if err := decodeJSON(r, &wire); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	command, err := brokerRequestFromJSON(wire)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(command.Payload)
	defer secret.Wipe(command.TaskEnvelope)
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	preview, err := a.broker.PreviewBrokerAgentIdentity(r.Context(), tenantID, principal, command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

//trstctl:mutation
func (a *API) issueBrokerAgentIdentity(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("agent_broker", "issue_identity", start, opErr) }()
		if a.broker == nil {
			opErr = ErrBrokerUnavailable
			return 0, nil, ErrBrokerUnavailable
		}
		var req brokerAgentIdentityJSON
		defer req.wipeSecrets()
		if err := decodeJSON(r, &req); err != nil {
			opErr = err
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		command, err := brokerRequestFromJSON(req)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		defer secret.Wipe(command.Payload)
		defer secret.Wipe(command.TaskEnvelope)
		issued, err := a.broker.IssueBrokerAgentIdentity(ctx, tenantID, idempotencyKey, command)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusCreated, issued, nil
	})
}

func (a *API) writeBrokerError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrBrokerUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "agent broker is not enabled"))
	case errors.Is(err, ErrBrokerInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrBrokerInvalid.Error()+": ")))
	case errors.Is(err, ErrBrokerRejected):
		a.writeProblem(w, problem.New(http.StatusForbidden, strings.TrimPrefix(err.Error(), ErrBrokerRejected.Error()+": ")))
	default:
		return false
	}
	return true
}
