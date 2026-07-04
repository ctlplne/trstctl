// SPDX-License-Identifier: MPL-2.0

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
}

type brokerAgentIdentityJSON struct {
	AgentID       string   `json:"agent_id"`
	Method        string   `json:"method"`
	PayloadBase64 string   `json:"payload_base64"`
	PublicKeyPEM  string   `json:"public_key_pem"`
	Scopes        []string `json:"scopes"`
	TTLSeconds    int64    `json:"ttl_seconds"`
}

type BrokerAgentIdentity struct {
	AgentID        string             `json:"agent_id"`
	NodeID         string             `json:"node_id"`
	Subject        string             `json:"subject"`
	CredentialID   string             `json:"credential_id"`
	CertificateID  string             `json:"certificate_id"`
	CertificatePEM string             `json:"certificate_pem"`
	Scopes         []string           `json:"scopes"`
	NotAfter       time.Time          `json:"not_after"`
	Attestation    attest.Attestation `json:"attestation"`
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
		if err := decodeJSON(r, &req); err != nil {
			opErr = err
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		agentID := strings.TrimSpace(req.AgentID)
		method := strings.TrimSpace(req.Method)
		if agentID == "" {
			opErr = errors.New("agent_id is required")
			return 0, nil, errStatus(http.StatusBadRequest, "agent_id is required")
		}
		if method == "" {
			opErr = errors.New("method is required")
			return 0, nil, errStatus(http.StatusBadRequest, "method is required")
		}
		if len(req.Scopes) == 0 {
			opErr = errors.New("at least one scope is required")
			return 0, nil, errStatus(http.StatusBadRequest, "at least one scope is required")
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
		issued, err := a.broker.IssueBrokerAgentIdentity(ctx, tenantID, idempotencyKey, BrokerAgentIdentityRequest{
			AgentID:      agentID,
			Method:       method,
			Payload:      payload,
			PublicKeyDER: block.Bytes,
			Scopes:       append([]string(nil), req.Scopes...),
			TTLSeconds:   req.TTLSeconds,
		})
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
