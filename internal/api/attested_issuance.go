// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	ErrAttestedIssuanceUnavailable = errors.New("api: attested issuance is not enabled")
	ErrAttestedIssuanceInvalid     = errors.New("api: invalid attested issuance request")
	ErrAttestedIssuanceRejected    = errors.New("api: attestation rejected")
)

// AttestedIssuerService is the served workload-attested issuance surface (F30).
// The API owns the tenant-scoped HTTP contract; the server implementation owns
// the configured attesters and signer-backed CA.
type AttestedIssuerService interface {
	PreviewAttestedSVID(ctx context.Context, tenantID, requester string, req AttestedSVIDRequest) (AttestedSVIDPreview, error)
	IssueAttestedSVID(ctx context.Context, tenantID, idempotencyKey string, req AttestedSVIDRequest) (AttestedSVID, error)
}

// WithAttestedIssuer wires the served attestation verifier + SVID issuer. When
// unset, the route fails closed with 503.
func WithAttestedIssuer(svc AttestedIssuerService) Option {
	return func(c *config) { c.attestedIssuer = svc }
}

type AttestedSVIDRequest struct {
	Method       string
	Payload      []byte
	PublicKeyDER []byte
	TTLSeconds   int64
}

type attestedSVIDJSON struct {
	Method        string          `json:"method"`
	PayloadBase64 secretJSONBytes `json:"payload_base64"`
	PublicKeyPEM  string          `json:"public_key_pem"`
	TTLSeconds    int64           `json:"ttl_seconds"`
}

func (r *attestedSVIDJSON) wipeSecrets() {
	r.PayloadBase64.wipe()
	r.PayloadBase64 = nil
}

type AttestedSVID struct {
	CertificatePEM string             `json:"certificate_pem"`
	SPIFFEID       string             `json:"spiffe_id,omitempty"`
	CredentialID   string             `json:"credential_id"`
	Subject        string             `json:"subject"`
	NotAfter       time.Time          `json:"not_after"`
	Attestation    attest.Attestation `json:"attestation"`
}

// AttestedSVIDPreview contains only exact request digests and operational
// metadata. A ready preview is not proof verification or issuance permission.
type AttestedSVIDPreview struct {
	Capability               string   `json:"capability"`
	Ready                    bool     `json:"ready"`
	EffectFree               bool     `json:"effect_free"`
	Method                   string   `json:"method"`
	Requester                string   `json:"requester"`
	TrustDomain              string   `json:"trust_domain"`
	SupportedMethods         []string `json:"supported_methods"`
	RequestedTTLSeconds      int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds      int64    `json:"effective_ttl_seconds"`
	DefaultTTLSeconds        int64    `json:"default_ttl_seconds"`
	MaxTTLSeconds            int64    `json:"max_ttl_seconds"`
	TTLDefaulted             bool     `json:"ttl_defaulted"`
	TTLClamped               bool     `json:"ttl_clamped"`
	RequiredPermission       string   `json:"required_permission"`
	AttestationVerification  string   `json:"attestation_verification"`
	PayloadSHA256            string   `json:"payload_sha256"`
	PublicKeySHA256          string   `json:"public_key_sha256"`
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

func attestedSVIDRequestFromJSON(req attestedSVIDJSON) (AttestedSVIDRequest, error) {
	// Kubernetes/GitHub proof can be a bearer credential. Both its base64 wire
	// representation and its decoded form must remain wipeable, never strings.
	defer req.PayloadBase64.wipe()
	method := strings.TrimSpace(req.Method)
	if method == "" {
		return AttestedSVIDRequest{}, errStatus(http.StatusBadRequest, "method is required")
	}
	payload := make([]byte, base64.StdEncoding.DecodedLen(len(req.PayloadBase64)))
	n, err := base64.StdEncoding.Decode(payload, req.PayloadBase64)
	if err != nil || n == 0 {
		secret.Wipe(payload)
		return AttestedSVIDRequest{}, errStatus(http.StatusBadRequest, "payload_base64 must be non-empty standard base64")
	}
	payload = payload[:n]
	key, err := crypto.ParsePublicKeyPEM([]byte(req.PublicKeyPEM))
	if err != nil {
		secret.Wipe(payload)
		return AttestedSVIDRequest{}, errStatus(http.StatusBadRequest, "public_key_pem must contain exactly one valid PUBLIC KEY PEM block")
	}
	return AttestedSVIDRequest{Method: method, Payload: payload, PublicKeyDER: key.DER, TTLSeconds: req.TTLSeconds}, nil
}

// previewAttestedSVID never verifies proof: a verifier can consume a nonce or
// emit an audit event. Those effects belong only to the explicit issue command.
func (a *API) previewAttestedSVID(w http.ResponseWriter, r *http.Request) {
	if a.attestedIssuer == nil {
		a.writeError(w, ErrAttestedIssuanceUnavailable)
		return
	}
	var wire attestedSVIDJSON
	// Register the pointer receiver before decoding: it also wipes a proof
	// decoded before a later field or trailing JSON document is rejected.
	defer wire.wipeSecrets()
	if err := decodeJSON(r, &wire); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	command, err := attestedSVIDRequestFromJSON(wire)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(command.Payload)
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
	preview, err := a.attestedIssuer.PreviewAttestedSVID(r.Context(), tenantID, principal, command)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, preview)
}

//trstctl:mutation
func (a *API) issueAttestedSVID(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	var wire attestedSVIDJSON
	defer wire.wipeSecrets()
	if err := decodeJSON(r, &wire); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req, err := attestedSVIDRequestFromJSON(wire)
	if err != nil {
		a.writeError(w, err)
		return
	}
	defer secret.Wipe(req.Payload)
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := attestedSVIDRequestBinding(principal, req.Method, req.Payload, req.PublicKeyDER, req.TTLSeconds)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("attestation", "issue_svid", start, opErr) }()
		if a.attestedIssuer == nil {
			opErr = ErrAttestedIssuanceUnavailable
			return 0, nil, ErrAttestedIssuanceUnavailable
		}
		issued, err := a.attestedIssuer.IssueAttestedSVID(ctx, tenantID, idempotencyKey, req)
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusCreated, issued, nil
	})
}

func attestedSVIDRequestBinding(principal, method string, payload, publicKeyDER []byte, ttlSeconds int64) (string, error) {
	if strings.TrimSpace(principal) == "" || strings.TrimSpace(method) == "" || len(payload) == 0 || len(publicKeyDER) == 0 {
		return "", errors.New("api: incomplete attested issuance request binding")
	}
	canonical, err := json.Marshal(struct {
		Principal       string `json:"principal"`
		Method          string `json:"method"`
		PayloadSHA256   string `json:"payload_sha256"`
		PublicKeySHA256 string `json:"public_key_sha256"`
		TTLSeconds      int64  `json:"ttl_seconds"`
	}{
		Principal: principal, Method: strings.TrimSpace(method),
		PayloadSHA256: crypto.SHA256Hex(payload), PublicKeySHA256: crypto.SHA256Hex(publicKeyDER),
		TTLSeconds: ttlSeconds,
	})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("attested-svid-request-v1\x00"), canonical...)), nil
}

func (a *API) writeAttestedIssuanceError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrAttestedIssuanceUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "attested issuance is not enabled"))
	case errors.Is(err, ErrAttestedIssuanceInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrAttestedIssuanceInvalid.Error()+": ")))
	case errors.Is(err, ErrAttestedIssuanceRejected):
		a.writeProblem(w, problem.New(http.StatusForbidden, strings.TrimPrefix(err.Error(), ErrAttestedIssuanceRejected.Error()+": ")))
	default:
		return false
	}
	return true
}
