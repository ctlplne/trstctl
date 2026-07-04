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
	ErrAttestedIssuanceUnavailable = errors.New("api: attested issuance is not enabled")
	ErrAttestedIssuanceInvalid     = errors.New("api: invalid attested issuance request")
	ErrAttestedIssuanceRejected    = errors.New("api: attestation rejected")
)

// AttestedIssuerService is the served workload-attested issuance surface (F30).
// The API owns the tenant-scoped HTTP contract; the server implementation owns
// the configured attesters and signer-backed CA.
type AttestedIssuerService interface {
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
	Method        string `json:"method"`
	PayloadBase64 string `json:"payload_base64"`
	PublicKeyPEM  string `json:"public_key_pem"`
	TTLSeconds    int64  `json:"ttl_seconds"`
}

type AttestedSVID struct {
	CertificatePEM string             `json:"certificate_pem"`
	CredentialID   string             `json:"credential_id"`
	Subject        string             `json:"subject"`
	NotAfter       time.Time          `json:"not_after"`
	Attestation    attest.Attestation `json:"attestation"`
}

//trstctl:mutation
func (a *API) issueAttestedSVID(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		start := time.Now()
		var opErr error
		defer func() { a.observeFeature("attestation", "issue_svid", start, opErr) }()
		if a.attestedIssuer == nil {
			opErr = ErrAttestedIssuanceUnavailable
			return 0, nil, ErrAttestedIssuanceUnavailable
		}
		var req attestedSVIDJSON
		if err := decodeJSON(r, &req); err != nil {
			opErr = err
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		method := strings.TrimSpace(req.Method)
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
		issued, err := a.attestedIssuer.IssueAttestedSVID(ctx, tenantID, idempotencyKey, AttestedSVIDRequest{
			Method:       method,
			Payload:      payload,
			PublicKeyDER: block.Bytes,
			TTLSeconds:   req.TTLSeconds,
		})
		if err != nil {
			opErr = err
			return 0, nil, err
		}
		return http.StatusCreated, issued, nil
	})
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
