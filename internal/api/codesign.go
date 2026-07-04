// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
)

// CodeSigningService is the served code-signing backend. The API owns transport,
// authz, and idempotency; the composition root supplies the real signer/keyless
// implementation plus the Rekor/Fulcio outbox wiring.
type CodeSigningService interface {
	SignCode(ctx context.Context, tenantID, idempotencyKey string, req CodeSigningRequest) (CodeSigningResponse, error)
	SignKeylessCode(ctx context.Context, tenantID, idempotencyKey string, req CodeSigningKeylessRequest) (CodeSigningResponse, error)
}

// WithCodeSigning mounts the served code-signing surface (CLM-06/F50). When unset,
// /api/v1/code-signing/* fails closed with 501.
func WithCodeSigning(svc CodeSigningService) Option {
	return func(c *config) { c.codeSigning = svc }
}

// CodeSigningServed reports whether the served code-signing surface is wired.
func (a *API) CodeSigningServed() bool { return a.codeSigning != nil }

type CodeSigningRequest struct {
	Principal    string `json:"-"`
	KeyID        string `json:"key_id"`
	ArtifactType string `json:"artifact_type"`
	Digest       []byte `json:"digest"`
}

type CodeSigningKeylessRequest struct {
	Principal       string `json:"-"`
	ArtifactType    string `json:"artifact_type"`
	Digest          []byte `json:"digest"`
	IdentityMethod  string `json:"identity_method"`
	IdentityPayload []byte `json:"identity_payload"`
	FulcioSAN       string `json:"fulcio_san,omitempty"`
	FulcioIssuer    string `json:"fulcio_issuer,omitempty"`
}

type CodeSigningResponse struct {
	Algorithm               string `json:"algorithm"`
	KeyID                   string `json:"key_id,omitempty"`
	ArtifactType            string `json:"artifact_type"`
	Signature               []byte `json:"signature"`
	PublicKeyDER            []byte `json:"public_key_der"`
	FulcioSAN               string `json:"fulcio_san,omitempty"`
	FulcioIssuer            string `json:"fulcio_issuer,omitempty"`
	TransparencyDestination string `json:"transparency_destination,omitempty"`
}

func codeSigningDisabledProblem() *apiError {
	return errStatus(http.StatusNotImplemented, "code-signing service is not enabled")
}

func mapCodeSigningError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not permitted"), strings.Contains(msg, "attest:"):
		return errStatus(http.StatusForbidden, msg)
	case strings.Contains(msg, "required"), strings.Contains(msg, "empty"), strings.Contains(msg, "mismatch"):
		return errStatus(http.StatusBadRequest, msg)
	case strings.Contains(msg, "no key"), strings.Contains(msg, "unknown key"), strings.Contains(msg, "resolve key"):
		return errStatus(http.StatusNotFound, msg)
	default:
		return err
	}
}

//trstctl:mutation
func (a *API) signCodeArtifact(w http.ResponseWriter, r *http.Request) {
	if a.codeSigning == nil {
		a.writeError(w, codeSigningDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req CodeSigningRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := validateCodeSigningRequest(req); err != nil {
			return 0, nil, err
		}
		principal, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		req.Principal = principal
		res, err := a.codeSigning.SignCode(ctx, tenantID, idempotencyKey, req)
		if err != nil {
			return 0, nil, mapCodeSigningError(err)
		}
		return http.StatusOK, res, nil
	})
}

//trstctl:mutation
func (a *API) signCodeArtifactKeyless(w http.ResponseWriter, r *http.Request) {
	if a.codeSigning == nil {
		a.writeError(w, codeSigningDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req CodeSigningKeylessRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := validateCodeSigningKeylessRequest(req); err != nil {
			return 0, nil, err
		}
		principal, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		req.Principal = principal
		res, err := a.codeSigning.SignKeylessCode(ctx, tenantID, idempotencyKey, req)
		if err != nil {
			return 0, nil, mapCodeSigningError(err)
		}
		return http.StatusOK, res, nil
	})
}

func requestPrincipalSubject(ctx context.Context) (string, error) {
	p, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok || p.Subject == "" {
		return "", errStatus(http.StatusUnauthorized, "an authenticated principal is required")
	}
	return p.Subject, nil
}

func validateCodeSigningRequest(req CodeSigningRequest) error {
	if strings.TrimSpace(req.KeyID) == "" {
		return errStatus(http.StatusBadRequest, "key_id is required")
	}
	if strings.TrimSpace(req.ArtifactType) == "" {
		return errStatus(http.StatusBadRequest, "artifact_type is required")
	}
	if len(req.Digest) == 0 {
		return errStatus(http.StatusBadRequest, "digest is required")
	}
	return nil
}

func validateCodeSigningKeylessRequest(req CodeSigningKeylessRequest) error {
	if strings.TrimSpace(req.ArtifactType) == "" {
		return errStatus(http.StatusBadRequest, "artifact_type is required")
	}
	if len(req.Digest) == 0 {
		return errStatus(http.StatusBadRequest, "digest is required")
	}
	if strings.TrimSpace(req.IdentityMethod) == "" {
		return errStatus(http.StatusBadRequest, "identity_method is required")
	}
	if len(req.IdentityPayload) == 0 {
		return errStatus(http.StatusBadRequest, "identity_payload is required")
	}
	return nil
}
