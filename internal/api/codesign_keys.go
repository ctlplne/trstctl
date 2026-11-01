// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Code-signing key certificates (P9): the certificate chain that names a
// managed code-signing key, for stock signing tools, and a certificate
// request signed by the key inside the signer.

// ErrCodeSigningKeyNotFound and ErrNoCodeSigningKeyCertificate are the
// service's answers for an unknown key and a key without a configured chain.
var (
	ErrCodeSigningKeyNotFound      = errors.New("codesign: no such key")
	ErrNoCodeSigningKeyCertificate = errors.New("codesign: no certificate chain is configured for this key")
)

// CodeSigningKeyService is implemented by a code-signing service that serves
// key certificates; a service without it answers like a disabled service.
type CodeSigningKeyService interface {
	KeyCertificate(ctx context.Context, tenantID, keyID string) (CodeSigningKeyCertificate, error)
	KeyCSR(ctx context.Context, tenantID, principal, keyID string, req CodeSigningKeyCSRRequest) ([]byte, error)
}

// CodeSigningKeyCertificate is the certificate chain configured for a key.
type CodeSigningKeyCertificate struct {
	KeyID           string    `json:"key_id"`
	Algorithm       string    `json:"algorithm"`
	PublicKeyDER    []byte    `json:"public_key_der"`
	ChainPEM        string    `json:"chain_pem"`
	LeafFingerprint string    `json:"leaf_fingerprint"`
	NotAfter        time.Time `json:"not_after"`
	CodeSigningEKU  bool      `json:"code_signing_eku"`
}

// CodeSigningKeyCSRRequest names the certificate subject.
type CodeSigningKeyCSRRequest struct {
	CommonName string `json:"common_name"`
}

// CodeSigningKeyCSR is a certificate request signed by the key.
type CodeSigningKeyCSR struct {
	KeyID  string `json:"key_id"`
	CSRPEM string `json:"csr_pem"`
}

func (a *API) codeSigningKeys() (CodeSigningKeyService, bool) {
	svc, ok := a.codeSigning.(CodeSigningKeyService)
	return svc, ok && a.codeSigning != nil
}

func (a *API) getCodeSigningKeyCertificate(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.codeSigningKeys()
	if !ok {
		a.writeError(w, codeSigningDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	cert, err := svc.KeyCertificate(r.Context(), tenantID, strings.TrimSpace(r.PathValue("key_id")))
	switch {
	case errors.Is(err, ErrCodeSigningKeyNotFound):
		a.writeError(w, errStatus(http.StatusNotFound, "no code-signing key with this id"))
	case errors.Is(err, ErrNoCodeSigningKeyCertificate):
		a.writeError(w, errStatus(http.StatusNotFound, "no certificate chain is configured for this code-signing key"))
	case err != nil:
		a.writeError(w, err)
	default:
		a.writeJSON(w, http.StatusOK, cert)
	}
}

func (a *API) createCodeSigningKeyCSR(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.codeSigningKeys()
	if !ok {
		a.writeError(w, codeSigningDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req CodeSigningKeyCSRRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.CommonName = strings.TrimSpace(req.CommonName)
	if req.CommonName == "" || len(req.CommonName) > 64 {
		a.writeError(w, errStatus(http.StatusBadRequest, "common_name is required (at most 64 characters)"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	keyID := strings.TrimSpace(r.PathValue("key_id"))
	// Signing a certificate request is a use of the key: the service records it
	// before the request is returned, and a replayed Idempotency-Key returns the
	// same request without signing again.
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		csrPEM, err := svc.KeyCSR(ctx, tenantID, principal, keyID, req)
		if errors.Is(err, ErrCodeSigningKeyNotFound) {
			return 0, nil, errStatus(http.StatusNotFound, "no code-signing key with this id")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, CodeSigningKeyCSR{KeyID: keyID, CSRPEM: string(csrPEM)}, nil
	})
}
