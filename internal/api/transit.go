// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/transit"
)

// TransitService is the served transit/EaaS backend. *transit.Service satisfies
// it; the API keeps this narrow so route handling never chooses providers at
// runtime.
type TransitService interface {
	CreateKey(ctx context.Context, tenantID, name string, kind transit.Kind) (transit.KeyInfo, error)
	Rotate(ctx context.Context, tenantID, name string) (transit.KeyInfo, error)
	Encrypt(ctx context.Context, tenantID, name string, plaintext, aad []byte) (string, error)
	Decrypt(ctx context.Context, tenantID, name, ciphertext string, aad []byte) ([]byte, error)
	Rewrap(ctx context.Context, tenantID, name, ciphertext string, aad []byte) (string, error)
	HMAC(ctx context.Context, tenantID, name string, data []byte) ([]byte, error)
	Sign(ctx context.Context, tenantID, name string, message []byte) ([]byte, []byte, error)
	Verify(ctx context.Context, tenantID string, message, sig, pubDER []byte) error
}

// WithTransit mounts the served transit/EaaS surface. When unset, the routes fail
// closed with 501 so OpenAPI/CLI parity can exist without silently enabling an
// unbacked crypto surface.
func WithTransit(svc TransitService) Option {
	return func(c *config) { c.transit = svc }
}

type transitKeyRequest struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type transitRotateRequest struct {
	Name string `json:"name"`
}

type transitKeyResponse struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Version int    `json:"version"`
}

type transitEncryptRequest struct {
	Key       string `json:"key"`
	Plaintext []byte `json:"plaintext"`
	AAD       []byte `json:"aad,omitempty"`
}

type transitCiphertextRequest struct {
	Key        string `json:"key"`
	Ciphertext string `json:"ciphertext"`
	AAD        []byte `json:"aad,omitempty"`
}

type transitCiphertextResponse struct {
	Ciphertext string `json:"ciphertext"`
	Version    int    `json:"version"`
}

type transitPlaintextResponse struct {
	Plaintext []byte `json:"plaintext"`
}

type transitDataRequest struct {
	Key  string `json:"key"`
	Data []byte `json:"data"`
}

type transitHMACResponse struct {
	HMAC []byte `json:"hmac"`
}

type transitSignRequest struct {
	Key     string `json:"key"`
	Message []byte `json:"message"`
}

type transitSignResponse struct {
	Signature []byte `json:"signature"`
	PublicDER []byte `json:"public_der"`
}

type transitVerifyRequest struct {
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
	PublicDER []byte `json:"public_der"`
}

type transitVerifyResponse struct {
	Valid bool `json:"valid"`
}

func transitDisabledProblem() *apiError {
	return errStatus(http.StatusNotImplemented, "transit encryption-as-a-service is not enabled")
}

func toTransitKeyResponse(info transit.KeyInfo) transitKeyResponse {
	return transitKeyResponse{Name: info.Name, Kind: string(info.Kind), Version: info.Version}
}

func mapTransitError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unknown key"):
		return errStatus(http.StatusNotFound, "no such transit key for this tenant")
	case strings.Contains(msg, "exists"):
		return errStatus(http.StatusConflict, msg)
	case strings.Contains(msg, "unknown kind"), strings.Contains(msg, "malformed ciphertext"), strings.Contains(msg, "bad version"), strings.Contains(msg, "bad ciphertext encoding"), strings.Contains(msg, "not an AEAD key"), strings.Contains(msg, "not an HMAC key"), strings.Contains(msg, "not a signing key"):
		return errStatus(http.StatusBadRequest, msg)
	default:
		return err
	}
}

//trstctl:mutation
func (a *API) createTransitKey(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req transitKeyRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name is required")
		}
		kind := transit.Kind(strings.TrimSpace(req.Kind))
		if kind == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "kind is required")
		}
		info, err := a.transit.CreateKey(ctx, tenantID, name, kind)
		if err != nil {
			return 0, nil, mapTransitError(err)
		}
		return http.StatusCreated, toTransitKeyResponse(info), nil
	})
}

//trstctl:mutation
func (a *API) rotateTransitKey(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req transitRotateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name is required")
		}
		info, err := a.transit.Rotate(ctx, tenantID, name)
		if err != nil {
			return 0, nil, mapTransitError(err)
		}
		return http.StatusOK, toTransitKeyResponse(info), nil
	})
}

//trstctl:mutation
func (a *API) encryptTransit(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req transitEncryptRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		defer secret.Wipe(req.Plaintext)
		defer secret.Wipe(req.AAD)
		key := strings.TrimSpace(req.Key)
		if key == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "key is required")
		}
		if len(req.Plaintext) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "plaintext is required")
		}
		ct, err := a.transit.Encrypt(ctx, tenantID, key, req.Plaintext, req.AAD)
		if err != nil {
			return 0, nil, mapTransitError(err)
		}
		version, err := transit.CiphertextVersion(ct)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, transitCiphertextResponse{Ciphertext: ct, Version: version}, nil
	})
}

func (a *API) decryptTransit(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req transitCiphertextRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer secret.Wipe(req.AAD)
	key := strings.TrimSpace(req.Key)
	if key == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "key is required"))
		return
	}
	if strings.TrimSpace(req.Ciphertext) == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "ciphertext is required"))
		return
	}
	plaintext, err := a.transit.Decrypt(r.Context(), tenantID, key, req.Ciphertext, req.AAD)
	if err != nil {
		a.writeError(w, mapTransitError(err))
		return
	}
	defer secret.Wipe(plaintext)
	a.writeTransitPlaintext(w, plaintext)
}

//trstctl:mutation
func (a *API) rewrapTransit(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req transitCiphertextRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		defer secret.Wipe(req.AAD)
		key := strings.TrimSpace(req.Key)
		if key == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "key is required")
		}
		if strings.TrimSpace(req.Ciphertext) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "ciphertext is required")
		}
		ct, err := a.transit.Rewrap(ctx, tenantID, key, req.Ciphertext, req.AAD)
		if err != nil {
			return 0, nil, mapTransitError(err)
		}
		version, err := transit.CiphertextVersion(ct)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, transitCiphertextResponse{Ciphertext: ct, Version: version}, nil
	})
}

//trstctl:mutation
func (a *API) hmacTransit(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req transitDataRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		defer secret.Wipe(req.Data)
		key := strings.TrimSpace(req.Key)
		if key == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "key is required")
		}
		if len(req.Data) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "data is required")
		}
		mac, err := a.transit.HMAC(ctx, tenantID, key, req.Data)
		if err != nil {
			return 0, nil, mapTransitError(err)
		}
		return http.StatusOK, transitHMACResponse{HMAC: mac}, nil
	})
}

//trstctl:mutation
func (a *API) signTransit(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req transitSignRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		defer secret.Wipe(req.Message)
		key := strings.TrimSpace(req.Key)
		if key == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "key is required")
		}
		if len(req.Message) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "message is required")
		}
		sig, pub, err := a.transit.Sign(ctx, tenantID, key, req.Message)
		if err != nil {
			return 0, nil, mapTransitError(err)
		}
		return http.StatusOK, transitSignResponse{Signature: sig, PublicDER: pub}, nil
	})
}

func (a *API) verifyTransit(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req transitVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer secret.Wipe(req.Message)
	defer secret.Wipe(req.Signature)
	defer secret.Wipe(req.PublicDER)
	if len(req.Message) == 0 || len(req.Signature) == 0 || len(req.PublicDER) == 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "message, signature, and public_der are required"))
		return
	}
	valid := true
	if err := a.transit.Verify(r.Context(), tenantID, req.Message, req.Signature, req.PublicDER); err != nil {
		valid = false
	}
	a.writeJSON(w, http.StatusOK, transitVerifyResponse{Valid: valid})
}

func (a *API) writeTransitPlaintext(w http.ResponseWriter, plaintext []byte) {
	body, err := json.Marshal(transitPlaintextResponse{Plaintext: plaintext})
	if err != nil {
		a.writeError(w, errors.New("failed to encode transit plaintext response"))
		return
	}
	defer secret.Wipe(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
