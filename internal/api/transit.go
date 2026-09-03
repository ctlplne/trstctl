// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/transit"
)

// TransitService is the served transit/EaaS backend. *transit.Service satisfies
// it; the API keeps this narrow so route handling never chooses providers at
// runtime.
type TransitService interface {
	ListKeys(ctx context.Context, tenantID string) ([]transit.KeyInfo, error)
	ListKeyVersions(ctx context.Context, tenantID, name string) (transit.Kind, []transit.KeyVersionInfo, error)
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

// TransitRuntimePosture is secret-free, in-memory truth supplied by the
// composition root. It contains no keyring path, certificate path, key bytes,
// client identity, or tenant identifier.
type TransitRuntimePosture struct {
	Served                bool
	PersistenceConfigured bool
	SealedStateFound      bool
	KMIPConfigured        bool
	KMIPServed            bool
	KMIPListening         bool
	KMIPTenantBound       bool
	KMIPAddress           string
}

// TransitPostureProvider reads only assembled runtime state for the authenticated
// tenant. It must not read storage, open a keyring, contact KMIP, or mutate state.
type TransitPostureProvider func(context.Context, string) TransitRuntimePosture

// WithTransitPosture attaches the effect-free recovery and KMIP posture reader.
func WithTransitPosture(provider TransitPostureProvider) Option {
	return func(c *config) { c.transitPosture = provider }
}

type transitKeyVersionResponse struct {
	Version int  `json:"version"`
	Current bool `json:"current"`
}

type transitKeyVersionListResponse struct {
	Name     string                      `json:"name"`
	Kind     string                      `json:"kind"`
	Versions []transitKeyVersionResponse `json:"versions"`
}

// TransitServicePosture explains whether keys survive restart and how restore
// works. Restore is intentionally automatic and deployment-custodied; there is
// no browser upload surface for key material.
type TransitServicePosture struct {
	Served                bool   `json:"served"`
	PersistenceConfigured bool   `json:"persistence_configured"`
	RestoreState          string `json:"restore_state"`
	RecoveryReady         bool   `json:"recovery_ready"`
	Detail                string `json:"detail"`
	Recovery              string `json:"recovery,omitempty"`
}

// KMIPPosture is an honest appliance profile and live listener state. It omits
// certificate paths and client identity material.
type KMIPPosture struct {
	State       string   `json:"state"`
	Configured  bool     `json:"configured"`
	Served      bool     `json:"served"`
	Listening   bool     `json:"listening"`
	TenantBound bool     `json:"tenant_bound"`
	Address     string   `json:"address,omitempty"`
	Transport   string   `json:"transport"`
	Profile     string   `json:"profile"`
	Objects     []string `json:"objects"`
	Operations  []string `json:"operations"`
	Detail      string   `json:"detail"`
	Recovery    string   `json:"recovery,omitempty"`
}

// TransitPosture is effect-free operational evidence for the console, API, and
// CLI. It does not claim wire interoperability; qualification still uses a stock
// KMIP client against the mTLS listener.
type TransitPosture struct {
	CheckedAt     string                `json:"checked_at"`
	EffectFree    bool                  `json:"effect_free"`
	Transit       TransitServicePosture `json:"transit"`
	KMIP          KMIPPosture           `json:"kmip"`
	RecoverySteps []string              `json:"recovery_steps"`
	Proof         []string              `json:"proof"`
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

type transitKeyListResponse struct {
	Items []transitKeyResponse `json:"items"`
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

func (a *API) listTransitKeys(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	infos, err := a.transit.ListKeys(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, mapTransitError(err))
		return
	}
	items := make([]transitKeyResponse, 0, len(infos))
	for _, info := range infos {
		items = append(items, toTransitKeyResponse(info))
	}
	a.writeJSON(w, http.StatusOK, transitKeyListResponse{Items: items})
}

func (a *API) listTransitKeyVersions(w http.ResponseWriter, r *http.Request) {
	if a.transit == nil {
		a.writeError(w, transitDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "name is required"))
		return
	}
	kind, versions, err := a.transit.ListKeyVersions(r.Context(), tenantID, name)
	if err != nil {
		a.writeError(w, mapTransitError(err))
		return
	}
	items := make([]transitKeyVersionResponse, 0, len(versions))
	for _, version := range versions {
		items = append(items, transitKeyVersionResponse{Version: version.Version, Current: version.Current})
	}
	a.writeJSON(w, http.StatusOK, transitKeyVersionListResponse{Name: name, Kind: string(kind), Versions: items})
}

func (a *API) getTransitPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	posture := TransitRuntimePosture{Served: a.transit != nil}
	if a.transitPosture != nil {
		posture = a.transitPosture(r.Context(), tenantID)
	}
	a.writeJSON(w, http.StatusOK, buildTransitPosture(posture))
}

func buildTransitPosture(runtime TransitRuntimePosture) TransitPosture {
	restoreState := "volatile"
	transitDetail := "Transit keys exist only in this process and will not survive a restart."
	transitRecovery := "Configure a protected Transit keyring directory and deployment KEK, then restart before creating production keys."
	if runtime.PersistenceConfigured {
		restoreState = "empty"
		transitDetail = "The sealed keyring is checkpointed after every create or rotate and restored automatically during startup. No key material is uploaded through the browser."
		transitRecovery = ""
		if runtime.SealedStateFound {
			restoreState = "restored"
			transitDetail = "The running service restored its sealed keyring during startup. Older AEAD versions remain available for decryption; signature verification uses the public DER returned when the signature was created."
		}
	}

	kmip := KMIPPosture{
		State: "not_configured", Configured: runtime.KMIPConfigured, Served: runtime.KMIPServed,
		Listening: runtime.KMIPListening, TenantBound: runtime.KMIPTenantBound,
		Transport: "mTLS", Profile: "KMIP 1.x AES-256 SymmetricKey appliance profile",
		Objects:    []string{"AES-256 SymmetricKey"},
		Operations: []string{"Create", "Get", "Locate", "Revoke", "Destroy"},
		Detail:     "KMIP is not configured for this tenant. Transit API operations remain independent.",
		Recovery:   "Enable the licensed KMIP listener, bind it to this tenant, configure server and client trust, and restart the reviewed candidate.",
	}
	if runtime.KMIPConfigured && runtime.KMIPServed && runtime.KMIPTenantBound {
		kmip.State = "starting"
		kmip.Address = runtime.KMIPAddress
		kmip.Detail = "The tenant-bound KMIP runtime is assembled but the listener is not yet accepting mTLS connections."
		kmip.Recovery = "Check the configured listen address and startup logs, repair the bind failure, and recheck before pointing an appliance at it."
		if runtime.KMIPListening {
			kmip.State = "listening"
			kmip.Detail = "The tenant-bound KMIP listener is accepting mutually authenticated connections. Prove interoperability with a stock KMIP client."
			kmip.Recovery = ""
		}
	}

	return TransitPosture{
		CheckedAt: time.Now().UTC().Format(time.RFC3339), EffectFree: true,
		Transit: TransitServicePosture{
			Served: runtime.Served, PersistenceConfigured: runtime.PersistenceConfigured,
			RestoreState: restoreState, RecoveryReady: runtime.Served && runtime.PersistenceConfigured,
			Detail: transitDetail, Recovery: transitRecovery,
		},
		KMIP: kmip,
		RecoverySteps: []string{
			"Keep the original ciphertext, signature, public key, and key name. API and CLI callers must also keep the request Idempotency-Key; do not create a replacement key after an uncertain response.",
			"Refresh this posture and the key-version history. If startup restore is blocked, repair the original KEK or sealed-keyring mount and restart; never delete or overwrite the sealed file.",
			"Retry the unchanged operation only after the service is healthy, then prove the result with decrypt, signature verification, version metadata, and the filtered immutable audit receipt.",
		},
		Proof: []string{
			"This request reads only secret-free in-memory composition and listener state for the authenticated tenant.",
			"It does not read or rewrite the sealed keyring, call a cryptographic operation, contact KMIP, append an event, or enqueue an outbox message.",
			"Key bytes, certificate paths, client identities, request payloads, and tenant identifiers are never returned.",
		},
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
