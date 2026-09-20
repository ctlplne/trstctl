// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// CodeSigningService is the served code-signing backend. The API owns transport,
// authz, and idempotency; the composition root supplies the real signer/keyless
// implementation plus the Rekor/Fulcio outbox wiring.
type CodeSigningService interface {
	SignCode(ctx context.Context, tenantID, idempotencyKey string, req CodeSigningRequest) (CodeSigningResponse, error)
	SignKeylessCode(ctx context.Context, tenantID, idempotencyKey string, req CodeSigningKeylessRequest) (CodeSigningResponse, error)
}

// CodeSigningPreviewService exposes only non-secret, in-memory configuration
// posture. A preview must never resolve a live signer, attest an identity, append
// an event, reserve idempotency, enqueue work, or contact Rekor/Fulcio.
type CodeSigningPreviewService interface {
	PreviewCodeSigning(ctx context.Context, tenantID, mode, keyID, identityMethod string) (CodeSigningPreviewStatus, error)
}

type CodeSigningPreviewStatus struct {
	Ready                    bool     `json:"ready"`
	Blockers                 []string `json:"blockers"`
	ConfigurationFingerprint string   `json:"configuration_fingerprint"`
	SigningAlgorithm         string   `json:"signing_algorithm,omitempty"`
	TransparencyDestination  string   `json:"transparency_destination,omitempty"`
	ApprovalRequired         bool     `json:"approval_required"`
}

// WithCodeSigning mounts the served code-signing surface (CLM-06/F50). When unset,
// /api/v1/code-signing/* fails closed with 501.
func WithCodeSigning(svc CodeSigningService) Option {
	return func(c *config) { c.codeSigning = svc }
}

// CodeSigningServed reports whether the served code-signing surface is wired.
func (a *API) CodeSigningServed() bool { return a.codeSigning != nil }

type CodeSigningRequest struct {
	Principal          string `json:"-"`
	KeyID              string `json:"key_id"`
	ArtifactType       string `json:"artifact_type"`
	Digest             []byte `json:"digest"`
	PreviewFingerprint string `json:"preview_fingerprint,omitempty"`
}

type CodeSigningKeylessRequest struct {
	Principal          string `json:"-"`
	ArtifactType       string `json:"artifact_type"`
	Digest             []byte `json:"digest"`
	IdentityMethod     string `json:"identity_method"`
	IdentityPayload    []byte `json:"identity_payload"`
	FulcioSAN          string `json:"fulcio_san,omitempty"`
	FulcioIssuer       string `json:"fulcio_issuer,omitempty"`
	PreviewFingerprint string `json:"preview_fingerprint,omitempty"`
}

type CodeSigningPreview struct {
	Capability               string   `json:"capability"`
	Operation                string   `json:"operation"`
	Mode                     string   `json:"mode"`
	Ready                    bool     `json:"ready"`
	EffectFree               bool     `json:"effect_free"`
	ArtifactType             string   `json:"artifact_type"`
	DigestSHA256             string   `json:"digest_sha256"`
	KeyID                    string   `json:"key_id,omitempty"`
	IdentityMethod           string   `json:"identity_method,omitempty"`
	RequiredPermission       string   `json:"required_permission"`
	RequestFingerprint       string   `json:"request_fingerprint"`
	ConfigurationFingerprint string   `json:"configuration_fingerprint"`
	SigningAlgorithm         string   `json:"signing_algorithm,omitempty"`
	TransparencyDestination  string   `json:"transparency_destination,omitempty"`
	ApprovalRequired         bool     `json:"approval_required"`
	Blockers                 []string `json:"blockers"`
	PreviewReads             []string `json:"preview_reads"`
	PreviewWrites            []string `json:"preview_writes"`
	PreviewExternalEffects   []string `json:"preview_external_effects"`
	ExecuteWrites            []string `json:"execute_writes"`
	ExecuteExternalEffects   []string `json:"execute_external_effects"`
	RecoverySteps            []string `json:"recovery_steps"`
	VerificationSteps        []string `json:"verification_steps"`
	CLIArgv                  []string `json:"cli_argv"`
	DataHandling             string   `json:"secret_data_handling"`
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
	case strings.Contains(msg, "idempotency key was already used"):
		return errStatus(http.StatusConflict, msg)
	case strings.Contains(msg, "not permitted"), strings.Contains(msg, "attest:"),
		strings.Contains(msg, "policy_denied"), strings.Contains(msg, "approval_required:codesign:"),
		strings.Contains(msg, "identity_attestation_failed"):
		return errStatus(http.StatusForbidden, msg)
	case strings.Contains(msg, "required"), strings.Contains(msg, "empty"), strings.Contains(msg, "mismatch"), strings.Contains(msg, "idempotency key"):
		return errStatus(http.StatusBadRequest, msg)
	case strings.Contains(msg, "no key"), strings.Contains(msg, "unknown key"), strings.Contains(msg, "resolve key"):
		return errStatus(http.StatusNotFound, msg)
	default:
		return err
	}
}

const codeSigningPreviewDomain = "trstctl.api.code-signing-preview.f50.v1"

func normalizeCodeSigningRequest(req *CodeSigningRequest) {
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.ArtifactType = strings.TrimSpace(req.ArtifactType)
	req.PreviewFingerprint = strings.TrimSpace(req.PreviewFingerprint)
}

func normalizeCodeSigningKeylessRequest(req *CodeSigningKeylessRequest) {
	req.ArtifactType = strings.TrimSpace(req.ArtifactType)
	req.IdentityMethod = strings.TrimSpace(req.IdentityMethod)
	req.FulcioSAN = strings.TrimSpace(req.FulcioSAN)
	req.FulcioIssuer = strings.TrimSpace(req.FulcioIssuer)
	req.PreviewFingerprint = strings.TrimSpace(req.PreviewFingerprint)
}

func (a *API) codeSigningPreviewStatus(ctx context.Context, tenantID, mode, keyID, identityMethod string) (CodeSigningPreviewStatus, error) {
	previewer, ok := a.codeSigning.(CodeSigningPreviewService)
	if !ok {
		return CodeSigningPreviewStatus{
			Blockers: []string{"the code-signing runtime does not expose effect-free configuration posture"},
		}, nil
	}
	status, err := previewer.PreviewCodeSigning(ctx, tenantID, mode, keyID, identityMethod)
	if err != nil {
		return CodeSigningPreviewStatus{}, err
	}
	if status.Blockers == nil {
		status.Blockers = []string{}
	}
	status.Ready = len(status.Blockers) == 0 && status.Ready
	if status.Ready && strings.TrimSpace(status.ConfigurationFingerprint) == "" {
		return CodeSigningPreviewStatus{}, errors.New("api: code-signing preview configuration evidence is missing")
	}
	return status, nil
}

func (a *API) codeSigningPreviewFingerprint(tenantID, principal, mode string, req any, configurationFingerprint string) (string, error) {
	if a.commandMAC == nil {
		return "", errors.New("api: server-keyed code-signing preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain                   string `json:"domain"`
		TenantID                 string `json:"tenant_id"`
		Principal                string `json:"principal"`
		Mode                     string `json:"mode"`
		Request                  any    `json:"request"`
		ConfigurationFingerprint string `json:"configuration_fingerprint"`
	}{
		Domain: codeSigningPreviewDomain, TenantID: tenantID, Principal: principal,
		Mode: mode, Request: req, ConfigurationFingerprint: configurationFingerprint,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := a.commandMAC([]byte(codeSigningPreviewDomain), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: code-signing preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

func codeSigningPreviewRequest(req CodeSigningRequest) CodeSigningRequest {
	req.Principal = ""
	req.PreviewFingerprint = ""
	return req
}

func codeSigningKeylessPreviewRequest(req CodeSigningKeylessRequest) CodeSigningKeylessRequest {
	req.Principal = ""
	req.PreviewFingerprint = ""
	return req
}

func (a *API) previewCodeArtifact(w http.ResponseWriter, r *http.Request) {
	if a.codeSigning == nil {
		a.writeError(w, codeSigningDisabledProblem())
		return
	}
	var req CodeSigningRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer secret.Wipe(req.Digest)
	normalizeCodeSigningRequest(&req)
	if err := validateCodeSigningRequest(req); err != nil {
		a.writeError(w, err)
		return
	}
	a.previewCodeSigning(w, r, "key", req.KeyID, "", req.ArtifactType, req.Digest, codeSigningPreviewRequest(req))
}

func (a *API) previewCodeArtifactKeyless(w http.ResponseWriter, r *http.Request) {
	if a.codeSigning == nil {
		a.writeError(w, codeSigningDisabledProblem())
		return
	}
	var req CodeSigningKeylessRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer secret.Wipe(req.Digest)
	defer secret.Wipe(req.IdentityPayload)
	normalizeCodeSigningKeylessRequest(&req)
	if err := validateCodeSigningKeylessRequest(req); err != nil {
		a.writeError(w, err)
		return
	}
	a.previewCodeSigning(w, r, "keyless", "", req.IdentityMethod, req.ArtifactType, req.Digest, codeSigningKeylessPreviewRequest(req))
}

func (a *API) previewCodeSigning(w http.ResponseWriter, r *http.Request, mode, keyID, identityMethod, artifactType string, digest []byte, request any) {
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
	status, err := a.codeSigningPreviewStatus(r.Context(), tenantID, mode, keyID, identityMethod)
	if err != nil {
		a.writeError(w, err)
		return
	}
	fingerprint, err := a.codeSigningPreviewFingerprint(tenantID, principal, mode, request, status.ConfigurationFingerprint)
	if err != nil {
		a.writeError(w, err)
		return
	}
	operation := "sign_code_artifact"
	cli := []string{"trstctl-cli", "code-signing", "preview", "-f", "code-signing.json"}
	dataHandling := "Preview handles only the SHA-256 artifact digest and signer metadata; artifact bytes and private keys never enter the API process."
	if mode == "keyless" {
		operation = "sign_code_artifact_keyless"
		cli = []string{"trstctl-cli", "code-signing", "keyless-preview", "-f", "code-signing.json"}
		dataHandling = "The identity proof is used only in wipeable request and keyed-MAC buffers during preview. It is never echoed, logged, persisted, attested, sent to Fulcio, or sent to Rekor until reviewed execution. Artifact bytes and private keys never enter the API process."
	}
	a.writeJSON(w, http.StatusOK, CodeSigningPreview{
		Capability: "F50", Operation: operation, Mode: mode, Ready: status.Ready,
		EffectFree: true, ArtifactType: artifactType, DigestSHA256: hex.EncodeToString(digest),
		KeyID: keyID, IdentityMethod: identityMethod, RequiredPermission: "keys:write",
		RequestFingerprint: fingerprint, ConfigurationFingerprint: status.ConfigurationFingerprint,
		SigningAlgorithm: status.SigningAlgorithm, TransparencyDestination: status.TransparencyDestination,
		ApprovalRequired: status.ApprovalRequired, Blockers: status.Blockers,
		PreviewReads: []string{
			"read tenant-scoped in-memory signer and identity-provider metadata",
			"read approval and transparency destination configuration without opening a signer",
		},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"append one immutable codesign.commanded event",
			"project one tenant-scoped durable signing operation",
			"commit sealed signer and transparency outbox intents before delivery",
		},
		ExecuteExternalEffects: []string{
			"the bounded worker asks the isolated signer to sign this exact SHA-256 digest",
			"after signing, the bounded transparency worker publishes and verifies the exact Rekor entry",
		},
		RecoverySteps: []string{
			"Before execution, go back or leave the page and nothing changes.",
			"After an ambiguous response, retry the identical reviewed request with the same Idempotency-Key.",
			"If this plan becomes stale, request a new preview; never force it.",
			"Use Recent signing outcomes to inspect a durable failure before retrying or changing the command.",
		},
		VerificationSteps: []string{
			"Verify the returned signature against this exact SHA-256 digest and returned public key.",
			"Confirm the durable operation reaches completed and transparency reaches verified.",
			"Confirm immutable events and audit evidence contain no artifact, identity token, or private key.",
		},
		CLIArgv: cli, DataHandling: dataHandling,
	})
}

//trstctl:mutation
func (a *API) signCodeArtifact(w http.ResponseWriter, r *http.Request) {
	if a.codeSigning == nil {
		a.writeError(w, codeSigningDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req CodeSigningRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer secret.Wipe(req.Digest)
	normalizeCodeSigningRequest(&req)
	if err := validateCodeSigningRequest(req); err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	req.Principal = principal
	binding, err := codeSigningRequestBinding("key", principal, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if req.PreviewFingerprint != "" {
			status, statusErr := a.codeSigningPreviewStatus(ctx, tenantID, "key", req.KeyID, "")
			if statusErr != nil {
				return 0, nil, statusErr
			}
			if !status.Ready {
				return 0, nil, errStatus(http.StatusConflict, "reviewed code-signing plan is no longer ready")
			}
			want, fingerprintErr := a.codeSigningPreviewFingerprint(tenantID, principal, "key", codeSigningPreviewRequest(req), status.ConfigurationFingerprint)
			if fingerprintErr != nil {
				return 0, nil, fingerprintErr
			}
			if !crypto.ConstantTimeEqual([]byte(req.PreviewFingerprint), []byte(want)) {
				return 0, nil, errStatus(http.StatusConflict, "reviewed code-signing plan is stale or does not match this caller, digest, signer, or runtime configuration")
			}
		}
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
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req CodeSigningKeylessRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer secret.Wipe(req.Digest)
	defer secret.Wipe(req.IdentityPayload)
	normalizeCodeSigningKeylessRequest(&req)
	if err := validateCodeSigningKeylessRequest(req); err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	req.Principal = principal
	binding, err := codeSigningRequestBinding("keyless", principal, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if req.PreviewFingerprint != "" {
			status, statusErr := a.codeSigningPreviewStatus(ctx, tenantID, "keyless", "", req.IdentityMethod)
			if statusErr != nil {
				return 0, nil, statusErr
			}
			if !status.Ready {
				return 0, nil, errStatus(http.StatusConflict, "reviewed keyless code-signing plan is no longer ready")
			}
			want, fingerprintErr := a.codeSigningPreviewFingerprint(tenantID, principal, "keyless", codeSigningKeylessPreviewRequest(req), status.ConfigurationFingerprint)
			if fingerprintErr != nil {
				return 0, nil, fingerprintErr
			}
			if !crypto.ConstantTimeEqual([]byte(req.PreviewFingerprint), []byte(want)) {
				return 0, nil, errStatus(http.StatusConflict, "reviewed keyless code-signing plan is stale or does not match this caller, digest, identity proof, or runtime configuration")
			}
		}
		res, err := a.codeSigning.SignKeylessCode(ctx, tenantID, idempotencyKey, req)
		if err != nil {
			return 0, nil, mapCodeSigningError(err)
		}
		return http.StatusOK, res, nil
	})
}

func codeSigningRequestBinding(operation, principal string, request any) (string, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	var material []byte
	material = append(material, operation...)
	material = append(material, 0)
	material = append(material, principal...)
	material = append(material, 0)
	material = append(material, encoded...)
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
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
	if len(req.Digest) != 32 {
		return errStatus(http.StatusBadRequest, "digest must be exactly 32 bytes (SHA-256)")
	}
	return nil
}

func validateCodeSigningKeylessRequest(req CodeSigningKeylessRequest) error {
	if strings.TrimSpace(req.ArtifactType) == "" {
		return errStatus(http.StatusBadRequest, "artifact_type is required")
	}
	if len(req.Digest) != 32 {
		return errStatus(http.StatusBadRequest, "digest must be exactly 32 bytes (SHA-256)")
	}
	if strings.TrimSpace(req.IdentityMethod) == "" {
		return errStatus(http.StatusBadRequest, "identity_method is required")
	}
	if len(req.IdentityPayload) == 0 {
		return errStatus(http.StatusBadRequest, "identity_payload is required")
	}
	return nil
}
