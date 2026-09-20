// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const minimumEphemeralAPIKeyTTL = time.Second

const ephemeralAccessReviewDomain = "trstctl.api.f38-access-review.v1"

type normalizedEphemeralAPIKeyRequest struct {
	Subject    string
	Scopes     []string
	TTLSeconds int64
}

type ephemeralAPIKeyPreviewResponse struct {
	Capability              string   `json:"capability"`
	Operation               string   `json:"operation"`
	Ready                   bool     `json:"ready"`
	EffectFree              bool     `json:"effect_free"`
	Subject                 string   `json:"subject"`
	Scopes                  []string `json:"scopes"`
	RequestedTTLSeconds     int64    `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds     int64    `json:"effective_ttl_seconds"`
	MinimumTTLSeconds       int64    `json:"minimum_ttl_seconds"`
	MaximumTTLSeconds       int64    `json:"maximum_ttl_seconds"`
	RequiredPermission      string   `json:"required_permission"`
	RequestFingerprint      string   `json:"request_fingerprint"`
	Blockers                []string `json:"blockers"`
	PreviewWrites           []string `json:"preview_writes"`
	PreviewExternalEffects  []string `json:"preview_external_effects"`
	ExecuteWrites           []string `json:"execute_writes"`
	ExecuteExternalEffects  []string `json:"execute_external_effects"`
	RecoverySteps           []string `json:"recovery_steps"`
	VerificationSteps       []string `json:"verification_steps"`
	CLIArgv                 []string `json:"cli_argv"`
	TokenDataHandling       string   `json:"token_data_handling"`
	NativeSecretStoreNeeded bool     `json:"native_secret_store_needed"`
}

func normalizeEphemeralAPIKeyScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, errStatus(http.StatusBadRequest, "at least one scope is required")
	}
	seen := make(map[string]struct{}, len(scopes))
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return nil, errStatus(http.StatusBadRequest, "scopes must be non-empty")
		}
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func (a *API) normalizeEphemeralAPIKeyRequest(
	ctx context.Context,
	tenantID string,
	req ephemeralAPIKeyJSON,
) (normalizedEphemeralAPIKeyRequest, error) {
	principal, err := requestPrincipalSubject(ctx)
	if err != nil {
		return normalizedEphemeralAPIKeyRequest{}, err
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = principal
	}
	if subject == "" {
		return normalizedEphemeralAPIKeyRequest{}, errStatus(http.StatusBadRequest, "subject is required")
	}
	scopes, err := normalizeEphemeralAPIKeyScopes(req.Scopes)
	if err != nil {
		return normalizedEphemeralAPIKeyRequest{}, err
	}
	if err := a.validatePermissionScopes(scopes); err != nil {
		return normalizedEphemeralAPIKeyRequest{}, err
	}
	if err := a.authorizeTokenScopeGrant(ctx, tenantID, scopes); err != nil {
		return normalizedEphemeralAPIKeyRequest{}, err
	}
	if req.TTLSeconds < int64(minimumEphemeralAPIKeyTTL/time.Second) {
		return normalizedEphemeralAPIKeyRequest{}, errStatus(http.StatusBadRequest, "ttl_seconds must be at least 1")
	}
	if req.TTLSeconds > int64(ephemeralAPIKeyMaxTTL/time.Second) {
		return normalizedEphemeralAPIKeyRequest{}, errStatus(http.StatusUnprocessableEntity, "ttl_seconds must be 3600 or less")
	}
	return normalizedEphemeralAPIKeyRequest{Subject: subject, Scopes: scopes, TTLSeconds: req.TTLSeconds}, nil
}

func (a *API) ephemeralAPIKeyCommandMAC() func(domain, material []byte) ([]byte, error) {
	if a.commandMAC != nil {
		return a.commandMAC
	}
	// Compatibility for direct API compositions that already wire the native
	// secret backend. Production server composition wires commandMAC separately.
	if a.secrets != nil {
		return a.secrets.be.CommandMAC
	}
	return nil
}

func (a *API) ephemeralAPIKeyPreviewFingerprint(
	tenantID, principal string,
	req normalizedEphemeralAPIKeyRequest,
) (string, error) {
	macFn := a.ephemeralAPIKeyCommandMAC()
	if macFn == nil {
		return "", errors.New("api: server-keyed ephemeral API-key preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain     string   `json:"domain"`
		TenantID   string   `json:"tenant_id"`
		Principal  string   `json:"principal"`
		Operation  string   `json:"operation"`
		Subject    string   `json:"subject"`
		Scopes     []string `json:"scopes"`
		TTLSeconds int64    `json:"ttl_seconds"`
	}{
		Domain: ephemeralAccessReviewDomain, TenantID: tenantID, Principal: principal,
		Operation: "issue_ephemeral_api_key", Subject: req.Subject,
		Scopes: append([]string(nil), req.Scopes...), TTLSeconds: req.TTLSeconds,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := macFn([]byte(ephemeralAccessReviewDomain), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: ephemeral API-key preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

// previewEphemeralAPIKey proves the exact subject, scopes, caller attenuation,
// and lifetime without minting a bearer, appending an event, recording an
// idempotency result, or calling another process/system.
func (a *API) previewEphemeralAPIKey(w http.ResponseWriter, r *http.Request) {
	var req ephemeralAPIKeyJSON
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
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
	normalized, err := a.normalizeEphemeralAPIKeyRequest(r.Context(), tenantID, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	fingerprint, err := a.ephemeralAPIKeyPreviewFingerprint(tenantID, principal, normalized)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, ephemeralAPIKeyPreviewResponse{
		Capability: "F38", Operation: "issue_ephemeral_api_key", Ready: true, EffectFree: true,
		Subject: normalized.Subject, Scopes: append([]string(nil), normalized.Scopes...),
		RequestedTTLSeconds: req.TTLSeconds, EffectiveTTLSeconds: normalized.TTLSeconds,
		MinimumTTLSeconds:  int64(minimumEphemeralAPIKeyTTL / time.Second),
		MaximumTTLSeconds:  int64(ephemeralAPIKeyMaxTTL / time.Second),
		RequiredPermission: "access:write", RequestFingerprint: fingerprint,
		Blockers: []string{}, PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"append one tenant-scoped api_token.created event containing only the bearer hash",
			"project one expiring token metadata row",
			"record the protected idempotent result so an interrupted response can be recovered exactly",
		},
		ExecuteExternalEffects: []string{},
		RecoverySteps: []string{
			"Before issuance, cancel and leave the system unchanged.",
			"After an interrupted response, retry the identical request with the same Idempotency-Key to recover the original bearer without minting another key.",
			"Revoke the key from the API-token ledger if it is no longer needed; otherwise the bounded lease worker revokes it at expiry.",
		},
		VerificationSteps: []string{
			"Use the bearer against an API authorized by one of the reviewed scopes.",
			"Confirm the token metadata ledger shows the reviewed subject, scopes, and expiry without the bearer value.",
			"Revoke the key or wait for expiry, then confirm the same bearer receives an unauthorized response.",
		},
		CLIArgv:                 []string{"trstctl", "ephemeral", "api-keys", "preview", "-f", "ephemeral-api-key.json"},
		TokenDataHandling:       "Preview never creates or receives a bearer. Issuance returns it once; only its one-way hash enters the event log and token ledger. Never place the bearer in URLs, logs, screenshots, or browser storage.",
		NativeSecretStoreNeeded: false,
	})
}
