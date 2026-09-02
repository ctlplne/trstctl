// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	defaultSecretShareTTL = 24 * time.Hour
	minimumSecretShareTTL = 60 * time.Second
	maximumSecretShareTTL = 7 * 24 * time.Hour
)

type secretSharePreviewRequest struct {
	TTLSeconds int `json:"ttl_seconds"`
}

type secretSharePreviewResponse struct {
	Capability                        string   `json:"capability"`
	Operation                         string   `json:"operation"`
	Ready                             bool     `json:"ready"`
	EffectFree                        bool     `json:"effect_free"`
	RequestedTTLSeconds               int      `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds               int      `json:"effective_ttl_seconds"`
	RequiredPermission                string   `json:"required_permission"`
	RequestFingerprint                string   `json:"request_fingerprint"`
	SensitiveChangeApprovalConfigured bool     `json:"sensitive_change_approval_configured"`
	Blockers                          []string `json:"blockers"`
	PreviewWrites                     []string `json:"preview_writes"`
	PreviewExternalEffects            []string `json:"preview_external_effects"`
	ExecuteWrites                     []string `json:"execute_writes"`
	ExecuteExternalEffects            []string `json:"execute_external_effects"`
	RecoverySteps                     []string `json:"recovery_steps"`
	VerificationSteps                 []string `json:"verification_steps"`
	CLIArgv                           []string `json:"cli_argv"`
	DataHandling                      string   `json:"secret_data_handling"`
}

func normalizeSecretShareTTL(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return defaultSecretShareTTL, nil
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl < minimumSecretShareTTL || ttl > maximumSecretShareTTL {
		return 0, fmt.Errorf("ttl_seconds must be between %d and %d", int(minimumSecretShareTTL.Seconds()), int(maximumSecretShareTTL.Seconds()))
	}
	return ttl, nil
}

func (a *API) secretSharePreviewFingerprint(tenantID, principal string, ttl time.Duration) (string, error) {
	if a.secrets == nil || a.secrets.be.CommandMAC == nil {
		return "", errors.New("api: server-keyed one-time-share preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain              string `json:"domain"`
		TenantID            string `json:"tenant_id"`
		Principal           string `json:"principal"`
		Operation           string `json:"operation"`
		EffectiveTTLSeconds int64  `json:"effective_ttl_seconds"`
	}{
		Domain: "trstctl.api.secret-share-preview.f60.v1", TenantID: tenantID,
		Principal: principal, Operation: "create_one_time_share", EffectiveTTLSeconds: int64(ttl.Seconds()),
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := a.secrets.be.CommandMAC([]byte("trstctl.api.secret-share-preview.f60.v1"), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: one-time-share preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

// previewShare validates one exact one-time-share lifetime without receiving the
// value and without writing state, emitting events, recording idempotency, calling
// the signer, enqueueing outbox work, or contacting another system.
func (a *API) previewShare(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	var req secretSharePreviewRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	ttl, err := normalizeSecretShareTTL(req.TTLSeconds)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
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
	fingerprint, err := a.secretSharePreviewFingerprint(tenantID, principal, ttl)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, secretSharePreviewResponse{
		Capability: "F60", Operation: "create_one_time_share", Ready: true, EffectFree: true,
		RequestedTTLSeconds: req.TTLSeconds, EffectiveTTLSeconds: int(ttl.Seconds()),
		RequiredPermission: "secrets:write", RequestFingerprint: fingerprint,
		SensitiveChangeApprovalConfigured: a.approvals != nil,
		Blockers:                          []string{}, PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"store one tenant-scoped sealed value with only the bearer-token hash",
			"append plaintext-free share-created audit evidence",
			"record the idempotent response so an ambiguous request can be retried safely",
		},
		ExecuteExternalEffects: []string{},
		RecoverySteps: []string{
			"Before execution, cancel and leave the system unchanged.",
			"After an ambiguous response, retry the identical request with the same Idempotency-Key to recover the original token without creating another share.",
			"After the token is delivered, redeem it once or let its short lifetime expire; a second redeem fails closed.",
		},
		VerificationSteps: []string{
			"Confirm the returned expiry matches the reviewed lifetime.",
			"Redeem the bearer token once and confirm the next redeem returns not found.",
			"Confirm audit evidence contains the share id and token hash, never the value or bearer token.",
		},
		CLIArgv:      []string{"trstctl", "secrets", "shares", "create", "-f", "share-request.json"},
		DataHandling: "Preview never receives the value. Execution seals the value and returns the bearer token once; neither may enter logs, events, URLs, or browser storage.",
	})
}
