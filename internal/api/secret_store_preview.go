// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

type secretStoreCreatePreviewResponse struct {
	Capability             string   `json:"capability"`
	Operation              string   `json:"operation"`
	Ready                  bool     `json:"ready"`
	EffectFree             bool     `json:"effect_free"`
	Name                   string   `json:"name"`
	OwnerID                string   `json:"owner_id,omitempty"`
	NextVersion            int      `json:"next_version"`
	RequiredPermission     string   `json:"required_permission"`
	RequestFingerprint     string   `json:"request_fingerprint"`
	Blockers               []string `json:"blockers"`
	PreviewWrites          []string `json:"preview_writes"`
	PreviewExternalEffects []string `json:"preview_external_effects"`
	ExecuteWrites          []string `json:"execute_writes"`
	ExecuteExternalEffects []string `json:"execute_external_effects"`
	RecoverySteps          []string `json:"recovery_steps"`
	DataHandling           string   `json:"secret_data_handling"`
}

func (a *API) secretStoreCreatePreviewFingerprint(tenantID, principal string, req secretWriteRequest) (string, error) {
	if a.secrets == nil || a.secrets.be.CommandMAC == nil {
		return "", errors.New("api: server-keyed application-secret preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain    string          `json:"domain"`
		TenantID  string          `json:"tenant_id"`
		Principal string          `json:"principal"`
		Action    string          `json:"action"`
		Name      string          `json:"name"`
		OwnerID   string          `json:"owner_id,omitempty"`
		Value     secretJSONBytes `json:"value"`
	}{
		Domain: "trstctl.api.native-secret-create-preview.f63.v1", TenantID: tenantID,
		Principal: principal, Action: "create", Name: req.Name, OwnerID: req.OwnerID, Value: req.Value,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := a.secrets.be.CommandMAC([]byte("trstctl.api.native-secret-create-preview.f63.v1"), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: application-secret preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

// previewSecretCreate validates the exact native-store create request while making
// no event append, projection write, idempotency record, audit entry, signer call,
// outbox enqueue, or external call. The secret value exists only in wipeable request
// buffers and the transient keyed-MAC input; it is never echoed in the plan.
func (a *API) previewSecretCreate(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	var req secretWriteRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer req.Value.wipe()
	if req.Name == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "name is required"))
		return
	}
	if len(req.Value) == 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "value is required"))
		return
	}
	if req.OwnerID != "" {
		ownerID, err := validateOwnerID(req.OwnerID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		req.OwnerID = ownerID
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
	blockers := make([]string, 0, 2)
	if req.OwnerID != "" {
		if _, ownerErr := a.store.GetOwner(r.Context(), tenantID, req.OwnerID); ownerErr != nil {
			if store.IsNotFound(ownerErr) {
				blockers = append(blockers, "The selected owner does not exist in this tenant.")
			} else {
				a.writeError(w, ownerErr)
				return
			}
		}
	}
	if _, getErr := a.secrets.be.Store.GetSecret(r.Context(), tenantID, req.Name); getErr == nil {
		blockers = append(blockers, "A secret with this name already exists. Review a rotation instead.")
	} else if !errors.Is(getErr, store.ErrSecretNotFound) {
		a.writeError(w, getErr)
		return
	}
	fingerprint, err := a.secretStoreCreatePreviewFingerprint(tenantID, principal, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, secretStoreCreatePreviewResponse{
		Capability: "F63", Operation: "create", Ready: len(blockers) == 0, EffectFree: true,
		Name: req.Name, OwnerID: req.OwnerID, NextVersion: 1,
		RequiredPermission: "secrets:write", RequestFingerprint: fingerprint,
		Blockers: blockers, PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"append immutable secret.created and secret.version.written events",
			"project one tenant-scoped sealed version 1 row and metadata receipt",
			"append plaintext-free audit evidence",
		},
		ExecuteExternalEffects: []string{},
		RecoverySteps: []string{
			"Cancel before execution to leave the store unchanged.",
			"After creation, rotate to a successor version or delete the exact secret if it is no longer required.",
		},
		DataHandling: "The value is validated only in transient wipeable memory and a server-keyed fingerprint; preview never echoes, logs, persists, signs, or sends it.",
	})
}
