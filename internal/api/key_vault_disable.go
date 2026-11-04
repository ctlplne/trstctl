// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// Key Vault disables (N2). Key Vault cannot revoke a certificate — only its
// issuing CA can. What trstctl can do there is disable the exact certificate
// version the inventory found, so the vault stops serving it to the
// applications that read it; the certificate stays valid until it expires or
// its CA revokes it. Every answer says so: status disabled, revoked false.

// KeyVaultDisableNote is the label every disable carries.
const KeyVaultDisableNote = "disabled in Key Vault, not revoked: the vault stops serving this version, and the certificate stays valid until it expires or its issuing CA revokes it"

// KeyVaultDisableService queues a disable through the covering Key Vault
// discovery source, which the server reads.
type KeyVaultDisableService interface {
	RequestKeyVaultDisable(ctx context.Context, tenantID, requester, certificateID, reason, command string) (store.KeyVaultDisable, error)
}

// WithKeyVaultDisable serves N2's routes.
func WithKeyVaultDisable(service KeyVaultDisableService) Option {
	return func(c *config) { c.keyVaultDisable = service }
}

// Errors the service answers with.
var (
	ErrKeyVaultDisableNotKeyVault = errors.New("this certificate was not found in Azure Key Vault; only a Key Vault certificate version can be disabled there")
	ErrKeyVaultDisableNoRoute     = errors.New("no Key Vault discovery source for this vault names a write_token_ref; add one to allow disabling")
)

func (a *API) keyVaultDisableRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/certificates/{id}/key-vault-disable", opID: "disableKeyVaultCertificate", summary: "Disable the exact Key Vault certificate version this inventory row was found as, through the vault's write credential; this is not a revocation — the certificate stays valid until it expires or its CA revokes it", handler: a.disableKeyVaultCertificate, pathParams: idPath, reqSchema: "KeyVaultDisableRequest", resSchema: "KeyVaultDisable", successCode: "202", mutation: true, perm: authz.IdentitiesWrite},
		{method: "GET", path: "/api/v1/certificates/{id}/key-vault-disables", opID: "listKeyVaultDisables", summary: "List a certificate's Key Vault disables: queued, disabled with the vault's readback, or failed; none is a revocation", handler: a.listKeyVaultDisables, pathParams: idPath, resSchema: "KeyVaultDisableList", successCode: "200", perm: authz.CertsRead},
	}
}

type keyVaultDisableView struct {
	ID             string     `json:"id"`
	CertificateID  string     `json:"certificate_id"`
	ResourceID     string     `json:"resource_id"`
	Status         string     `json:"status"`
	Revoked        bool       `json:"revoked"`
	Note           string     `json:"note"`
	Reason         string     `json:"reason"`
	RequestedBy    string     `json:"requested_by"`
	RequestedAt    time.Time  `json:"requested_at"`
	DisabledAt     *time.Time `json:"disabled_at,omitempty"`
	VaultUpdatedAt *time.Time `json:"vault_updated_at,omitempty"`
	Failure        string     `json:"failure,omitempty"`
}

func keyVaultDisableResponse(d store.KeyVaultDisable) keyVaultDisableView {
	view := keyVaultDisableView{ID: d.ID, CertificateID: d.CertificateID, ResourceID: d.ResourceID, Status: "queued", Revoked: false,
		Note: KeyVaultDisableNote, Reason: d.Reason, RequestedBy: d.RequestedBy, RequestedAt: d.RequestedAt, DisabledAt: d.DisabledAt,
		VaultUpdatedAt: d.VaultUpdatedAt}
	switch {
	case d.Disabled:
		view.Status = "disabled"
	case d.JobStatus == "failed" || d.JobStatus == "dead_letter" || d.JobStatus == "cancelled":
		view.Status, view.Failure = "failed", d.JobError
	}
	return view
}

type keyVaultDisableRequest struct {
	Reason string `json:"reason"`
}

//trstctl:mutation
func (a *API) disableKeyVaultCertificate(w http.ResponseWriter, r *http.Request) {
	key, certificateID := r.Header.Get("Idempotency-Key"), r.PathValue("id")
	var req keyVaultDisableRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 200 {
		a.writeError(w, errStatus(http.StatusBadRequest, "reason is required (at most 200 characters)"))
		return
	}
	subject, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding := crypto.SHA256Hex([]byte("key-vault-disable\x00" + subject + "\x00" + certificateID + "\x00" + req.Reason))
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.keyVaultDisable == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "Key Vault disable is not configured")
		}
		d, err := a.keyVaultDisable.RequestKeyVaultDisable(ctx, tenantID, subject, certificateID, req.Reason, key+"\x00"+certificateID)
		switch {
		case store.IsNotFound(err):
			return 0, nil, errStatus(http.StatusNotFound, "certificate not found")
		case errors.Is(err, ErrKeyVaultDisableNotKeyVault):
			return 0, nil, errStatusFrom(http.StatusBadRequest, err)
		case errors.Is(err, ErrKeyVaultDisableNoRoute):
			return 0, nil, errStatusFrom(http.StatusConflict, err)
		case err != nil:
			return 0, nil, err
		}
		return http.StatusAccepted, keyVaultDisableResponse(d), nil
	})
}

func (a *API) listKeyVaultDisables(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	disables, err := a.store.ListKeyVaultDisables(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]keyVaultDisableView, 0, len(disables))
	for _, d := range disables {
		items = append(items, keyVaultDisableResponse(d))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func keyVaultDisableSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	disable := object(map[string]*Schema{"id": str(), "certificate_id": str(), "resource_id": str(),
		"status": {Type: "string", Enum: []string{"queued", "disabled", "failed"}}, "revoked": {Type: "boolean"}, "note": str(),
		"reason": str(), "requested_by": str(), "requested_at": ts(), "disabled_at": ts(), "vault_updated_at": ts(), "failure": str()},
		"id", "certificate_id", "resource_id", "status", "revoked", "note", "reason", "requested_by", "requested_at")
	return map[string]*Schema{
		"KeyVaultDisableRequest": object(map[string]*Schema{"reason": str()}, "reason"),
		"KeyVaultDisable":        disable,
		"KeyVaultDisableList":    object(map[string]*Schema{"items": {Type: "array", Items: disable}}, "items"),
	}
}
