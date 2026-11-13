// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

// A236-L4: a deleted application secret is kept, sealed and with its version
// history, until the deleted-secret retention window (secrets.deleted_retention,
// SecretsBackend.DeletedRetention) ends. These routes list what is kept,
// restore one — an event-sourced "undelete" through the same fence, dual
// control and receipt as every other secret change — and purge one before the
// window ends. A list never carries a value.

// deletedSecretResponse is one deleted secret kept for restore: metadata only.
type deletedSecretResponse struct {
	Name      string    `json:"name"`
	OwnerID   string    `json:"owner_id,omitempty"`
	Version   int       `json:"version"`
	Versions  int       `json:"versions"`
	CreatedAt time.Time `json:"created_at"`
	DeletedAt time.Time `json:"deleted_at"`
	// PurgeAfter is when the retention sweep removes it; restore it before.
	PurgeAfter time.Time `json:"purge_after"`
}

func (a *API) deletedSecretRoutes() []route {
	name := []param{pathString("name", "hierarchical secret name")}
	page := []param{{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"}}
	return []route{
		{method: "GET", path: "/api/v1/secrets/deleted", opID: "listDeletedSecrets",
			summary: "List deleted application secrets kept for restore until the retention window ends (no values)",
			handler: a.listDeletedSecrets, query: page, resSchema: "DeletedSecretList", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/deleted/{name...}", opID: "restoreDeletedSecret",
			summary: "Restore a deleted application secret at the version it had, with its version history",
			handler: a.restoreDeletedSecret, pathParams: name, resSchema: "SecretMeta", successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "DELETE", path: "/api/v1/secrets/deleted/{name...}", opID: "purgeDeletedSecret",
			summary: "Purge a deleted application secret and its version history before the retention window ends",
			handler: a.purgeDeletedSecret, pathParams: name, successCode: "204", mutation: true, perm: authz.SecretsWrite},
	}
}

func deletedSecretSchemas() map[string]*Schema {
	item := object(map[string]*Schema{
		"name": str(), "owner_id": str(), "version": {Type: "integer", Description: "the version the secret had when deleted; a restore brings it back"},
		"versions":   {Type: "integer", Description: "historical versions kept with it"},
		"created_at": timestamp(), "deleted_at": timestamp(),
		"purge_after": {Type: "string", Format: "date-time", Description: "when the retention sweep removes it"},
	}, "name", "version", "versions", "created_at", "deleted_at", "purge_after")
	return map[string]*Schema{
		"DeletedSecret":     item,
		"DeletedSecretList": object(map[string]*Schema{"items": {Type: "array", Items: ref("DeletedSecret")}}, "items"),
	}
}

func (a *API) deletedSecretView(d store.DeletedSecret) deletedSecretResponse {
	return deletedSecretResponse{
		Name: d.Name, OwnerID: d.OwnerID, Version: d.Version, Versions: d.Versions,
		CreatedAt: d.CreatedAt, DeletedAt: d.DeletedAt, PurgeAfter: d.DeletedAt.Add(a.secrets.be.DeletedRetention),
	}
}

// listDeletedSecrets lists the tenant's deleted secrets still kept, most
// recently deleted first; a secret in a restricted environment the caller is
// not granted is left out, as it is from the live list.
func (a *API) listDeletedSecrets(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	hidden, err := a.hiddenSecretPrefixes(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	kept, err := a.secrets.be.Store.ListDeletedSecrets(r.Context(), tenantID, hidden, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]deletedSecretResponse, 0, len(kept))
	for _, d := range kept {
		items = append(items, a.deletedSecretView(d))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

// restoreDeletedSecret brings a deleted secret back at the version it had,
// with its owner and version history. It is idempotent (AN-5); a name with no
// kept tombstone is 404, and a name a live secret has taken since is 409.
//
//trstctl:mutation
func (a *API) restoreDeletedSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	name := r.PathValue("name")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	bindingTenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if err := a.requireSecretWrite(r.Context(), bindingTenantID, name); err != nil {
		a.writeError(w, err)
		return
	}
	keyDigest, requestBinding, err := a.applicationSecretRequestBinding(
		bindingTenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(), "undelete", "native", name, nil)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, requestBinding, func(ctx context.Context, tenantID string) (int, any, error) {
		if tenantID != bindingTenantID {
			return 0, nil, errors.New("api: application-secret binding tenant changed")
		}
		// A restore puts a stored secret back: it takes the same creation fence
		// and stored-secrets quota as a create.
		return withStoredSecretCreationFence(ctx, tenantID, func(work context.Context) (int, any, error) {
			return a.executeSecretUndelete(work, tenantID, name, idempotencyKey, keyDigest, requestBinding)
		})
	})
}

func (a *API) executeSecretUndelete(ctx context.Context, tenantID, name, idempotencyKey, keyDigest, requestBinding string) (int, any, error) {
	tenantEpoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return 0, nil, err
	}
	eventID := applicationSecretMutationEventID(tenantID, tenantEpoch, name, "undelete", keyDigest)
	if receipt, ok, receiptErr := a.applicationSecretMaterializedResult(
		ctx, tenantID, eventID, requestBinding, name, "undelete"); receiptErr != nil {
		return 0, nil, applicationSecretMutationError(receiptErr)
	} else if ok {
		return http.StatusOK, applicationSecretReceiptMeta(receipt), nil
	}
	fence, payload, prepared, err := a.applicationSecretMutationFence(
		ctx, tenantID, name, "undelete", eventID, requestBinding)
	if err != nil {
		return 0, nil, applicationSecretMutationError(err)
	}
	if !prepared {
		if _, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name); err == nil {
			return 0, nil, errStatus(http.StatusConflict, "a secret of this name exists; delete or rename it before restoring the deleted one")
		} else if !errors.Is(err, store.ErrSecretNotFound) {
			return 0, nil, err
		}
		deleted, sealed, err := a.secrets.be.Store.GetDeletedSecret(ctx, tenantID, name)
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusNotFound, "no deleted secret of this name is kept")
			}
			return 0, nil, err
		}
		if err := usage.AllowCreate(ctx, tenantID, usage.MeterSecretsStored); err != nil {
			return 0, nil, err
		}
		commandKeyDigest, commandEvidence, commandErr := a.applicationSecretCommandEvidence(tenantID, idempotencyKey, canonicalApplicationSecretCommand{
			Domain: "trstctl.api.application-secret-command.v2", TenantEpoch: tenantEpoch, Action: "undelete",
			Name: name, Surface: "native", ExpectedVersion: deleted.Version, ResultVersion: deleted.Version,
			SourceVersion: deleted.Version, SourceWrittenAt: deleted.DeletedAt.UTC(),
		})
		if commandErr != nil {
			return 0, nil, commandErr
		}
		if commandKeyDigest != keyDigest {
			return 0, nil, errors.New("api: application-secret idempotency digest changed")
		}
		payload = projections.ApplicationSecretMutation{
			TenantEpoch: tenantEpoch, Action: "undelete", Name: name, OwnerID: deleted.OwnerID,
			ExpectedVersion: deleted.Version, ResultVersion: deleted.Version, Sealed: sealed,
			SourceVersion: deleted.Version, SourceWrittenAt: deleted.DeletedAt.UTC(),
			IdempotencyKeyDigest: keyDigest, RequestBinding: requestBinding,
			CommandEvidence: commandEvidence, Surface: "native",
		}
		fence, payload, err = a.claimApplicationSecretMutationFence(ctx, tenantID, name,
			"undelete", eventID, projections.EventApplicationSecretUndeleted, requestBinding, payload)
		if errors.Is(err, store.ErrSecretNotFound) {
			// Purged or deleted again since the read: the claim found nothing to restore.
			return 0, nil, errStatus(http.StatusNotFound, "no deleted secret of this name is kept")
		}
		if err != nil {
			return 0, nil, applicationSecretMutationError(err)
		}
	}
	fence, payload, err = a.finalizeApplicationSecretMutationFence(ctx, tenantID, fence, payload)
	if err != nil {
		return 0, nil, applicationSecretMutationError(err)
	}
	if _, _, err := a.appendAndProjectApplicationSecretMutation(ctx, tenantID, fence, payload, prepared); err != nil {
		if receipt, ok, retiredErr := a.applicationSecretResultAfterFenceRetired(
			ctx, tenantID, eventID, requestBinding, name, "undelete", err); retiredErr != nil {
			return 0, nil, retiredErr
		} else if ok {
			return http.StatusOK, applicationSecretReceiptMeta(receipt), nil
		}
		return 0, nil, applicationSecretMutationError(err)
	}
	restored, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, toSecretMeta(restored), nil
}

// purgeDeletedSecret removes a kept deleted secret and its history now. It is
// idempotent (AN-5); a name with no kept tombstone is 404.
//
//trstctl:mutation
func (a *API) purgeDeletedSecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	name := r.PathValue("name")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if err := a.requireSecretWrite(r.Context(), tenantID, name); err != nil {
		a.writeError(w, err)
		return
	}
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		purged, err := a.secrets.be.Store.PurgeDeletedSecret(ctx, tenantID, name)
		if errors.Is(err, store.ErrApplicationSecretMutationInFlight) {
			return 0, nil, errStatus(http.StatusConflict, "a restore or change of this secret is in flight: retry when it finishes")
		}
		if err != nil {
			return 0, nil, err
		}
		if !purged {
			return 0, nil, errStatus(http.StatusNotFound, "no deleted secret of this name is kept")
		}
		a.auditDeletedSecretPurge(ctx, tenantID, name)
		return http.StatusNoContent, nil, nil
	})
}

// auditDeletedSecretPurge records that a deleted secret was purged before its
// retention window ended: the name only, never a value.
func (a *API) auditDeletedSecretPurge(ctx context.Context, tenantID, name string) {
	if a.secrets == nil || a.secrets.be.Audit == nil {
		return
	}
	data, err := json.Marshal(map[string]string{"name": name, "reason": "purged"})
	if err != nil {
		return
	}
	_ = auditsink.Emit(ctx, a.secrets.be.Audit, nil, "secret.deleted_purged", tenantID, data)
}
