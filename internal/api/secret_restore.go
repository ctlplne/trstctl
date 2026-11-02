// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A236: folder restore. A restore puts an environment (or one folder of it)
// back to how it stood at a point in time, as new versions written in one
// batch: each secret that changed since then gets a new version holding the
// value it had at that time. Secrets created since are listed and left alone;
// nothing is deleted. A version whose credential a rotation retired, revoked
// or let expire is refused by name — a restore never silently brings back a
// dead credential — and every restored value's references must still resolve
// as the caller may read them, without a cycle. Like a promotion, the caller
// previews a value-free plan and applies it by its digest.

const (
	secretRestoreRestore      = "restore"
	secretRestoreUnchanged    = "unchanged"
	secretRestoreCreatedSince = "created_since"
	secretRestoreBlocked      = "blocked"
)

type secretRestoreRequest struct {
	Environment string    `json:"environment"`
	Folder      string    `json:"folder,omitempty"`
	At          time.Time `json:"at"`
	PlanDigest  string    `json:"plan_digest,omitempty"`
}

type secretRestoreItem struct {
	Name           string `json:"name"`
	CurrentVersion int    `json:"current_version"`
	RestoreVersion int    `json:"restore_version,omitempty"`
	Action         string `json:"action"`
	Reason         string `json:"reason,omitempty"`
}

type secretRestorePlan struct {
	Project     string              `json:"project"`
	Environment string              `json:"environment"`
	Folder      string              `json:"folder,omitempty"`
	At          time.Time           `json:"at"`
	PlanDigest  string              `json:"plan_digest"`
	Items       []secretRestoreItem `json:"items"`
	Changes     int                 `json:"changes"`
	Blocked     int                 `json:"blocked"`
}

func (a *API) secretRestoreRoutes() []route {
	project := []param{pathString("project", "secrets project slug")}
	return []route{
		{method: "POST", path: "/api/v1/secrets/projects/{project}/restores/preview", opID: "previewSecretRestore",
			summary: "Preview restoring an environment (or one folder) to a point in time: a value-free plan and its digest",
			handler: a.previewSecretRestore, pathParams: project, reqSchema: "SecretRestoreRequest",
			resSchema: "SecretRestorePlan", successCode: "200", perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/projects/{project}/restores", opID: "applySecretRestore",
			summary: "Apply a reviewed restore plan by its digest as one batch of new versions; nothing outside the folder changes",
			handler: a.applySecretRestore, pathParams: project, reqSchema: "SecretRestoreRequest",
			resSchema: "SecretVersionBatchReceipt", successCode: "201", mutation: true, perm: authz.SecretsWrite},
	}
}

func secretRestoreSchemas() map[string]*Schema {
	return map[string]*Schema{
		"SecretRestoreRequest": object(map[string]*Schema{
			"environment": str(), "folder": str(), "at": timestamp(), "plan_digest": str(),
		}, "environment", "at"),
		"SecretRestoreItem": object(map[string]*Schema{
			"name": str(), "current_version": {Type: "integer"}, "restore_version": {Type: "integer"},
			"action": {Type: "string", Enum: []string{secretRestoreRestore, secretRestoreUnchanged,
				secretRestoreCreatedSince, secretRestoreBlocked}},
			"reason": str(),
		}, "name", "current_version", "action"),
		"SecretRestorePlan": object(map[string]*Schema{
			"project": str(), "environment": str(), "folder": str(), "at": timestamp(), "plan_digest": str(),
			"items": {Type: "array", Items: ref("SecretRestoreItem")}, "changes": {Type: "integer"}, "blocked": {Type: "integer"},
		}, "project", "environment", "at", "plan_digest", "items", "changes", "blocked"),
	}
}

func (a *API) previewSecretRestore(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req secretRestoreRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	planned, err := a.planSecretRestore(r.Context(), tenantID, r.PathValue("project"), req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, planned.plan)
}

//trstctl:mutation
func (a *API) applySecretRestore(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	project := r.PathValue("project")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req secretRestoreRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if _, err := hex.DecodeString(req.PlanDigest); err != nil || len(req.PlanDigest) != 64 {
		a.writeError(w, errStatus(http.StatusBadRequest, "plan_digest from a restore preview is required"))
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
	keyDigest, binding, err := a.applicationSecretRequestBinding(
		tenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(), "restore", "native", project, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, binding, func(ctx context.Context, authorizedTenant string) (int, any, error) {
		if authorizedTenant != tenantID {
			return 0, nil, errors.New("api: secret restore tenant changed")
		}
		receipt, err := a.executeSecretVersionBatch(ctx, tenantID, store.ApplicationSecretBatchRestore,
			idempotencyKey, keyDigest, binding, req.PlanDigest,
			func(ctx context.Context) ([]projections.ApplicationSecretBatchVersionItem, int, error) {
				return a.sealSecretRestore(ctx, tenantID, project, req)
			})
		if err != nil {
			return 0, nil, err
		}
		if receipt.BatchID == "" {
			return http.StatusOK, receipt, nil
		}
		return http.StatusCreated, receipt, nil
	})
}

type secretRestorePlanned struct {
	plan   secretRestorePlan
	sealed map[string]store.SecretVersion // name → the version to restore
}

// planSecretRestore builds the reviewed restore plan from version history.
func (a *API) planSecretRestore(ctx context.Context, tenantID, project string, req secretRestoreRequest) (*secretRestorePlanned, error) {
	_, envs, _, err := a.store.GetSecretProject(ctx, tenantID, project)
	if errors.Is(err, store.ErrSecretProjectNotFound) {
		return nil, errStatus(http.StatusNotFound, "no such secrets project")
	}
	if err != nil {
		return nil, err
	}
	known := false
	for _, env := range envs {
		known = known || env.Slug == req.Environment
	}
	now := time.Now().UTC()
	switch {
	case !known:
		return nil, errStatus(http.StatusBadRequest, "environment must be one of this project's environments")
	case !validSecretFolder(req.Folder):
		return nil, errStatus(http.StatusBadRequest, "folder is a relative path without empty or dot segments, at most 256 bytes")
	case req.At.IsZero() || req.At.After(now):
		return nil, errStatus(http.StatusBadRequest, "at is a past point in time")
	}
	envPrefix := project + "/" + req.Environment + "/"
	if ok, err := a.secretScopeAllows(ctx, tenantID, envPrefix, true); err != nil {
		return nil, err
	} else if !ok {
		return nil, errStatus(http.StatusForbidden, "the environment is restricted to members with write access")
	}
	prefix := envPrefix
	if req.Folder != "" {
		prefix += req.Folder + "/"
	}
	hidden, err := a.hiddenSecretPrefixes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	current, err := a.store.ListSecretNamesUnder(ctx, tenantID, []string{prefix}, hidden, secretPromotionLimit+1)
	if err != nil {
		return nil, err
	}
	if len(current) > secretPromotionLimit {
		return nil, errStatus(http.StatusBadRequest, "a restore covers at most 100 secrets at once; narrow it with a folder")
	}
	planned := &secretRestorePlanned{
		plan: secretRestorePlan{Project: project, Environment: req.Environment, Folder: req.Folder,
			At: req.At.UTC(), Items: []secretRestoreItem{}},
		sealed: map[string]store.SecretVersion{},
	}
	values := map[string][]byte{}
	defer func() {
		for name, value := range values {
			secret.Wipe(value)
			delete(values, name)
		}
	}()
	for _, rec := range current {
		item := secretRestoreItem{Name: rec.Name, CurrentVersion: rec.Version}
		old, err := a.secrets.be.Store.GetSecretVersionAt(ctx, tenantID, rec.Name, req.At)
		switch {
		case errors.Is(err, store.ErrSecretNotFound):
			item.Action = secretRestoreCreatedSince
		case err != nil:
			return nil, err
		case old.Version == rec.Version:
			item.Action, item.RestoreVersion = secretRestoreUnchanged, old.Version
		default:
			item.Action, item.RestoreVersion = secretRestoreRestore, old.Version
			state, err := a.secrets.be.Store.SecretVersionCredentialState(ctx, tenantID, rec.Name, old.Version, now)
			if err != nil {
				return nil, err
			}
			if state.State != "" {
				item.Action, item.Reason = secretRestoreBlocked, secretCredentialStateReason(state)
				break
			}
			plain, err := a.secrets.open(ctx, tenantID, old.Sealed, sealAAD(tenantID, rec.Name))
			if err != nil {
				return nil, err
			}
			values[rec.Name] = plain
			planned.sealed[rec.Name] = old
		}
		planned.plan.Items = append(planned.plan.Items, item)
	}
	// Restored values must resolve as they will stand: a restored name reads
	// its restored value, everything else its stored value as the caller may
	// read it.
	reached, resolved := map[string]int{}, map[string]bool{}
	for i := range planned.plan.Items {
		item := &planned.plan.Items[i]
		if item.Action != secretRestoreRestore {
			continue
		}
		reason, err := a.promotionReferenceProblem(ctx, tenantID, item.Name, values, reached, resolved, nil)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			item.Action, item.Reason = secretRestoreBlocked, reason
			delete(planned.sealed, item.Name)
		}
	}
	for _, item := range planned.plan.Items {
		switch item.Action {
		case secretRestoreRestore:
			planned.plan.Changes++
		case secretRestoreBlocked:
			planned.plan.Blocked++
		}
	}
	material, err := json.Marshal(struct {
		Domain  string            `json:"domain"`
		Plan    secretRestorePlan `json:"plan"`
		Reached map[string]int    `json:"reached"`
	}{"trstctl.secret.restore-plan.v1", planned.plan, reached})
	if err != nil {
		return nil, err
	}
	planned.plan.PlanDigest = crypto.SHA256Hex(material)
	return planned, nil
}

// sealSecretRestore recomputes the plan and returns its restored versions'
// own ciphertext: the name is unchanged, so its sealed bytes stay valid.
func (a *API) sealSecretRestore(
	ctx context.Context, tenantID, project string, req secretRestoreRequest,
) ([]projections.ApplicationSecretBatchVersionItem, int, error) {
	planned, err := a.planSecretRestore(ctx, tenantID, project, req)
	if err != nil {
		return nil, 0, err
	}
	if planned.plan.PlanDigest != req.PlanDigest {
		return nil, 0, &apiError{status: http.StatusConflict,
			detail: "the plan changed since the preview: review the new plan and apply its digest",
			ext:    map[string]any{"code": "plan_stale", "plan": planned.plan}}
	}
	if planned.plan.Blocked > 0 {
		return nil, 0, &apiError{status: http.StatusConflict,
			detail: "the plan has blocked items; nothing was restored",
			ext:    map[string]any{"code": "plan_blocked", "plan": planned.plan}}
	}
	var items []projections.ApplicationSecretBatchVersionItem
	for _, item := range planned.plan.Items {
		if item.Action != secretRestoreRestore {
			continue
		}
		old := planned.sealed[item.Name]
		items = append(items, projections.ApplicationSecretBatchVersionItem{
			Name: item.Name, ExpectedVersion: item.CurrentVersion, ResultVersion: item.CurrentVersion + 1,
			Sealed: old.Sealed, SourceName: item.Name, SourceVersion: old.Version,
		})
	}
	return items, 0, nil
}
