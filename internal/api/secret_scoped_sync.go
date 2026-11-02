// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretsync"
	"trstctl.com/trstctl/internal/store"
)

// A237: scoped secret sync. A definition syncs every secret under a source
// prefix (a project environment, a folder, any name prefix) to a configured
// target under a destination prefix. Its plan is value-free: per destination
// key create, update (drift when the destination changed outside the sync),
// unchanged, delete (a key it manages whose source is gone, with delete_scope
// managed or prefix; any key under the destination prefix with delete_scope
// prefix), orphaned (kept), unmanaged (a key it didn't write — never touched
// otherwise) or blocked (two sources on one key, a key that would also be a
// folder, or an existing key it didn't write). Applying the
// plan by its digest queues the existing durable per-secret sync jobs for the
// writes and one outbox command per delete.

const (
	scopedSyncSourceLimit      = 500
	scopedSyncDestinationLimit = 1000
)

var scopedSyncNamespace = googleuuid.MustParse("d98c96a4-b0ce-58d4-9771-9c85e2aca8e0")

type secretScopedSyncRequest struct {
	Name              string `json:"name"`
	SourcePrefix      string `json:"source_prefix"`
	Target            string `json:"target"`
	DestinationPrefix string `json:"destination_prefix,omitempty"`
	KeyTransform      string `json:"key_transform,omitempty"`
	DeleteScope       string `json:"delete_scope,omitempty"`
	AdoptExisting     bool   `json:"adopt_existing,omitempty"`
}

type secretScopedSyncApplyRequest struct {
	PlanDigest string `json:"plan_digest"`
}

type secretScopedSyncKeyResponse struct {
	Key           string `json:"key"`
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion int    `json:"source_version,omitempty"`
	State         string `json:"state"`
	JobID         string `json:"job_id,omitempty"`
	JobStatus     string `json:"job_status,omitempty"`
}

type secretScopedSyncResponse struct {
	ID                string                        `json:"id"`
	Name              string                        `json:"name"`
	SourcePrefix      string                        `json:"source_prefix"`
	Target            string                        `json:"target"`
	DestinationPrefix string                        `json:"destination_prefix,omitempty"`
	KeyTransform      string                        `json:"key_transform"`
	DeleteScope       string                        `json:"delete_scope"`
	AdoptExisting     bool                          `json:"adopt_existing"`
	DefinedBy         string                        `json:"defined_by,omitempty"`
	CreatedAt         time.Time                     `json:"created_at"`
	UpdatedAt         time.Time                     `json:"updated_at"`
	LastPlanDigest    string                        `json:"last_plan_digest,omitempty"`
	LastAppliedAt     *time.Time                    `json:"last_applied_at,omitempty"`
	Keys              []secretScopedSyncKeyResponse `json:"keys,omitempty"`
}

type secretScopedSyncItem struct {
	Key           string `json:"key"`
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion int    `json:"source_version,omitempty"`
	Action        string `json:"action"`
	Reason        string `json:"reason,omitempty"`
}

type secretScopedSyncPlan struct {
	SyncID     string                 `json:"sync_id"`
	Name       string                 `json:"name"`
	Target     string                 `json:"target"`
	PlanDigest string                 `json:"plan_digest"`
	Items      []secretScopedSyncItem `json:"items"`
	Changes    int                    `json:"changes"`
	Blocked    int                    `json:"blocked"`
}

type secretScopedSyncWork struct {
	Key   string `json:"key"`
	JobID string `json:"job_id,omitempty"`
	// DeleteID is the outbox command of a delete.
	DeleteID string `json:"delete_id,omitempty"`
}

type secretScopedSyncReceipt struct {
	SyncID     string                 `json:"sync_id"`
	PlanDigest string                 `json:"plan_digest"`
	Writes     []secretScopedSyncWork `json:"writes"`
	Deletes    []secretScopedSyncWork `json:"deletes"`
}

func (a *API) secretScopedSyncRoutes() []route {
	id := []param{pathString("id", "scoped sync ID")}
	return []route{
		{method: "POST", path: "/api/v1/secrets/scoped-syncs", opID: "defineSecretScopedSync",
			summary: "Define a scoped sync: every secret under a source prefix to a configured target under a destination prefix",
			handler: a.defineSecretScopedSync, reqSchema: "SecretScopedSyncRequest", resSchema: "SecretScopedSync",
			successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/scoped-syncs", opID: "listSecretScopedSyncs",
			summary: "List scoped syncs", handler: a.listSecretScopedSyncs, resSchema: "SecretScopedSyncList",
			successCode: "200", perm: authz.SecretsRead},
		{method: "GET", path: "/api/v1/secrets/scoped-syncs/{id}", opID: "getSecretScopedSync",
			summary: "Show a scoped sync with the destination keys it manages and their delivery status",
			handler: a.getSecretScopedSync, pathParams: id, resSchema: "SecretScopedSync", successCode: "200", perm: authz.SecretsRead},
		{method: "DELETE", path: "/api/v1/secrets/scoped-syncs/{id}", opID: "removeSecretScopedSync",
			summary: "Remove a scoped sync; the destination keys it wrote stay", handler: a.removeSecretScopedSync,
			pathParams: id, successCode: "204", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/scoped-syncs/{id}/preview", opID: "previewSecretScopedSync",
			summary: "Preview a scoped sync: a value-free plan per destination key and its digest",
			handler: a.previewSecretScopedSync, pathParams: id, resSchema: "SecretScopedSyncPlan", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/scoped-syncs/{id}/apply", opID: "applySecretScopedSync",
			summary: "Apply a reviewed scoped sync plan by its digest; a changed source or destination makes it stale",
			handler: a.applySecretScopedSync, pathParams: id, reqSchema: "SecretScopedSyncApplyRequest",
			resSchema: "SecretScopedSyncReceipt", successCode: "201", mutation: true, perm: authz.SecretsWrite},
	}
}

func secretScopedSyncSchemas() map[string]*Schema {
	key := object(map[string]*Schema{
		"key": str(), "source_name": str(), "source_version": {Type: "integer"},
		"state":  {Type: "string", Enum: []string{store.SecretScopedSyncKeySynced, store.SecretScopedSyncKeyDeleteQueued}},
		"job_id": str(), "job_status": str(),
	}, "key", "state")
	work := object(map[string]*Schema{"key": str(), "job_id": str(), "delete_id": str()}, "key")
	return map[string]*Schema{
		"SecretScopedSyncRequest": object(map[string]*Schema{
			"name": str(), "source_prefix": str(), "target": str(), "destination_prefix": str(),
			"key_transform":  {Type: "string", Enum: []string{"path", "env"}},
			"delete_scope":   {Type: "string", Enum: []string{"none", "managed", "prefix"}},
			"adopt_existing": {Type: "boolean"},
		}, "name", "source_prefix", "target"),
		"SecretScopedSync": object(map[string]*Schema{
			"id": str(), "name": str(), "source_prefix": str(), "target": str(), "destination_prefix": str(),
			"key_transform": str(), "delete_scope": str(), "adopt_existing": {Type: "boolean"}, "defined_by": str(),
			"created_at": timestamp(), "updated_at": timestamp(), "last_plan_digest": str(), "last_applied_at": timestamp(),
			"keys": {Type: "array", Items: key},
		}, "id", "name", "source_prefix", "target", "key_transform", "delete_scope", "adopt_existing", "created_at", "updated_at"),
		"SecretScopedSyncList": object(map[string]*Schema{
			"items": {Type: "array", Items: ref("SecretScopedSync")}, "next_cursor": str(),
		}, "items"),
		"SecretScopedSyncPlan": object(map[string]*Schema{
			"sync_id": str(), "name": str(), "target": str(), "plan_digest": str(),
			"items": {Type: "array", Items: object(map[string]*Schema{
				"key": str(), "source_name": str(), "source_version": {Type: "integer"},
				"action": {Type: "string", Enum: []string{"create", "update", "unchanged", "delete", "orphaned", "unmanaged", "deleting", "blocked"}},
				"reason": str(),
			}, "key", "action")},
			"changes": {Type: "integer"}, "blocked": {Type: "integer"},
		}, "sync_id", "name", "target", "plan_digest", "items", "changes", "blocked"),
		"SecretScopedSyncApplyRequest": object(map[string]*Schema{"plan_digest": str()}, "plan_digest"),
		"SecretScopedSyncReceipt": object(map[string]*Schema{
			"sync_id": str(), "plan_digest": str(),
			"writes": {Type: "array", Items: work}, "deletes": {Type: "array", Items: work},
		}, "sync_id", "plan_digest", "writes", "deletes"),
	}
}

func scopedSyncView(d store.SecretScopedSync) secretScopedSyncResponse {
	return secretScopedSyncResponse{
		ID: d.ID, Name: d.Name, SourcePrefix: d.SourcePrefix, Target: d.Target, DestinationPrefix: d.DestinationPrefix,
		KeyTransform: d.KeyTransform, DeleteScope: d.DeleteScope, AdoptExisting: d.AdoptExisting, DefinedBy: d.DefinedBy,
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt, LastPlanDigest: d.LastPlanDigest, LastAppliedAt: d.LastAppliedAt,
	}
}

// scopedSyncTarget is the definition's target with its scoped operations.
func (a *API) scopedSyncTarget(tenantID, name string) (secretsync.ScopedTarget, error) {
	target := a.secrets.syncTargets(tenantID)[name]
	if target == nil {
		return nil, errStatus(http.StatusBadRequest, "target "+name+" is not a configured secret-sync target")
	}
	scoped, ok := target.Scoped()
	if !ok {
		return nil, errStatus(http.StatusBadRequest, "target "+name+" does not list its keys, so it can't take a scoped sync (KV v2 targets can)")
	}
	return scoped, nil
}

//trstctl:mutation
func (a *API) defineSecretScopedSync(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretScopedSyncRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		source := strings.TrimSuffix(strings.TrimSpace(req.SourcePrefix), "/")
		dest := strings.Trim(strings.TrimSpace(req.DestinationPrefix), "/")
		transform, scope := req.KeyTransform, req.DeleteScope
		if transform == "" {
			transform = "path"
		}
		if scope == "" {
			scope = "none"
		}
		switch {
		case !secretProjectSlug.MatchString(req.Name):
			return 0, nil, errStatus(http.StatusBadRequest, "name is lowercase letters, digits and hyphens (1-63)")
		case !validApplicationSecretImportPath(source) || len(source) > 512:
			return 0, nil, errStatus(http.StatusBadRequest, "source_prefix is a relative secret path, for example payments/prod/")
		case dest != "" && (!validApplicationSecretImportPath(dest) || len(dest) > 512):
			return 0, nil, errStatus(http.StatusBadRequest, "destination_prefix is a relative path without empty or dot segments")
		case transform != "path" && transform != "env":
			return 0, nil, errStatus(http.StatusBadRequest, "key_transform is path or env")
		case scope != "none" && scope != "managed" && scope != "prefix":
			return 0, nil, errStatus(http.StatusBadRequest, "delete_scope is none, managed (keys this sync wrote) or prefix (every key under the destination prefix)")
		}
		if _, err := a.scopedSyncTarget(tenantID, req.Target); err != nil {
			return 0, nil, err
		}
		// A235: a definition reads its source; a restricted environment the
		// caller isn't granted can't be synced out.
		if ok, err := a.secretScopeAllows(ctx, tenantID, source+"/", false); err != nil {
			return 0, nil, err
		} else if !ok {
			return 0, nil, errStatus(http.StatusForbidden, "the source is a restricted environment you are not a member of")
		}
		existing, err := a.store.ListSecretScopedSyncs(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		for _, d := range existing {
			if d.Name == req.Name {
				return 0, nil, errStatus(http.StatusConflict, "a scoped sync named "+req.Name+" already exists")
			}
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		id := googleuuid.NewString()
		if err := a.orch.DefineSecretScopedSync(ctx, tenantID, projections.SecretScopedSyncDefined{
			ID: id, Name: req.Name, SourcePrefix: source + "/", Target: req.Target, DestinationPrefix: dest,
			KeyTransform: transform, DeleteScope: scope, AdoptExisting: req.AdoptExisting, DefinedBy: subject,
		}); err != nil {
			return 0, nil, err
		}
		d, err := a.store.GetSecretScopedSync(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, scopedSyncView(d), nil
	})
}

func (a *API) listSecretScopedSyncs(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	defs, err := a.store.ListSecretScopedSyncs(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]secretScopedSyncResponse, 0, len(defs))
	for _, d := range defs {
		items = append(items, scopedSyncView(d))
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func (a *API) loadScopedSync(ctx context.Context, tenantID, id string) (store.SecretScopedSync, error) {
	d, err := a.store.GetSecretScopedSync(ctx, tenantID, id)
	if errors.Is(err, store.ErrSecretScopedSyncNotFound) {
		return d, errStatus(http.StatusNotFound, "no such scoped sync")
	}
	return d, err
}

func (a *API) getSecretScopedSync(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	d, err := a.loadScopedSync(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	keys, err := a.store.ListSecretScopedSyncKeys(r.Context(), tenantID, d.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	view := scopedSyncView(d)
	for _, k := range keys {
		item := secretScopedSyncKeyResponse{Key: k.RemoteKey, SourceName: k.SourceName, SourceVersion: k.SourceVersion, State: k.State, JobID: k.JobID}
		if k.JobID != "" {
			if job, err := a.secrets.be.Store.GetSecretSyncJob(r.Context(), tenantID, k.JobID); err == nil {
				item.JobStatus = string(job.Status)
			} else if store.IsNotFound(err) {
				item.JobStatus = "not_queued"
			}
		}
		view.Keys = append(view.Keys, item)
	}
	a.writeJSON(w, http.StatusOK, view)
}

//trstctl:mutation
func (a *API) removeSecretScopedSync(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		d, err := a.loadScopedSync(ctx, tenantID, r.PathValue("id"))
		if err != nil {
			return 0, nil, err
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.RemoveSecretScopedSync(ctx, tenantID, projections.SecretScopedSyncRemoved{ID: d.ID, RemovedBy: subject}); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) previewSecretScopedSync(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	d, err := a.loadScopedSync(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	plan, err := a.planSecretScopedSync(r.Context(), tenantID, d)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, plan)
}

// scopedSyncDestinationKey maps a source path under the prefix to its key.
func scopedSyncDestinationKey(d store.SecretScopedSync, rel string) string {
	key := rel
	if d.KeyTransform == "env" {
		var b strings.Builder
		for _, r := range rel {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				b.WriteRune(unicode.ToUpper(r))
			} else {
				b.WriteByte('_')
			}
		}
		key = b.String()
	}
	if d.DestinationPrefix != "" {
		key = d.DestinationPrefix + "/" + key
	}
	return key
}

// planSecretScopedSync builds the value-free plan. Source values are opened
// only to compare digests with the destination and are wiped at once.
func (a *API) planSecretScopedSync(ctx context.Context, tenantID string, d store.SecretScopedSync) (secretScopedSyncPlan, error) {
	plan := secretScopedSyncPlan{SyncID: d.ID, Name: d.Name, Target: d.Target, Items: []secretScopedSyncItem{}}
	scoped, err := a.scopedSyncTarget(tenantID, d.Target)
	if err != nil {
		return plan, err
	}
	if ok, err := a.secretScopeAllows(ctx, tenantID, d.SourcePrefix, false); err != nil {
		return plan, err
	} else if !ok {
		return plan, errStatus(http.StatusForbidden, "the source is a restricted environment you are not a member of")
	}
	hidden, err := a.hiddenSecretPrefixes(ctx, tenantID)
	if err != nil {
		return plan, err
	}
	sources, err := a.store.ListSecretNamesUnder(ctx, tenantID, []string{d.SourcePrefix}, hidden, scopedSyncSourceLimit+1)
	if err != nil {
		return plan, err
	}
	if len(sources) > scopedSyncSourceLimit {
		return plan, errStatus(http.StatusBadRequest, "a scoped sync covers at most 500 secrets; narrow its source prefix")
	}
	existing, err := scoped.ListKeys(ctx, d.DestinationPrefix, scopedSyncDestinationLimit)
	if errors.Is(err, secretsync.ErrScopedListLimit) {
		return plan, errStatus(http.StatusBadRequest, "the destination holds more than 1000 keys under its prefix; narrow the destination prefix")
	}
	if err != nil {
		return plan, errStatus(http.StatusBadGateway, "the target's keys could not be listed")
	}
	managedRows, err := a.store.ListSecretScopedSyncKeys(ctx, tenantID, d.ID)
	if err != nil {
		return plan, err
	}
	managed := map[string]store.SecretScopedSyncKey{}
	for _, k := range managedRows {
		managed[k.RemoteKey] = k
	}
	onDestination := map[string]bool{}
	for _, k := range existing {
		onDestination[k] = true
	}
	bySource := map[string][]store.Secret{}
	var planned []string
	for _, src := range sources {
		key := scopedSyncDestinationKey(d, strings.TrimPrefix(src.Name, d.SourcePrefix))
		if len(bySource[key]) == 0 {
			planned = append(planned, key)
		}
		bySource[key] = append(bySource[key], src)
	}
	slices.Sort(planned)
	all := slices.Clone(existing)
	all = append(all, planned...)
	slices.Sort(all)
	all = slices.Compact(all)
	digests := map[string]string{}
	for _, key := range planned {
		srcs := bySource[key]
		item := secretScopedSyncItem{Key: key, SourceName: srcs[0].Name, SourceVersion: srcs[0].Version}
		switch {
		case len(srcs) > 1:
			item.Action, item.Reason = "blocked", "two secrets map to this key: "+srcs[0].Name+" and "+srcs[1].Name
		case scopedSyncNested(all, key) != "":
			item.Action, item.Reason = "blocked", "the destination would hold both "+key+" and "+scopedSyncNested(all, key)+"; a key can't also be a folder"
		case onDestination[key] && managed[key].RemoteKey == "" && !d.AdoptExisting:
			item.Action, item.Reason = "blocked", "the destination already holds "+key+", which this sync didn't write; set adopt_existing to take it over"
		default:
			action, err := a.scopedSyncWriteAction(ctx, tenantID, scoped, srcs[0], key, onDestination[key], digests)
			if err != nil {
				return plan, err
			}
			item.Action = action
			switch {
			case action == "update" && managed[key].RemoteKey == "":
				item.Reason = "adopted: the destination key was not written by this sync"
			case action == "update" && managed[key].SourceVersion == srcs[0].Version:
				item.Reason = "drift: the destination changed outside this sync"
			}
		}
		plan.Items = append(plan.Items, item)
	}
	for _, k := range managedRows {
		if len(bySource[k.RemoteKey]) > 0 {
			continue
		}
		item := secretScopedSyncItem{Key: k.RemoteKey, SourceName: k.SourceName, SourceVersion: k.SourceVersion}
		switch {
		case k.State == store.SecretScopedSyncKeyDeleteQueued:
			item.Action, item.Reason = "deleting", "a delete is queued"
		case d.DeleteScope == "managed" || d.DeleteScope == "prefix":
			item.Action, item.Reason = "delete", "its source is gone and the delete scope includes it"
		default:
			item.Action, item.Reason = "orphaned", "its source is gone; the delete scope none keeps it"
		}
		plan.Items = append(plan.Items, item)
	}
	for _, key := range existing {
		if len(bySource[key]) > 0 || managed[key].RemoteKey != "" {
			continue
		}
		if d.DeleteScope == "prefix" {
			plan.Items = append(plan.Items, secretScopedSyncItem{Key: key, Action: "delete",
				Reason: "not written by this sync, but the reviewed delete scope is every key under the destination prefix"})
			continue
		}
		plan.Items = append(plan.Items, secretScopedSyncItem{Key: key, Action: "unmanaged", Reason: "not written by this sync; never touched"})
	}
	slices.SortFunc(plan.Items, func(x, y secretScopedSyncItem) int { return strings.Compare(x.Key, y.Key) })
	for _, item := range plan.Items {
		switch item.Action {
		case "create", "update", "delete":
			plan.Changes++
		case "blocked":
			plan.Blocked++
		}
	}
	material, err := json.Marshal(struct {
		Domain     string                 `json:"domain"`
		Definition store.SecretScopedSync `json:"definition"`
		Items      []secretScopedSyncItem `json:"items"`
		Digests    map[string]string      `json:"destination_digests"`
		Existing   []string               `json:"existing"`
	}{"trstctl.secret.scoped-sync-plan.v1", d, plan.Items, digests, existing})
	if err != nil {
		return plan, err
	}
	plan.PlanDigest = crypto.SHA256Hex(material)
	return plan, nil
}

// scopedSyncNested returns a key in all that is key's parent or child path.
func scopedSyncNested(all []string, key string) string {
	for _, other := range all {
		if other != key && (strings.HasPrefix(other, key+"/") || strings.HasPrefix(key, other+"/")) {
			return other
		}
	}
	return ""
}

// scopedSyncWriteAction compares the source value with the destination by
// digest: create, update or unchanged. The destination digest joins the plan
// digest so a destination change makes a reviewed plan stale.
func (a *API) scopedSyncWriteAction(ctx context.Context, tenantID string, scoped secretsync.ScopedTarget,
	src store.Secret, key string, exists bool, digests map[string]string) (string, error) {
	if !exists {
		return "create", nil
	}
	_, current, err := scoped.ReadDigest(ctx, key)
	if err != nil {
		return "", errStatus(http.StatusBadGateway, "the target's key "+key+" could not be read back")
	}
	digests[key] = current
	rec, err := a.secrets.be.Store.GetSecret(ctx, tenantID, src.Name)
	if err != nil {
		return "", err
	}
	plain, err := a.secrets.open(ctx, tenantID, rec.Sealed, sealAAD(tenantID, src.Name))
	if err != nil {
		return "", err
	}
	defer secret.Wipe(plain)
	if current != "" && crypto.ConstantTimeEqual([]byte(current), []byte(crypto.SHA256Hex(plain))) {
		return "unchanged", nil
	}
	return "update", nil
}

//trstctl:mutation
func (a *API) applySecretScopedSync(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	var req secretScopedSyncApplyRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if _, err := hex.DecodeString(req.PlanDigest); err != nil || len(req.PlanDigest) != 64 {
		a.writeError(w, errStatus(http.StatusBadRequest, "plan_digest from a scoped sync preview is required"))
		return
	}
	id := r.PathValue("id")
	a.mutateDurable(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		d, err := a.loadScopedSync(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		receipt, err := a.executeSecretScopedSync(ctx, tenantID, d, req.PlanDigest)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, receipt, nil
	})
}

// executeSecretScopedSync fixes the plan in one event under a stable ID, then
// queues a durable sync job per write. A retry finds the event and resumes
// queueing from it, so a crash in between never needs a new plan.
func (a *API) executeSecretScopedSync(ctx context.Context, tenantID string, d store.SecretScopedSync, planDigest string) (secretScopedSyncReceipt, error) {
	receipt := secretScopedSyncReceipt{SyncID: d.ID, PlanDigest: planDigest, Writes: []secretScopedSyncWork{}, Deletes: []secretScopedSyncWork{}}
	if a.secrets.be.QueueSecretSync == nil || a.secrets.be.EventLog == nil {
		return receipt, errStatus(http.StatusServiceUnavailable, "event-backed secret sync is not configured")
	}
	epoch, err := a.secrets.be.Store.ApplicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return receipt, err
	}
	eventID := googleuuid.NewSHA1(scopedSyncNamespace, []byte(tenantID+"\x00"+epoch+"\x00"+d.ID+"\x00"+planDigest)).String()
	var applied projections.SecretScopedSyncApplied
	if prior, found, err := a.secrets.be.EventLog.EventByID(ctx, eventID); err != nil {
		return receipt, err
	} else if found {
		if err := json.Unmarshal(prior.Data, &applied); err != nil {
			return receipt, err
		}
	} else {
		plan, err := a.planSecretScopedSync(ctx, tenantID, d)
		if err != nil {
			return receipt, err
		}
		if plan.PlanDigest != planDigest {
			return receipt, &apiError{status: http.StatusConflict,
				detail: "the plan changed since the preview: a source or the destination moved; review the new plan",
				ext:    map[string]any{"code": "plan_stale", "plan": plan}}
		}
		if plan.Blocked > 0 {
			return receipt, &apiError{status: http.StatusConflict, detail: "the plan has blocked items; nothing was synced",
				ext: map[string]any{"code": "plan_blocked", "plan": plan}}
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return receipt, err
		}
		applied = projections.SecretScopedSyncApplied{TenantEpoch: epoch, ID: d.ID, Target: d.Target, PlanDigest: planDigest,
			AppliedBy: subject, Items: []projections.SecretScopedSyncAppliedItem{}}
		for _, item := range plan.Items {
			switch item.Action {
			case "create", "update":
				applied.Items = append(applied.Items, projections.SecretScopedSyncAppliedItem{
					RemoteKey: item.Key, SourceName: item.SourceName, SourceVersion: item.SourceVersion, Action: item.Action,
					JobID: store.DurableSecretSyncJobIDForEpoch(tenantID, epoch, scopedSyncJobKey(d.ID, item, planDigest)),
				})
			case "delete":
				applied.Items = append(applied.Items, projections.SecretScopedSyncAppliedItem{
					RemoteKey: item.Key, Action: "delete",
					DeleteID: googleuuid.NewSHA1(scopedSyncNamespace, []byte(tenantID+"\x00"+epoch+"\x00"+d.ID+"\x00"+item.Key+"\x00"+planDigest)).String(),
				})
			}
		}
		if applied, err = a.orch.RecordSecretScopedSyncApplied(ctx, tenantID, eventID, applied); err != nil {
			return receipt, applicationSecretMutationError(err)
		}
	}
	for _, item := range applied.Items {
		if item.Action == "delete" {
			receipt.Deletes = append(receipt.Deletes, secretScopedSyncWork{Key: item.RemoteKey, DeleteID: item.DeleteID})
			continue
		}
		if err := a.queueScopedSyncWrite(ctx, tenantID, d, applied, item); err != nil {
			return receipt, err
		}
		receipt.Writes = append(receipt.Writes, secretScopedSyncWork{Key: item.RemoteKey, JobID: item.JobID})
	}
	return receipt, nil
}

func scopedSyncJobKey(syncID string, item secretScopedSyncItem, planDigest string) string {
	return "scoped-sync:" + syncID + ":" + item.Key + ":" + strconv.Itoa(item.SourceVersion) + ":" + planDigest
}

// queueScopedSyncWrite queues one write with the planned version's value; the
// job's identity and binding derive from the plan, so a retry finds it.
func (a *API) queueScopedSyncWrite(ctx context.Context, tenantID string, d store.SecretScopedSync,
	applied projections.SecretScopedSyncApplied, item projections.SecretScopedSyncAppliedItem) error {
	version, err := a.secrets.be.Store.GetSecretVersion(ctx, tenantID, item.SourceName, item.SourceVersion)
	if err != nil {
		return err
	}
	value, err := a.secrets.open(ctx, tenantID, version.Sealed, sealAAD(tenantID, item.SourceName))
	if err != nil {
		return err
	}
	defer secret.Wipe(value)
	key := scopedSyncJobKey(d.ID, secretScopedSyncItem{Key: item.RemoteKey, SourceVersion: item.SourceVersion}, applied.PlanDigest)
	binding := crypto.SHA256Hex([]byte("trstctl.scoped-sync.job.v1\x00" + key + "\x00" + item.SourceName))
	err = a.secrets.be.QueueSecretSync(ctx, tenantID, item.SourceName, item.SourceVersion, d.Target, item.RemoteKey, key, binding, value)
	if errors.Is(err, store.ErrIdempotencyConflict) {
		return errStatus(http.StatusConflict, "a different sync job holds this plan's write")
	}
	return err
}
