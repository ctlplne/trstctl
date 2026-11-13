// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	scopedSyncReconcilerSubject = "system:scoped-sync-reconciler"

	// scopedSyncModeApproved is approval-gated convergence (A237-L1): the
	// reconciler re-plans the definition like an auto one, but a plan with
	// changes is applied only once the tenant's required number of distinct
	// approvers approve that exact plan; a manual apply waits for the same
	// approval.
	scopedSyncModeApproved = "approved"
	// scopedSyncApprovalKind is the approval request kind of an approved
	// definition's plan; its resource is the definition's ID.
	scopedSyncApprovalKind = "secret_scoped_sync"
	// scopedSyncAwaitingApproval is the reconcile status of an approved
	// definition whose current plan waits for its approvers.
	scopedSyncAwaitingApproval = "awaiting_approval"
)

// validScopedSyncMode is a mode a definition can hold.
func validScopedSyncMode(mode string) bool {
	return mode == "manual" || mode == "auto" || mode == scopedSyncModeApproved
}

var scopedSyncNamespace = googleuuid.MustParse("d98c96a4-b0ce-58d4-9771-9c85e2aca8e0")

type secretScopedSyncRequest struct {
	Name              string `json:"name"`
	SourcePrefix      string `json:"source_prefix"`
	Target            string `json:"target"`
	DestinationPrefix string `json:"destination_prefix,omitempty"`
	KeyTransform      string `json:"key_transform,omitempty"`
	DeleteScope       string `json:"delete_scope,omitempty"`
	AdoptExisting     bool   `json:"adopt_existing,omitempty"`
	Mode              string `json:"mode,omitempty"`
}

type secretScopedSyncModeRequest struct {
	Mode string `json:"mode"`
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
	Mode              string                        `json:"mode"`
	LastReconcileAt   *time.Time                    `json:"last_reconcile_at,omitempty"`
	ReconcileStatus   string                        `json:"reconcile_status,omitempty"`
	ReconcileReason   string                        `json:"reconcile_reason,omitempty"`
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
		{method: "PUT", path: "/api/v1/secrets/scoped-syncs/{id}", opID: "replaceSecretScopedSync",
			summary: "Replace a scoped sync's definition in place; moving the destination releases the keys it managed there, which stay",
			handler: a.replaceSecretScopedSync, pathParams: id, reqSchema: "SecretScopedSyncRequest", resSchema: "SecretScopedSync",
			successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "DELETE", path: "/api/v1/secrets/scoped-syncs/{id}", opID: "removeSecretScopedSync",
			summary: "Remove a scoped sync; the destination keys it wrote stay", handler: a.removeSecretScopedSync,
			pathParams: id, successCode: "204", mutation: true, perm: authz.SecretsWrite},
		{method: "PUT", path: "/api/v1/secrets/scoped-syncs/{id}/mode", opID: "setSecretScopedSyncMode",
			summary: "Set a scoped sync's mode: manual (a reviewed apply), auto (applied when its sources change and nothing is blocked) or approved (as auto, each plan applied once approved)",
			handler: a.setSecretScopedSyncMode, pathParams: id, reqSchema: "SecretScopedSyncModeRequest", resSchema: "SecretScopedSync",
			successCode: "200", mutation: true, perm: authz.SecretsWrite},
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
			"mode":           {Type: "string", Enum: []string{"manual", "auto", scopedSyncModeApproved}},
		}, "name", "source_prefix", "target"),
		"SecretScopedSyncModeRequest": object(map[string]*Schema{
			"mode": {Type: "string", Enum: []string{"manual", "auto", scopedSyncModeApproved}},
		}, "mode"),
		"SecretScopedSync": object(map[string]*Schema{
			"id": str(), "name": str(), "source_prefix": str(), "target": str(), "destination_prefix": str(),
			"key_transform": str(), "delete_scope": str(), "adopt_existing": {Type: "boolean"}, "defined_by": str(),
			"created_at": timestamp(), "updated_at": timestamp(), "last_plan_digest": str(), "last_applied_at": timestamp(),
			"mode": {Type: "string", Enum: []string{"manual", "auto", scopedSyncModeApproved}}, "last_reconcile_at": timestamp(),
			"reconcile_status": {Type: "string", Enum: []string{"applied", "unchanged", "blocked", "failed", scopedSyncAwaitingApproval}}, "reconcile_reason": str(),
			"keys": {Type: "array", Items: key},
		}, "id", "name", "source_prefix", "target", "key_transform", "delete_scope", "adopt_existing", "mode", "created_at", "updated_at"),
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
		Mode: d.Mode, LastReconcileAt: d.LastReconcileAt, ReconcileStatus: d.LastReconcileStatus, ReconcileReason: d.LastReconcileReason,
	}
}

// scopedSyncTarget is the definition's target with its scoped operations. A
// target that can't list its keys takes a scoped sync from its delivery
// receipts only (A237-L2): a key the sync didn't write can't be seen there and
// would be replaced, so the definition must say adopt_existing.
func (a *API) scopedSyncTarget(tenantID, name string, adoptExisting bool) (secretsync.ScopedTarget, error) {
	target := a.secrets.syncTargets(tenantID)[name]
	if target == nil {
		return nil, errStatus(http.StatusBadRequest, "target "+name+" is not a configured secret-sync target")
	}
	if scoped, ok := target.Scoped(); ok {
		return scoped, nil
	}
	if !adoptExisting {
		return nil, errStatus(http.StatusBadRequest, "target "+name+" can't list its keys, so a scoped sync to it works from its delivery receipts only: "+
			"a key this sync didn't write can't be seen and would be replaced. Set adopt_existing to accept that (delete_scope stays none)")
	}
	return target.ScopedFromReceipts(), nil
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
		def, err := a.checkScopedSyncDefinition(ctx, tenantID, req, "")
		if err != nil {
			return 0, nil, err
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		id := googleuuid.NewString()
		if err := a.orch.DefineSecretScopedSync(ctx, tenantID, projections.SecretScopedSyncDefined{
			ID: id, Name: def.Name, SourcePrefix: def.SourcePrefix, Target: def.Target, DestinationPrefix: def.DestinationPrefix,
			KeyTransform: def.KeyTransform, DeleteScope: def.DeleteScope, AdoptExisting: def.AdoptExisting, DefinedBy: subject, Mode: req.Mode,
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

// checkScopedSyncDefinition validates a definition request, for a new
// definition (self "") or a replacement of the one with ID self (A237-L3), and
// returns the canonical definition: the source read by the caller (a
// restricted environment it isn't granted can't be synced out, A235), a
// configured target that lists its keys, and a name no other definition holds.
func (a *API) checkScopedSyncDefinition(ctx context.Context, tenantID string, req secretScopedSyncRequest, self string) (store.SecretScopedSync, error) {
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
		return store.SecretScopedSync{}, errStatus(http.StatusBadRequest, "name is lowercase letters, digits and hyphens (1-63)")
	case !validApplicationSecretImportPath(source) || len(source) > 512:
		return store.SecretScopedSync{}, errStatus(http.StatusBadRequest, "source_prefix is a relative secret path, for example payments/prod/")
	case dest != "" && (!validApplicationSecretImportPath(dest) || len(dest) > 512):
		return store.SecretScopedSync{}, errStatus(http.StatusBadRequest, "destination_prefix is a relative path without empty or dot segments")
	case transform != "path" && transform != "env":
		return store.SecretScopedSync{}, errStatus(http.StatusBadRequest, "key_transform is path or env")
	case req.Mode != "" && !validScopedSyncMode(req.Mode):
		return store.SecretScopedSync{}, errStatus(http.StatusBadRequest, "mode is manual, auto or approved")
	case scope != "none" && scope != "managed" && scope != "prefix":
		return store.SecretScopedSync{}, errStatus(http.StatusBadRequest, "delete_scope is none, managed (keys this sync wrote) or prefix (every key under the destination prefix)")
	}
	scoped, err := a.scopedSyncTarget(tenantID, req.Target, req.AdoptExisting)
	if err != nil {
		return store.SecretScopedSync{}, err
	}
	if !secretsync.ScopedListsKeys(scoped) && scope != "none" {
		// A237-L2: a receipt-only destination can't delete keys.
		return store.SecretScopedSync{}, errStatus(http.StatusBadRequest,
			"target "+req.Target+" can't list or delete its keys, so delete_scope is none: a key whose source is gone is kept")
	}
	// A235: a definition reads its source; a restricted environment the
	// caller isn't granted can't be synced out.
	if ok, err := a.secretScopeAllows(ctx, tenantID, source+"/", false); err != nil {
		return store.SecretScopedSync{}, err
	} else if !ok {
		return store.SecretScopedSync{}, errStatus(http.StatusForbidden, "the source is a restricted environment you are not a member of")
	}
	existing, err := a.store.ListSecretScopedSyncs(ctx, tenantID)
	if err != nil {
		return store.SecretScopedSync{}, err
	}
	for _, d := range existing {
		if d.Name == req.Name && d.ID != self {
			return store.SecretScopedSync{}, errStatus(http.StatusConflict, "a scoped sync named "+req.Name+" already exists")
		}
	}
	return store.SecretScopedSync{
		Name: req.Name, SourcePrefix: source + "/", Target: req.Target, DestinationPrefix: dest,
		KeyTransform: transform, DeleteScope: scope, AdoptExisting: req.AdoptExisting, Mode: req.Mode,
	}, nil
}

// replaceSecretScopedSync replaces a definition in place (A237-L3): the same
// checks as a new one, the same ID and history. A replacement that moves the
// destination (another target, destination prefix or key transform) releases
// the keys the definition managed there, which stay as on removal; one that
// keeps it keeps them managed. A mode left out stays; leaving the approved
// mode needs access:write, as switching does. The replacer becomes the
// definition's author.
//
//trstctl:mutation
func (a *API) replaceSecretScopedSync(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretScopedSyncRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		current, err := a.loadScopedSync(ctx, tenantID, r.PathValue("id"))
		if err != nil {
			return 0, nil, err
		}
		next, err := a.checkScopedSyncDefinition(ctx, tenantID, req, current.ID)
		if err != nil {
			return 0, nil, err
		}
		if next.Mode == "" {
			next.Mode = current.Mode
		}
		if current.Mode == scopedSyncModeApproved && next.Mode != scopedSyncModeApproved {
			if err := requireScopedSyncGateAuthority(ctx, tenantID, "leaving approval-gated convergence"); err != nil {
				return 0, nil, err
			}
		}
		if next.Name == current.Name && next.SourcePrefix == current.SourcePrefix && next.Target == current.Target &&
			next.DestinationPrefix == current.DestinationPrefix && next.KeyTransform == current.KeyTransform &&
			next.DeleteScope == current.DeleteScope && next.AdoptExisting == current.AdoptExisting && next.Mode == current.Mode {
			view, err := a.scopedSyncViewWithKeys(ctx, tenantID, current)
			return http.StatusOK, view, err
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.ReplaceSecretScopedSync(ctx, tenantID, projections.SecretScopedSyncReplaced{
			ID: current.ID, Name: next.Name, SourcePrefix: next.SourcePrefix, Target: next.Target,
			DestinationPrefix: next.DestinationPrefix, KeyTransform: next.KeyTransform, DeleteScope: next.DeleteScope,
			AdoptExisting: next.AdoptExisting, Mode: next.Mode, ReplacedBy: subject,
			ReleaseKeys: next.Target != current.Target || next.DestinationPrefix != current.DestinationPrefix ||
				next.KeyTransform != current.KeyTransform,
		}); err != nil {
			return 0, nil, err
		}
		d, err := a.loadScopedSync(ctx, tenantID, current.ID)
		if err != nil {
			return 0, nil, err
		}
		view, err := a.scopedSyncViewWithKeys(ctx, tenantID, d)
		return http.StatusOK, view, err
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
	view, err := a.scopedSyncViewWithKeys(r.Context(), tenantID, d)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

// scopedSyncViewWithKeys is the definition with the destination keys it
// manages and their delivery status.
func (a *API) scopedSyncViewWithKeys(ctx context.Context, tenantID string, d store.SecretScopedSync) (secretScopedSyncResponse, error) {
	keys, err := a.store.ListSecretScopedSyncKeys(ctx, tenantID, d.ID)
	if err != nil {
		return secretScopedSyncResponse{}, err
	}
	view := scopedSyncView(d)
	for _, k := range keys {
		item := secretScopedSyncKeyResponse{Key: k.RemoteKey, SourceName: k.SourceName, SourceVersion: k.SourceVersion, State: k.State, JobID: k.JobID}
		if k.JobID != "" {
			if job, err := a.secrets.be.Store.GetSecretSyncJob(ctx, tenantID, k.JobID); err == nil {
				item.JobStatus = string(job.Status)
			} else if store.IsNotFound(err) {
				item.JobStatus = "not_queued"
			}
		}
		view.Keys = append(view.Keys, item)
	}
	return view, nil
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
		// A237-L1: an approval-gated definition is not removed (and then
		// defined again ungated) by those it gates.
		if d.Mode == scopedSyncModeApproved {
			if err := requireScopedSyncGateAuthority(ctx, tenantID, "removing an approval-gated scoped sync"); err != nil {
				return 0, nil, err
			}
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

//trstctl:mutation
func (a *API) setSecretScopedSyncMode(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretScopedSyncModeRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if !validScopedSyncMode(req.Mode) {
			return 0, nil, errStatus(http.StatusBadRequest, "mode is manual, auto or approved")
		}
		d, err := a.loadScopedSync(ctx, tenantID, r.PathValue("id"))
		if err != nil {
			return 0, nil, err
		}
		// A237-L1: leaving approval-gated convergence is the tenant
		// administrator's decision, not one the gated members make.
		if d.Mode == scopedSyncModeApproved && req.Mode != scopedSyncModeApproved {
			if err := requireScopedSyncGateAuthority(ctx, tenantID, "leaving approval-gated convergence"); err != nil {
				return 0, nil, err
			}
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if d.Mode != req.Mode {
			if err := a.orch.SetSecretScopedSyncMode(ctx, tenantID, projections.SecretScopedSyncModeSet{ID: d.ID, Mode: req.Mode, SetBy: subject}); err != nil {
				return 0, nil, err
			}
			if d, err = a.loadScopedSync(ctx, tenantID, d.ID); err != nil {
				return 0, nil, err
			}
		}
		return http.StatusOK, scopedSyncView(d), nil
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

// scopedSyncDestinationKey maps a source path under the prefix to its key. A
// flat destination (variable names) joins its prefix without a slash.
func scopedSyncDestinationKey(d store.SecretScopedSync, rel string, flat bool) string {
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
		if flat {
			return d.DestinationPrefix + key
		}
		key = d.DestinationPrefix + "/" + key
	}
	return key
}

// planSecretScopedSync builds the value-free plan. Source values are opened
// only to compare digests with the destination and are wiped at once.
func (a *API) planSecretScopedSync(ctx context.Context, tenantID string, d store.SecretScopedSync) (secretScopedSyncPlan, error) {
	plan := secretScopedSyncPlan{SyncID: d.ID, Name: d.Name, Target: d.Target, Items: []secretScopedSyncItem{}}
	scoped, err := a.scopedSyncTarget(tenantID, d.Target, d.AdoptExisting)
	if err != nil {
		return plan, err
	}
	receiptOnly := !secretsync.ScopedListsKeys(scoped)
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
		if receiptOnly {
			// A237-L2: the destination's known keys are the ones this sync
			// delivered; its other keys can't be listed.
			existing = append(existing, k.RemoteKey)
		}
	}
	if receiptOnly {
		slices.Sort(existing)
	}
	onDestination := map[string]bool{}
	for _, k := range existing {
		onDestination[k] = true
	}
	bySource := map[string][]store.Secret{}
	var planned []string
	for _, src := range sources {
		key := scopedSyncDestinationKey(d, strings.TrimPrefix(src.Name, d.SourcePrefix), secretsync.ScopedFlatKeys(scoped))
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
		case secretsync.ScopedValidKey(scoped, key) != nil:
			item.Action, item.Reason = "blocked", "the target can't hold "+key+": "+secretsync.ScopedValidKey(scoped, key).Error()+scopedSyncKeyHint(d)
		case onDestination[key] && managed[key].RemoteKey == "" && !d.AdoptExisting:
			item.Action, item.Reason = "blocked", "the destination already holds "+key+", which this sync didn't write; set adopt_existing to take it over"
		default:
			action, err := a.scopedSyncWriteAction(ctx, tenantID, scoped, srcs[0], key, onDestination[key], managed[key], digests)
			if err != nil {
				return plan, err
			}
			item.Action = action
			switch {
			case action == "create" && receiptOnly:
				item.Reason = "receipt-only: the target can't list its keys, so a key of this name this sync didn't write would be replaced (adopt_existing)"
			case action == "update" && managed[key].RemoteKey == "":
				item.Reason = "adopted: the destination key was not written by this sync"
			case action == "update" && !secretsync.ScopedReadsBack(scoped):
				item.Reason = "receipt-only: the source changed since its last delivery; the destination's value can't be read back"
			case action == "update" && managed[key].SourceVersion == srcs[0].Version:
				item.Reason = "drift: the destination changed outside this sync"
			case action == "unchanged" && !secretsync.ScopedReadsBack(scoped):
				item.Reason = "receipt-only: this version was delivered; the destination's value can't be read back, so a change made outside this sync can't be seen"
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
		case receiptOnly:
			item.Action, item.Reason = "orphaned", "its source is gone; the target can't delete keys, so it stays"
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
	// The digest binds what the plan means — the definition's route, rules,
	// mode and author, the items and the destination it saw — and not the
	// reconciler's bookkeeping on the definition, which changes on every pass:
	// an approved definition's plan must stay the same plan while it waits for
	// its approvers (A237-L1).
	definition := struct {
		ID                string `json:"id"`
		Name              string `json:"name"`
		SourcePrefix      string `json:"source_prefix"`
		Target            string `json:"target"`
		DestinationPrefix string `json:"destination_prefix"`
		KeyTransform      string `json:"key_transform"`
		DeleteScope       string `json:"delete_scope"`
		AdoptExisting     bool   `json:"adopt_existing"`
		DefinedBy         string `json:"defined_by"`
		Mode              string `json:"mode"`
	}{d.ID, d.Name, d.SourcePrefix, d.Target, d.DestinationPrefix, d.KeyTransform, d.DeleteScope, d.AdoptExisting, d.DefinedBy, d.Mode}
	material, err := json.Marshal(struct {
		Domain     string                 `json:"domain"`
		Definition any                    `json:"definition"`
		Items      []secretScopedSyncItem `json:"items"`
		Digests    map[string]string      `json:"destination_digests"`
		Existing   []string               `json:"existing"`
	}{"trstctl.secret.scoped-sync-plan.v2", definition, plan.Items, digests, existing})
	if err != nil {
		return plan, err
	}
	plan.PlanDigest = crypto.SHA256Hex(material)
	return plan, nil
}

// scopedSyncKeyHint suggests the env transform when a path key is refused.
func scopedSyncKeyHint(d store.SecretScopedSync) string {
	if d.KeyTransform == "env" {
		return ""
	}
	return "; key_transform env makes variable names"
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
	src store.Secret, key string, exists bool, managed store.SecretScopedSyncKey, digests map[string]string) (string, error) {
	if !exists {
		return "create", nil
	}
	if !secretsync.ScopedReadsBack(scoped) {
		// A receipt-only destination: this source version's delivered job is
		// the only evidence of what it holds.
		if managed.RemoteKey != "" && managed.SourceVersion == src.Version && managed.JobID != "" {
			job, err := a.secrets.be.Store.GetSecretSyncJob(ctx, tenantID, managed.JobID)
			if err != nil && !store.IsNotFound(err) {
				return "", err
			}
			if err == nil && job.Status == store.SecretSyncJobDelivered {
				return "unchanged", nil
			}
		}
		return "update", nil
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
	if current != "" && crypto.ConstantTimeEqual([]byte(current), []byte(secretsync.ScopedDigestOf(scoped, plain))) {
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
		// A237-L1: an approved definition applies a plan only with its exact
		// approval, which the event carries for the projection to consume.
		var approval *store.OperationApprovalUse
		if d.Mode == scopedSyncModeApproved {
			if approval, err = a.authorizeScopedSyncApply(ctx, tenantID, d, planDigest); err != nil {
				return receipt, err
			}
		}
		// The reconciler applies an auto definition's plan with no request
		// principal; its applies name it.
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			subject = scopedSyncReconcilerSubject
		}
		applied = projections.SecretScopedSyncApplied{TenantEpoch: epoch, ID: d.ID, Target: d.Target, PlanDigest: planDigest,
			AppliedBy: subject, Items: []projections.SecretScopedSyncAppliedItem{}, Approval: approval}
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

// ScopedSyncReconcileState is the reconciler's memory between ticks: for each
// tenant/definition, the source set and time of its last full plan.
type ScopedSyncReconcileState map[string]ScopedSyncSeen

// ScopedSyncSeen is one definition's last full plan.
type ScopedSyncSeen struct {
	SourceDigest string
	PlannedAt    time.Time
}

// ReconcileScopedSecretSyncs runs one pass over the given tenants' auto scoped
// syncs (A237 continuous mode). A definition is re-planned when its source set
// changed or its drift check is due; a plan with changes and nothing blocked is
// applied exactly as a reviewed apply would be, under the reconciler's name. A
// blocked or failed plan is recorded on the definition and nothing is written.
// It returns how many plans it applied.
func (a *API) ReconcileScopedSecretSyncs(ctx context.Context, tenants []string, state ScopedSyncReconcileState, now time.Time, driftEvery time.Duration) (int, error) {
	if a.secrets == nil || a.store == nil {
		return 0, nil
	}
	applied := 0
	var firstErr error
	for _, tenantID := range tenants {
		defs, err := a.store.ListSecretScopedSyncs(ctx, tenantID)
		if err != nil {
			firstErr = errors.Join(firstErr, err)
			continue
		}
		for _, d := range defs {
			if d.Mode != "auto" && d.Mode != scopedSyncModeApproved {
				continue
			}
			digest, err := a.store.SecretScopedSyncSourceDigest(ctx, tenantID, d.SourcePrefix)
			if err != nil {
				firstErr = errors.Join(firstErr, err)
				continue
			}
			key := tenantID + "/" + d.ID
			// A plan awaiting approval is looked at every pass, so an approval
			// is acted on as soon as it is given.
			awaiting := d.Mode == scopedSyncModeApproved && d.LastReconcileStatus == scopedSyncAwaitingApproval
			if seen, ok := state[key]; ok && !awaiting && seen.SourceDigest == digest && now.Sub(seen.PlannedAt) < driftEvery {
				continue
			}
			state[key] = ScopedSyncSeen{SourceDigest: digest, PlannedAt: now}
			status, reason, planDigest := a.reconcileScopedSync(ctx, tenantID, d)
			if status == "applied" {
				applied++
			}
			if status == "applied" || status != d.LastReconcileStatus || reason != d.LastReconcileReason || digest != d.SourceDigest {
				if err := a.orch.RecordSecretScopedSyncReconciled(ctx, tenantID, projections.SecretScopedSyncReconciled{
					ID: d.ID, Status: status, Reason: reason, PlanDigest: planDigest, SourceDigest: digest,
				}); err != nil {
					firstErr = errors.Join(firstErr, err)
				}
			}
		}
	}
	return applied, firstErr
}

// reconcileScopedSync plans one auto definition and applies the plan when it
// has changes and nothing blocked. Reasons are a closed set (no target text).
func (a *API) reconcileScopedSync(ctx context.Context, tenantID string, d store.SecretScopedSync) (status, reason, planDigest string) {
	plan, err := a.planSecretScopedSync(ctx, tenantID, d)
	switch {
	case err != nil:
		return "failed", "the plan could not be made; preview it to see why", ""
	case plan.Blocked > 0:
		return "blocked", strconv.Itoa(plan.Blocked) + " blocked items; review the plan and apply it yourself", plan.PlanDigest
	case plan.Changes == 0:
		return "unchanged", "", plan.PlanDigest
	}
	if _, err := a.executeSecretScopedSync(ctx, tenantID, d, plan.PlanDigest); err != nil {
		var wait *scopedSyncApprovalWait
		if errors.As(err, &wait) {
			if wait.terminal {
				return "blocked", "the plan's approval request " + wait.requestID + " was denied, expired or used; a changed plan asks again", plan.PlanDigest
			}
			return scopedSyncAwaitingApproval, strconv.Itoa(plan.Changes) + " changes await approval request " + wait.requestID, plan.PlanDigest
		}
		return "failed", "the plan could not be applied; preview it to see why", plan.PlanDigest
	}
	return "applied", strconv.Itoa(plan.Changes) + " changes applied", plan.PlanDigest
}

// scopedSyncApprovalWait is an approved definition's plan without its approval
// yet (A237-L1): the apply route answers its 403; the reconciler records the
// request it waits for, or that the request can no longer approve this plan.
type scopedSyncApprovalWait struct {
	requestID string
	terminal  bool
	cause     error
}

func (e *scopedSyncApprovalWait) Error() string { return e.cause.Error() }
func (e *scopedSyncApprovalWait) Unwrap() error { return e.cause }

// requireScopedSyncGateAuthority is access:write, for what would lift an
// approval gate (A237-L1).
func requireScopedSyncGateAuthority(ctx context.Context, tenantID, what string) error {
	principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if !principal.Can(authz.AccessWrite, authz.Scope{TenantID: tenantID}) {
		return errStatus(http.StatusForbidden, what+" needs access:write")
	}
	return nil
}

// authorizeScopedSyncApply asks for, or finds, the exact approval of an
// approved definition's plan (A237-L1). A manual apply asks as its caller; the
// reconciler, which has no caller, asks as the definition's author. Either way
// the requester cannot approve its own request, and the approvers are members
// who write in the source's environment. Until approved, the answer is 403
// naming the request.
func (a *API) authorizeScopedSyncApply(ctx context.Context, tenantID string, d store.SecretScopedSync, planDigest string) (*store.OperationApprovalUse, error) {
	if a.gate.Checker == nil {
		return nil, errStatus(http.StatusForbidden, "an approval-gated scoped sync needs the approval store, and none is configured")
	}
	exact, ok := a.gate.Checker.(ExactApprovalChecker)
	if !ok {
		return nil, errStatus(http.StatusForbidden, "an approval-gated scoped sync needs exact single-use approval authority")
	}
	destination := d.Target
	if d.DestinationPrefix != "" {
		destination += "/" + d.DestinationPrefix
	}
	requester := d.DefinedBy
	if subject, err := requestPrincipalSubject(ctx); err == nil {
		requester = subject
	}
	intent := ApprovalIntent{
		TenantID: tenantID, ResourceKind: scopedSyncApprovalKind, ResourceID: d.ID,
		ResourceName: d.Name + ": " + d.SourcePrefix + " to " + destination, Action: "apply", Requester: requester,
		FromState: "plan:" + planDigest, ToState: destination, TargetVersion: 1,
		Reason:       "apply scoped sync " + d.Name + " by the plan " + planDigest,
		EvidenceRefs: []string{"plan_digest:" + planDigest, scopedSyncSourceEvidence + d.SourcePrefix},
	}
	authority, approved, reason := exact.AuthorizeApproval(ctx, intent)
	if authority.RequestID == "" || authority.IntentDigest == "" ||
		authority.Requester != intent.Requester || authority.ResourceKind != intent.ResourceKind ||
		authority.ResourceID != intent.ResourceID || authority.Action != intent.Action ||
		authority.FromState != intent.FromState || authority.ToState != intent.ToState ||
		authority.TargetVersion != intent.TargetVersion || authority.RequiredApprovals <= 0 {
		return nil, approvalAPIError(store.ErrApprovalDrifted)
	}
	if !approved {
		if reason == "" {
			reason = "this exact plan awaits its approvers"
		}
		return nil, &scopedSyncApprovalWait{requestID: authority.RequestID, terminal: authority.Disposition.Terminal(),
			cause: errStatus(http.StatusForbidden, fmt.Sprintf("dual control: approval_required:%s request_id=%s intent_digest=%s: %s",
				d.ID, authority.RequestID, authority.IntentDigest, reason))}
	}
	return &store.OperationApprovalUse{
		RequestID: authority.RequestID, IntentDigest: authority.IntentDigest,
		Requester: authority.Requester, ResourceKind: authority.ResourceKind,
		ResourceID: authority.ResourceID, Action: authority.Action,
		FromState: authority.FromState, ToState: authority.ToState,
		TargetVersion: authority.TargetVersion, RequiredApprovals: authority.RequiredApprovals,
		Reason: authority.Reason, EvidenceRefs: authority.EvidenceRefs,
	}, nil
}

// scopedSyncSourceEvidence prefixes the evidence ref naming an approved
// definition's source prefix, which the approval routes check the approver's
// grant against.
const scopedSyncSourceEvidence = "source:"
