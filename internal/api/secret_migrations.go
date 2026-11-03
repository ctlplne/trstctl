// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretmigrate"
	"trstctl.com/trstctl/internal/store"
)

// A243: migrating secrets from another system's export, and coexisting with
// it until its consumers move. A run starts with a value-free assessment of
// the export (dotenv, JSON or YAML, per environment and folder); staging
// imports its values by the assessment's digest as new versions while the
// export's system stays each secret's one writer (the store refuses its own
// writes to them); the translated permissions are applied separately, under
// access:write; each consumer's first read from the store is recorded; cutover
// needs every consumer to have read; a credential the export could not carry
// is reissued, never counted as migrated; and the run keeps the rollback
// manifest — every version it found — to undo itself.

// secretMigrationStageLimit is the most secrets one stage writes: one
// versioned batch.
const secretMigrationStageLimit = 100

type secretMigrationRequest struct {
	MigrationID            string   `json:"migration_id,omitempty"`
	PlanDigest             string   `json:"plan_digest,omitempty"`
	AcceptOpenEnvironments []string `json:"accept_open_environments,omitempty"`
	secretmigrate.Bundle
}

type secretMigrationObjectResponse struct {
	Name            string `json:"name"`
	Outcome         string `json:"outcome"`
	PriorVersion    int    `json:"prior_version"`
	Version         int    `json:"version"`
	Writer          string `json:"writer"`
	Rollback        string `json:"rollback,omitempty"`
	RollbackVersion int    `json:"rollback_version,omitempty"`
}

type secretMigrationConsumerStatus struct {
	Name    string   `json:"name"`
	Subject string   `json:"subject"`
	Secrets []string `json:"secrets"`
	Read    []string `json:"read"`
	Pending []string `json:"pending"`
	Problem string   `json:"problem,omitempty"`
}

type secretMigrationResponse struct {
	ID                 string                          `json:"id"`
	Project            string                          `json:"project"`
	State              string                          `json:"state"`
	Digest             string                          `json:"digest"`
	Plan               json.RawMessage                 `json:"plan"`
	AcceptedOpen       []string                        `json:"accepted_open"`
	CreatedBy          string                          `json:"created_by,omitempty"`
	CreatedAt          time.Time                       `json:"created_at"`
	StagedAt           *time.Time                      `json:"staged_at,omitempty"`
	CutOverAt          *time.Time                      `json:"cut_over_at,omitempty"`
	CutOverBy          string                          `json:"cut_over_by,omitempty"`
	RolledBackAt       *time.Time                      `json:"rolled_back_at,omitempty"`
	PermissionsApplied json.RawMessage                 `json:"permissions_applied"`
	Objects            []secretMigrationObjectResponse `json:"objects"`
	Consumers          []secretMigrationConsumerStatus `json:"consumers"`
}

type secretMigrationListResponse struct {
	Items []secretMigrationResponse `json:"items"`
}

func (a *API) secretMigrationRoutes() []route {
	id := []param{pathString("id", "secret migration ID")}
	return []route{
		{method: "POST", path: "/api/v1/secrets/migrations/assess", opID: "assessSecretMigration",
			summary: "Assess an export (dotenv, JSON or YAML per environment and folder) as a migration run: a value-free plan and its digest",
			handler: a.assessSecretMigration, reqSchema: "SecretMigrationRequest", resSchema: "SecretMigration",
			successCode: "201", mutation: true, perm: authz.SecretsWrite},
		{method: "GET", path: "/api/v1/secrets/migrations", opID: "listSecretMigrations",
			summary: "List secret migration runs, newest first", handler: a.listSecretMigrations,
			resSchema: "SecretMigrationList", successCode: "200", perm: authz.SecretsRead},
		{method: "GET", path: "/api/v1/secrets/migrations/{id}", opID: "getSecretMigration",
			summary: "Show a migration run: its plan, the rollback manifest, each secret's writer and the consumers' reads",
			handler: a.getSecretMigration, pathParams: id, resSchema: "SecretMigration", successCode: "200", perm: authz.SecretsRead},
		{method: "POST", path: "/api/v1/secrets/migrations/{id}/stage", opID: "stageSecretMigration",
			summary: "Import the assessed export by its plan digest as new versions; the export's system stays each secret's writer until cutover",
			handler: a.stageSecretMigration, pathParams: id, reqSchema: "SecretMigrationRequest", resSchema: "SecretMigration",
			successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/migrations/{id}/permissions", opID: "applySecretMigrationPermissions",
			summary: "Apply the run's translated permissions as project memberships; held ones stay for review",
			handler: a.applySecretMigrationPermissions, pathParams: id, resSchema: "SecretMigration",
			successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "POST", path: "/api/v1/secrets/migrations/{id}/cutover", opID: "cutOverSecretMigration",
			summary: "Hand the staged secrets' writing to the store once every consumer has read them from it",
			handler: a.cutOverSecretMigration, pathParams: id, reqSchema: "SecretMigrationCutOverRequest", resSchema: "SecretMigration",
			successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/migrations/{id}/reissue", opID: "reissueSecretMigrationCredentials",
			summary: "Issue new values for credentials the export could not carry; they are reissued, never counted as migrated",
			handler: a.reissueSecretMigrationCredentials, pathParams: id, reqSchema: "SecretMigrationReissueRequest", resSchema: "SecretMigration",
			successCode: "200", mutation: true, perm: authz.SecretsWrite},
		{method: "POST", path: "/api/v1/secrets/migrations/{id}/rollback", opID: "rollBackSecretMigration",
			summary: "Undo a run from its manifest: restore the versions it found, delete what it created, keep what changed since",
			handler: a.rollBackSecretMigration, pathParams: id, resSchema: "SecretMigration",
			successCode: "200", mutation: true, perm: authz.SecretsWrite},
	}
}

func secretMigrationSchemas() map[string]*Schema {
	strs := &Schema{Type: "array", Items: str()}
	source := object(map[string]*Schema{
		"environment": str(), "folder": str(),
		"format":  {Type: "string", Enum: []string{secretmigrate.FormatDotenv, secretmigrate.FormatJSON, secretmigrate.FormatYAML}},
		"content": str(),
	}, "environment", "format", "content")
	permission := object(map[string]*Schema{
		"subject": str(), "environment": str(), "folder": str(),
		"access": {Type: "string", Enum: []string{"read", "write", "admin"}},
	}, "subject", "environment", "access")
	consumer := object(map[string]*Schema{
		"name": str(), "subject": str(), "environment": str(), "secrets": strs,
	}, "name", "subject", "environment")
	object_ := object(map[string]*Schema{
		"name": str(), "outcome": {Type: "string", Enum: []string{store.SecretMigrationMigrated, store.SecretMigrationReissued}},
		"prior_version": {Type: "integer"}, "version": {Type: "integer"},
		"writer":           {Type: "string", Enum: []string{store.SecretMigrationWriterSource, store.SecretMigrationWriterStore}},
		"rollback":         {Type: "string", Enum: []string{store.SecretMigrationRollbackRestored, store.SecretMigrationRollbackDeleted, store.SecretMigrationRollbackKept}},
		"rollback_version": {Type: "integer"},
	}, "name", "outcome", "prior_version", "version", "writer")
	consumerStatus := object(map[string]*Schema{
		"name": str(), "subject": str(), "secrets": strs, "read": strs, "pending": strs, "problem": str(),
	}, "name", "subject", "secrets", "read", "pending")
	return map[string]*Schema{
		"SecretMigrationRequest": object(map[string]*Schema{
			"migration_id": str(), "plan_digest": str(), "accept_open_environments": strs,
			"project": str(), "sources": {Type: "array", Items: source},
			"permissions": {Type: "array", Items: permission}, "consumers": {Type: "array", Items: consumer},
		}, "project", "sources"),
		"SecretMigrationCutOverRequest": object(map[string]*Schema{"no_consumers": {Type: "boolean"}}),
		"SecretMigrationReissueRequest": object(map[string]*Schema{"names": strs}, "names"),
		"SecretMigration": object(map[string]*Schema{
			"id": str(), "project": str(),
			"state":  {Type: "string", Enum: []string{store.SecretMigrationAssessed, store.SecretMigrationStaged, store.SecretMigrationCutOver, store.SecretMigrationRolledBack}},
			"digest": str(), "plan": {Type: "object", Description: "the value-free assessment"},
			"accepted_open": strs, "created_by": str(), "created_at": timestamp(), "staged_at": timestamp(),
			"cut_over_at": timestamp(), "cut_over_by": str(), "rolled_back_at": timestamp(),
			"permissions_applied": {Type: "array", Items: &Schema{Type: "object"}},
			"objects":             {Type: "array", Items: object_}, "consumers": {Type: "array", Items: consumerStatus},
		}, "id", "project", "state", "digest", "plan", "accepted_open", "created_at", "permissions_applied", "objects", "consumers"),
		"SecretMigrationList": object(map[string]*Schema{"items": {Type: "array", Items: ref("SecretMigration")}}, "items"),
	}
}

// decodeSecretMigrationRequest reads a request whose sources hold values; the
// caller wipes it.
func decodeSecretMigrationRequest(r *http.Request) (req secretMigrationRequest, err error) {
	defer func() {
		if err != nil {
			req.Wipe()
		}
	}()
	err = decodeJSON(r, &req)
	return req, err
}

// planSecretMigration parses and assesses req against the store as the
// caller sees it, and returns the parsed export (holding values: the caller
// wipes it), the assessment and its digest.
func (a *API) planSecretMigration(ctx context.Context, tenantID string, req *secretMigrationRequest, migrationID string, acceptOpen []string) (*secretmigrate.Parsed, secretmigrate.Assessment, string, error) {
	parsed, err := secretmigrate.Parse(&req.Bundle)
	if err != nil {
		return nil, secretmigrate.Assessment{}, "", errStatusFrom(http.StatusUnprocessableEntity, err)
	}
	_, envs, members, err := a.store.GetSecretProject(ctx, tenantID, req.Project)
	if err != nil {
		parsed.Wipe()
		if store.IsNotFound(err) {
			return nil, secretmigrate.Assessment{}, "", errStatus(http.StatusUnprocessableEntity,
				"create project "+req.Project+" and its environments before migrating into it")
		}
		return nil, secretmigrate.Assessment{}, "", err
	}
	dest := secretmigrate.Destination{
		Environments: map[string]secretmigrate.EnvironmentState{}, Versions: map[string]int{}, Members: map[string]secretmigrate.Member{},
	}
	for _, e := range envs {
		dest.Environments[e.Slug] = secretmigrate.EnvironmentState{Restricted: e.Restricted}
	}
	for _, m := range members {
		dest.Members[m.Subject] = secretmigrate.Member{Role: m.Role, Environments: m.Environments}
	}
	for _, o := range parsed.Objects {
		if rec, err := a.secrets.be.Store.GetSecret(ctx, tenantID, o.Name); err == nil {
			dest.Versions[o.Name] = rec.Version
		} else if !errors.Is(err, store.ErrSecretNotFound) {
			parsed.Wipe()
			return nil, secretmigrate.Assessment{}, "", err
		}
	}
	dest.Exists = func(name string) bool {
		if a.requireSecretRead(ctx, tenantID, name) != nil {
			return false
		}
		_, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name)
		return err == nil
	}
	plan := secretmigrate.Assess(parsed, &req.Bundle, dest, acceptOpen)
	// What the store adds: an environment the caller may not write, and one
	// writer per secret — a name another run's export system still writes.
	for i := range plan.Objects {
		o := &plan.Objects[i]
		if o.Action == secretmigrate.ActionBlocked {
			continue
		}
		if ok, err := a.secretScopeAllows(ctx, tenantID, o.Name, true); err != nil {
			parsed.Wipe()
			return nil, secretmigrate.Assessment{}, "", err
		} else if !ok {
			blockObject(&plan, i, "you may not write environment "+o.Environment)
			continue
		}
		writer, err := a.store.SecretMigrationSourceWriter(ctx, tenantID, o.Name)
		if err != nil {
			parsed.Wipe()
			return nil, secretmigrate.Assessment{}, "", err
		}
		if writer != "" && writer != migrationID {
			blockObject(&plan, i, "migration "+writer+" still has its export's system writing this secret")
		}
	}
	input := secretmigrate.DigestInput(plan, parsed)
	defer secret.Wipe(input)
	mac, err := a.secrets.be.CommandMAC([]byte("trstctl.api.secret-migration-plan.v1"), append([]byte(tenantID+"\x00"), input...))
	if err != nil {
		parsed.Wipe()
		return nil, secretmigrate.Assessment{}, "", err
	}
	digest := hex.EncodeToString(mac)
	secret.Wipe(mac)
	return parsed, plan, digest, nil
}

func blockObject(plan *secretmigrate.Assessment, i int, reason string) {
	o := &plan.Objects[i]
	switch o.Action {
	case secretmigrate.ActionImport:
		plan.Counts.Import--
	case secretmigrate.ActionReissue:
		plan.Counts.Reissue--
	}
	o.Action, o.Reason = secretmigrate.ActionBlocked, reason
	plan.Counts.Blocked++
}

//trstctl:mutation
func (a *API) assessSecretMigration(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	req, err := decodeSecretMigrationRequest(r)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer req.Wipe()
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		id := strings.TrimSpace(req.MigrationID)
		status := http.StatusCreated
		if id != "" {
			run, err := a.store.GetSecretMigration(ctx, tenantID, id)
			if err != nil {
				return 0, nil, secretMigrationLookupError(err)
			}
			if run.Project != req.Project || (run.State != store.SecretMigrationAssessed && run.State != store.SecretMigrationStaged) {
				return 0, nil, errStatus(http.StatusConflict, "a run is re-assessed for the same project while it is assessed or staged")
			}
			status = http.StatusOK
		} else {
			id = googleuuid.NewString()
		}
		parsed, plan, digest, err := a.planSecretMigration(ctx, tenantID, &req, id, req.AcceptOpenEnvironments)
		if err != nil {
			return 0, nil, err
		}
		parsed.Wipe()
		principal, _ := requestPrincipalSubject(ctx)
		if err := a.orch.RecordSecretMigrationEvent(ctx, tenantID, projections.EventSecretMigrationAssessed, id+"\x00"+digest,
			projections.SecretMigrationAssessed{ID: id, Project: req.Project, Digest: digest, Plan: plan,
				AcceptedOpen: sortedUnique(req.AcceptOpenEnvironments), By: principal}); err != nil {
			return 0, nil, err
		}
		resp, err := a.secretMigrationView(ctx, tenantID, id)
		return status, resp, err
	})
}

//trstctl:mutation
func (a *API) stageSecretMigration(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	id := r.PathValue("id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	req, err := decodeSecretMigrationRequest(r)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer req.Wipe()
	if _, err := hex.DecodeString(req.PlanDigest); err != nil || len(req.PlanDigest) != 64 {
		a.writeError(w, errStatus(http.StatusBadRequest, "plan_digest from the run's assessment is required"))
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
	keyDigest, binding, err := a.applicationSecretRequestBinding(tenantID, idempotencyKey, principal, r.Method,
		r.URL.EscapedPath(), "migrate", "native", id, struct {
			Digest string `json:"plan_digest"`
		}{req.PlanDigest})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, binding, func(ctx context.Context, authorized string) (int, any, error) {
		if authorized != tenantID {
			return 0, nil, errors.New("api: secret migration tenant changed")
		}
		run, err := a.store.GetSecretMigration(ctx, tenantID, id)
		if err != nil {
			return 0, nil, secretMigrationLookupError(err)
		}
		if run.State != store.SecretMigrationAssessed && run.State != store.SecretMigrationStaged {
			return 0, nil, errStatus(http.StatusConflict, "a run stages while it is assessed or staged; this one is "+run.State)
		}
		if req.PlanDigest != run.Digest || req.Project != run.Project {
			return 0, nil, &apiError{status: http.StatusConflict,
				detail: "the plan digest is not this run's current assessment: assess again and stage its digest",
				ext:    map[string]any{"code": "plan_stale"}}
		}
		return withStoredSecretCreationFence(ctx, tenantID, func(work context.Context) (int, any, error) {
			var written []projections.SecretMigrationVersion
			receipt, err := a.executeSecretVersionBatch(work, tenantID, store.ApplicationSecretBatchMigration,
				idempotencyKey, keyDigest, binding, run.Digest,
				func(ctx context.Context) ([]projections.ApplicationSecretBatchVersionItem, int, error) {
					items, creates, versions, err := a.sealSecretMigration(ctx, tenantID, &req, run)
					written = versions
					return items, creates, err
				})
			if err != nil {
				return 0, nil, err
			}
			if receipt.BatchID != "" {
				if written == nil {
					// A replay completed from the batch's receipt.
					for _, item := range receipt.Items {
						written = append(written, projections.SecretMigrationVersion{Name: item.Name, PriorVersion: item.Version - 1, Version: item.Version})
					}
				}
				if err := a.orch.RecordSecretMigrationEvent(ctx, tenantID, projections.EventSecretMigrationStaged, id+"\x00"+receipt.BatchID,
					projections.SecretMigrationStaged{ID: id, BatchID: receipt.BatchID, Items: written, By: principal}); err != nil {
					return 0, nil, err
				}
			}
			resp, err := a.secretMigrationView(ctx, tenantID, id)
			return http.StatusOK, resp, err
		})
	})
}

// sealSecretMigration re-assesses the export, refuses a stale or blocked
// plan, and seals each value to import. A value this run already staged and
// unchanged is not written again.
func (a *API) sealSecretMigration(
	ctx context.Context, tenantID string, req *secretMigrationRequest, run store.SecretMigration,
) ([]projections.ApplicationSecretBatchVersionItem, int, []projections.SecretMigrationVersion, error) {
	parsed, plan, digest, err := a.planSecretMigration(ctx, tenantID, req, run.ID, run.AcceptedOpen)
	if err != nil {
		return nil, 0, nil, err
	}
	defer parsed.Wipe()
	if digest != run.Digest {
		return nil, 0, nil, &apiError{status: http.StatusConflict,
			detail: "the export or the store changed since the assessment: assess again and stage its digest",
			ext:    map[string]any{"code": "plan_stale"}}
	}
	values := map[string][]byte{}
	for _, o := range parsed.Objects {
		values[o.Name] = o.Value
	}
	staged := map[string]store.SecretMigrationObject{}
	for _, o := range run.Objects {
		staged[o.Name] = o
	}
	var items []projections.ApplicationSecretBatchVersionItem
	var versions []projections.SecretMigrationVersion
	creates := 0
	for _, o := range plan.Objects {
		if o.Action != secretmigrate.ActionImport {
			continue
		}
		if prior, ok := staged[o.Name]; ok && prior.Version == o.ExistingVersion {
			current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, o.Name)
			if err != nil {
				return nil, 0, nil, err
			}
			plain, err := a.secrets.open(ctx, tenantID, current.Sealed, sealAAD(tenantID, o.Name))
			if err != nil {
				return nil, 0, nil, err
			}
			same := crypto.ConstantTimeEqual(plain, values[o.Name])
			secret.Wipe(plain)
			if same {
				continue
			}
		}
		if len(items) == secretMigrationStageLimit {
			return nil, 0, nil, errStatus(http.StatusUnprocessableEntity, fmt.Sprintf(
				"a stage writes at most %d secrets: assess each environment or folder as its own run", secretMigrationStageLimit))
		}
		sealed, err := a.secrets.seal(ctx, tenantID, values[o.Name], sealAAD(tenantID, o.Name))
		if err != nil {
			return nil, 0, nil, err
		}
		items = append(items, projections.ApplicationSecretBatchVersionItem{
			Name: o.Name, ExpectedVersion: o.ExistingVersion, ResultVersion: o.ExistingVersion + 1, Sealed: sealed,
			SourceName: "migration:" + run.ID, SourceVersion: 1,
		})
		versions = append(versions, projections.SecretMigrationVersion{Name: o.Name, PriorVersion: o.ExistingVersion, Version: o.ExistingVersion + 1})
		if o.ExistingVersion == 0 {
			creates++
		}
	}
	slices.SortFunc(items, func(x, y projections.ApplicationSecretBatchVersionItem) int { return strings.Compare(x.Name, y.Name) })
	return items, creates, versions, nil
}

//trstctl:mutation
func (a *API) applySecretMigrationPermissions(w http.ResponseWriter, r *http.Request) {
	if a.store == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		run, err := a.store.GetSecretMigration(ctx, tenantID, id)
		if err != nil {
			return 0, nil, secretMigrationLookupError(err)
		}
		if run.State == store.SecretMigrationRolledBack {
			return 0, nil, errStatus(http.StatusConflict, "the run was rolled back")
		}
		var plan secretmigrate.Assessment
		if err := json.Unmarshal(run.Plan, &plan); err != nil {
			return 0, nil, err
		}
		_, _, members, err := a.store.GetSecretProject(ctx, tenantID, run.Project)
		if err != nil {
			return 0, nil, err
		}
		existing := map[string]bool{}
		for _, m := range members {
			existing[m.Subject] = true
		}
		principal, _ := requestPrincipalSubject(ctx)
		var grants []projections.SecretMigrationGrant
		seen := map[string]bool{}
		for _, perm := range plan.Permissions {
			// Only a translated grant is applied, and only to a subject with no
			// membership yet: one that gained one since the assessment is left
			// for review rather than overwritten.
			if perm.Status != secretmigrate.PermissionTranslated || seen[perm.Subject] || existing[perm.Subject] {
				continue
			}
			seen[perm.Subject] = true
			if err := a.orch.GrantSecretProjectMember(ctx, tenantID, projections.SecretProjectMemberGranted{
				Project: run.Project, Subject: perm.Subject, Role: perm.Role, Environments: perm.Environments, GrantedBy: principal,
			}); err != nil {
				return 0, nil, err
			}
			grants = append(grants, projections.SecretMigrationGrant{Subject: perm.Subject, Role: perm.Role, Environments: perm.Environments})
		}
		if len(grants) > 0 {
			if err := a.orch.RecordSecretMigrationEvent(ctx, tenantID, projections.EventSecretMigrationPermissionsApplied,
				id+"\x00"+r.Header.Get("Idempotency-Key"), projections.SecretMigrationPermissionsApplied{ID: id, Grants: grants, By: principal}); err != nil {
				return 0, nil, err
			}
		}
		resp, err := a.secretMigrationView(ctx, tenantID, id)
		return http.StatusOK, resp, err
	})
}

//trstctl:mutation
func (a *API) cutOverSecretMigration(w http.ResponseWriter, r *http.Request) {
	if a.store == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	id := r.PathValue("id")
	var req struct {
		NoConsumers bool `json:"no_consumers"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			a.writeError(w, errWithStatus(http.StatusBadRequest, err))
			return
		}
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		view, err := a.secretMigrationView(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if view.State == store.SecretMigrationCutOver {
			return http.StatusOK, view, nil
		}
		if view.State != store.SecretMigrationStaged {
			return 0, nil, errStatus(http.StatusConflict, "a run cuts over once staged; this one is "+view.State)
		}
		if len(view.Consumers) == 0 && !req.NoConsumers {
			return 0, nil, errStatus(http.StatusConflict,
				"the run names no consumers: list them in the assessment, or cut over with no_consumers true")
		}
		var pending []string
		for _, c := range view.Consumers {
			if c.Problem != "" || len(c.Pending) > 0 {
				pending = append(pending, c.Name)
			}
		}
		if len(pending) > 0 {
			return 0, nil, &apiError{status: http.StatusConflict,
				detail: "consumers have not read every secret from the store yet: " + strings.Join(pending, ", "),
				ext:    map[string]any{"code": "consumers_pending", "consumers": view.Consumers}}
		}
		principal, _ := requestPrincipalSubject(ctx)
		if err := a.orch.RecordSecretMigrationEvent(ctx, tenantID, projections.EventSecretMigrationCutOver, id,
			projections.SecretMigrationCutOver{ID: id, By: principal}); err != nil {
			return 0, nil, err
		}
		resp, err := a.secretMigrationView(ctx, tenantID, id)
		return http.StatusOK, resp, err
	})
}

//trstctl:mutation
func (a *API) reissueSecretMigrationCredentials(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	id := r.PathValue("id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req struct {
		Names []string `json:"names"`
	}
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	names := sortedUnique(req.Names)
	if len(names) == 0 || len(names) > secretMigrationStageLimit {
		a.writeError(w, errStatus(http.StatusBadRequest, fmt.Sprintf("names lists 1 to %d credentials to reissue", secretMigrationStageLimit)))
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
	keyDigest, binding, err := a.applicationSecretRequestBinding(tenantID, idempotencyKey, principal, r.Method,
		r.URL.EscapedPath(), "migrate-reissue", "native", id, names)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, binding, func(ctx context.Context, authorized string) (int, any, error) {
		if authorized != tenantID {
			return 0, nil, errors.New("api: secret migration tenant changed")
		}
		run, err := a.store.GetSecretMigration(ctx, tenantID, id)
		if err != nil {
			return 0, nil, secretMigrationLookupError(err)
		}
		if run.State == store.SecretMigrationRolledBack {
			return 0, nil, errStatus(http.StatusConflict, "the run was rolled back")
		}
		var plan secretmigrate.Assessment
		if err := json.Unmarshal(run.Plan, &plan); err != nil {
			return 0, nil, err
		}
		reissuable := map[string]bool{}
		for _, o := range plan.Objects {
			reissuable[o.Name] = o.Action == secretmigrate.ActionReissue
		}
		for _, o := range run.Objects {
			if o.Outcome == store.SecretMigrationReissued {
				reissuable[o.Name] = false
			}
		}
		var written []projections.SecretMigrationVersion
		receipt, err := a.executeSecretVersionBatch(ctx, tenantID, store.ApplicationSecretBatchMigration,
			idempotencyKey, keyDigest, binding, run.Digest,
			func(ctx context.Context) ([]projections.ApplicationSecretBatchVersionItem, int, error) {
				var items []projections.ApplicationSecretBatchVersionItem
				creates := 0
				for _, name := range names {
					if !reissuable[name] {
						return nil, 0, errStatus(http.StatusConflict, name+" is not a credential this run plans to reissue, or it was reissued already")
					}
					if ok, err := a.secretScopeAllows(ctx, tenantID, name, true); err != nil || !ok {
						return nil, 0, errStatus(http.StatusForbidden, "you may not write "+name)
					}
					version := 0
					if rec, err := a.secrets.be.Store.GetSecret(ctx, tenantID, name); err == nil {
						version = rec.Version
					} else if !errors.Is(err, store.ErrSecretNotFound) {
						return nil, 0, err
					}
					value, err := newReissuedCredential()
					if err != nil {
						return nil, 0, err
					}
					sealed, err := a.secrets.seal(ctx, tenantID, value, sealAAD(tenantID, name))
					secret.Wipe(value)
					if err != nil {
						return nil, 0, err
					}
					items = append(items, projections.ApplicationSecretBatchVersionItem{
						Name: name, ExpectedVersion: version, ResultVersion: version + 1, Sealed: sealed,
						SourceName: "migration:" + id + ":reissue", SourceVersion: 1,
					})
					written = append(written, projections.SecretMigrationVersion{Name: name, PriorVersion: version, Version: version + 1})
					if version == 0 {
						creates++
					}
				}
				return items, creates, nil
			})
		if err != nil {
			return 0, nil, err
		}
		if receipt.BatchID != "" {
			if written == nil {
				for _, item := range receipt.Items {
					written = append(written, projections.SecretMigrationVersion{Name: item.Name, PriorVersion: item.Version - 1, Version: item.Version})
				}
			}
			if err := a.orch.RecordSecretMigrationEvent(ctx, tenantID, projections.EventSecretMigrationReissued, id+"\x00"+receipt.BatchID,
				projections.SecretMigrationReissued{ID: id, BatchID: receipt.BatchID, Items: written, By: principal}); err != nil {
				return 0, nil, err
			}
		}
		resp, err := a.secretMigrationView(ctx, tenantID, id)
		return http.StatusOK, resp, err
	})
}

// newReissuedCredential is a new random credential: 32 bytes, base64url.
func newReissuedCredential() ([]byte, error) {
	raw, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(out, raw)
	return out, nil
}

//trstctl:mutation
func (a *API) rollBackSecretMigration(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	id := r.PathValue("id")
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
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	keyDigest, binding, err := a.applicationSecretRequestBinding(tenantID, idempotencyKey, principal, r.Method,
		r.URL.EscapedPath(), "migrate-rollback", "native", id, nil)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, binding, func(ctx context.Context, authorized string) (int, any, error) {
		if authorized != tenantID {
			return 0, nil, errors.New("api: secret migration tenant changed")
		}
		run, err := a.store.GetSecretMigration(ctx, tenantID, id)
		if err != nil {
			return 0, nil, secretMigrationLookupError(err)
		}
		if run.State == store.SecretMigrationRolledBack {
			resp, err := a.secretMigrationView(ctx, tenantID, id)
			return http.StatusOK, resp, err
		}
		// Restores go in one versioned batch: a secret still at the version the
		// run wrote gets the version the run found back. What the batch
		// restored is read from its receipt, so a retried rollback that finds
		// the batch done classifies the same way.
		var restores, deletes []store.SecretMigrationObject
		for _, o := range run.Objects {
			if o.PriorVersion == 0 {
				deletes = append(deletes, o)
			} else {
				restores = append(restores, o)
			}
		}
		receipt, err := a.executeSecretVersionBatch(ctx, tenantID, store.ApplicationSecretBatchMigration,
			idempotencyKey, keyDigest, binding, run.Digest,
			func(ctx context.Context) ([]projections.ApplicationSecretBatchVersionItem, int, error) {
				var items []projections.ApplicationSecretBatchVersionItem
				for _, o := range restores {
					current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, o.Name)
					if errors.Is(err, store.ErrSecretNotFound) {
						continue
					} else if err != nil {
						return nil, 0, err
					}
					if current.Version != o.Version {
						continue // written after the run wrote it: kept
					}
					prior, err := a.secrets.be.Store.GetSecretVersion(ctx, tenantID, o.Name, o.PriorVersion)
					if err != nil {
						return nil, 0, err
					}
					items = append(items, projections.ApplicationSecretBatchVersionItem{
						Name: o.Name, ExpectedVersion: current.Version, ResultVersion: current.Version + 1, Sealed: prior.Sealed,
						SourceName: "migration:" + id + ":rollback", SourceVersion: o.PriorVersion,
					})
				}
				slices.SortFunc(items, func(x, y projections.ApplicationSecretBatchVersionItem) int { return strings.Compare(x.Name, y.Name) })
				return items, 0, nil
			})
		if err != nil {
			return 0, nil, err
		}
		restored := map[string]int{}
		for _, item := range receipt.Items {
			restored[item.Name] = item.Version
		}
		var results []projections.SecretMigrationRollbackItem
		for _, o := range restores {
			if version, ok := restored[o.Name]; ok {
				results = append(results, projections.SecretMigrationRollbackItem{Name: o.Name, Rollback: store.SecretMigrationRollbackRestored, Version: version})
			} else {
				results = append(results, projections.SecretMigrationRollbackItem{Name: o.Name, Rollback: store.SecretMigrationRollbackKept})
			}
		}
		// A secret the run created is deleted, each as its own command bound
		// to this rollback, so a retried rollback converges on its receipt; one
		// written since the run wrote it is kept.
		for _, o := range deletes {
			current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, o.Name)
			if err != nil && !errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, err
			}
			if err == nil && current.Version != o.Version {
				results = append(results, projections.SecretMigrationRollbackItem{Name: o.Name, Rollback: store.SecretMigrationRollbackKept, Version: current.Version})
				continue
			}
			key := idempotencyKey + "/rollback/" + o.Name
			deleteDigest, deleteBinding, err := a.applicationSecretRequestBinding(tenantID, key, principal, http.MethodDelete,
				"/api/v1/secrets/store/"+o.Name, "delete", "native", o.Name, nil)
			if err != nil {
				return 0, nil, err
			}
			if _, err := a.executeSecretDelete(ctx, tenantID, o.Name, key, deleteDigest, deleteBinding); err != nil {
				var apiErr *apiError
				if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound {
					results = append(results, projections.SecretMigrationRollbackItem{Name: o.Name, Rollback: store.SecretMigrationRollbackKept})
					continue
				}
				return 0, nil, err
			}
			results = append(results, projections.SecretMigrationRollbackItem{Name: o.Name, Rollback: store.SecretMigrationRollbackDeleted})
		}
		sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
		if err := a.orch.RecordSecretMigrationEvent(ctx, tenantID, projections.EventSecretMigrationRolledBack, id,
			projections.SecretMigrationRolledBack{ID: id, Items: results, By: principal}); err != nil {
			return 0, nil, err
		}
		resp, err := a.secretMigrationView(ctx, tenantID, id)
		return http.StatusOK, resp, err
	})
}

func (a *API) listSecretMigrations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	runs, err := a.store.ListSecretMigrations(r.Context(), tenantID, 200)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := secretMigrationListResponse{Items: []secretMigrationResponse{}}
	for _, run := range runs {
		out.Items = append(out.Items, secretMigrationResponseOf(run))
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) getSecretMigration(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	view, err := a.secretMigrationView(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

// secretMigrationView is a run with its objects and each consumer's progress.
func (a *API) secretMigrationView(ctx context.Context, tenantID, id string) (secretMigrationResponse, error) {
	run, err := a.store.GetSecretMigration(ctx, tenantID, id)
	if err != nil {
		return secretMigrationResponse{}, secretMigrationLookupError(err)
	}
	out := secretMigrationResponseOf(run)
	for _, o := range run.Objects {
		out.Objects = append(out.Objects, secretMigrationObjectResponse{Name: o.Name, Outcome: o.Outcome,
			PriorVersion: o.PriorVersion, Version: o.Version, Writer: o.Writer, Rollback: o.Rollback, RollbackVersion: o.RollbackVersion})
	}
	var plan secretmigrate.Assessment
	if err := json.Unmarshal(run.Plan, &plan); err != nil {
		return secretMigrationResponse{}, err
	}
	read := map[string]bool{}
	for _, r := range run.ConsumerReads {
		read[r.Consumer+"\x00"+r.Name] = true
	}
	for _, c := range plan.Consumers {
		status := secretMigrationConsumerStatus{Name: c.Name, Subject: c.Subject, Secrets: c.Secrets, Read: []string{}, Pending: []string{}, Problem: c.Problem}
		for _, name := range c.Secrets {
			if read[c.Name+"\x00"+name] {
				status.Read = append(status.Read, name)
			} else {
				status.Pending = append(status.Pending, name)
			}
		}
		out.Consumers = append(out.Consumers, status)
	}
	return out, nil
}

func secretMigrationResponseOf(run store.SecretMigration) secretMigrationResponse {
	permissions := run.PermissionsApplied
	if len(permissions) == 0 {
		permissions = json.RawMessage("[]")
	}
	return secretMigrationResponse{
		ID: run.ID, Project: run.Project, State: run.State, Digest: run.Digest, Plan: run.Plan,
		AcceptedOpen: nonNilStringSlice(run.AcceptedOpen), CreatedBy: run.CreatedBy, CreatedAt: run.CreatedAt,
		StagedAt: run.StagedAt, CutOverAt: run.CutOverAt, CutOverBy: run.CutOverBy, RolledBackAt: run.RolledBackAt,
		PermissionsApplied: permissions, Objects: []secretMigrationObjectResponse{}, Consumers: []secretMigrationConsumerStatus{},
	}
}

func secretMigrationLookupError(err error) error {
	if store.IsNotFound(err) {
		return errStatus(http.StatusNotFound, "no such secret migration")
	}
	return err
}

// observeMigratedSecretRead records a consumer's first read of a migrated
// secret from the store, as the subject the run expects it to read as. A
// failure to record is logged and never fails the read; without the record
// the run only stays short of cutover.
func (a *API) observeMigratedSecretRead(r *http.Request, tenantID, name string, version int) {
	if a.orch == nil || a.store == nil {
		return
	}
	reader, err := requestPrincipalSubject(r.Context())
	if err != nil || reader == "" {
		return
	}
	waiting, err := a.store.SecretMigrationsAwaitingConsumerRead(r.Context(), tenantID, name, reader)
	for _, pair := range waiting {
		if err != nil {
			break
		}
		err = a.orch.RecordSecretMigrationEvent(r.Context(), tenantID, projections.EventSecretMigrationConsumerRead,
			pair[0]+"\x00"+pair[1]+"\x00"+name, projections.SecretMigrationConsumerRead{
				ID: pair[0], Consumer: pair[1], Name: name, Version: version, Reader: reader,
			})
	}
	if err != nil {
		slog.Warn("api: a migrated secret's consumer read was not recorded",
			slog.String("types", errorTypeChain(err)), slog.String("error", redactQuoted(truncateForLog(err.Error(), 240))))
	}
}

// requireSecretWriterIsStore refuses a write to a secret whose writer is still
// a migration's export system (A243): one writer per secret until cutover.
func (a *API) requireSecretWriterIsStore(ctx context.Context, tenantID, name string) error {
	if a.store == nil {
		return nil
	}
	migration, err := a.store.SecretMigrationSourceWriter(ctx, tenantID, name)
	if err != nil {
		return err
	}
	if migration != "" {
		return &apiError{status: http.StatusConflict,
			detail: "this secret is written by its migration's source system until cutover (migration " + migration + ")",
			ext:    map[string]any{"code": "migration_source_writer", "migration_id": migration}}
	}
	return nil
}

func sortedUnique(in []string) []string {
	out := []string{}
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func nonNilStringSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
