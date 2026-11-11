// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// The secrets workspace (A235). A project (an application) has environments;
// a secret belongs to one by its name, "<project>/<environment>/<folder…>/<key>",
// and stays a row of the one native store, so references, history, recovery,
// sync and `trstctl run` work unchanged. A restricted environment is open only
// to the project members granted it, on every surface that reads or writes by
// name — the native API, every hop of a reference, previews, imports, syncs and
// the Vault-compatible KV routes. A read it denies answers as "no such secret",
// so names are not an existence oracle; a denied write is 403. Projects and
// environments change under access:write. Membership changes under
// access:write, or under secrets:write by a member holding the project's admin
// role, within its own grant (A235-L1): it grants and revokes only
// environments it holds itself, so a secrets:write token still cannot grant
// itself an environment.

var secretProjectSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

const (
	secretProjectEnvironmentLimit = 32
	secretProjectSecretListLimit  = 200
	secretOwnerUnknown            = "unknown"
)

type secretProjectEnvironmentRequest struct {
	Slug       string `json:"slug"`
	Name       string `json:"name,omitempty"`
	Restricted bool   `json:"restricted,omitempty"`
}

type secretProjectCreateRequest struct {
	Slug         string                            `json:"slug"`
	Name         string                            `json:"name,omitempty"`
	OwnerID      string                            `json:"owner_id,omitempty"`
	Environments []secretProjectEnvironmentRequest `json:"environments"`
}

type secretProjectMemberRequest struct {
	Role         string   `json:"role"`
	Environments []string `json:"environments,omitempty"`
}

type secretProjectSecretResponse struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	Version int    `json:"version"`
	OwnerID string `json:"owner_id,omitempty"`
	Owner   string `json:"owner"`
}

type secretProjectEnvironmentResponse struct {
	Slug       string `json:"slug"`
	Name       string `json:"name,omitempty"`
	Restricted bool   `json:"restricted"`
	// Access is what the caller has here: "open" (unrestricted), "member"
	// (restricted, granted) or "restricted" (not granted; secrets not listed).
	Access  string                        `json:"access"`
	Secrets []secretProjectSecretResponse `json:"secrets"`
}

type secretProjectMemberResponse struct {
	Subject      string    `json:"subject"`
	Role         string    `json:"role"`
	Environments []string  `json:"environments"`
	GrantedBy    string    `json:"granted_by,omitempty"`
	GrantedAt    time.Time `json:"granted_at"`
}

// secretProjectResourceResponse is one certificate or identity the project's
// owner holds, with its health: expired, expiring (within 30 days) or ok.
type secretProjectResourceResponse struct {
	ID       string     `json:"id"`
	Kind     string     `json:"kind"`
	Name     string     `json:"name"`
	Status   string     `json:"status,omitempty"`
	NotAfter *time.Time `json:"not_after,omitempty"`
	Health   string     `json:"health"`
}

// secretProjectOwnerResources is the application view: what the project's
// owner holds besides these secrets.
type secretProjectOwnerResources struct {
	Certificates            int                             `json:"certificates"`
	Identities              int                             `json:"identities"`
	SoonestCertificates     []secretProjectResourceResponse `json:"soonest_certificates"`
	SoonestIdentities       []secretProjectResourceResponse `json:"soonest_identities"`
	CertificatesNeedingWork int                             `json:"certificates_needing_work"`
}

type secretProjectResponse struct {
	Slug         string                             `json:"slug"`
	Name         string                             `json:"name,omitempty"`
	OwnerID      string                             `json:"owner_id,omitempty"`
	Owner        string                             `json:"owner"`
	CreatedBy    string                             `json:"created_by,omitempty"`
	CreatedAt    time.Time                          `json:"created_at"`
	Environments []secretProjectEnvironmentResponse `json:"environments,omitempty"`
	Members      []secretProjectMemberResponse      `json:"members,omitempty"`
	// OwnerResources is absent when the owner is unknown: nothing is guessed.
	OwnerResources *secretProjectOwnerResources `json:"owner_resources,omitempty"`
	// CanManageMembers says whether the caller may grant and revoke members
	// (A235-L1): access:write, or the project's admin role. A project admin
	// restricted to some environments manages only those, listed in
	// ManageableEnvironments; empty means every environment.
	CanManageMembers       bool     `json:"can_manage_members"`
	ManageableEnvironments []string `json:"manageable_environments,omitempty"`
}

// secretProjectMemberManager is who may change a project's membership and
// within what (A235-L1): access:write manages every project in full; a caller
// with secrets:write holding the project's admin role manages it within its
// own grant, never past it.
type secretProjectMemberManager struct {
	full bool
	// perm is the real permission the change is made under, which the
	// tenant's ABAC policy is evaluated against: access:write in full,
	// secrets:write for a project admin.
	perm authz.Permission
	// environments is a delegated admin's own grant; empty is every
	// environment.
	environments []string
}

// secretProjectMemberManagerFor resolves principal's authority over a
// project's membership at target from the members already loaded for the
// project. The routes admit authz.SecretsMembersManage (access:write or
// secrets:write); this decides which of the two the caller acts under.
func secretProjectMemberManagerFor(principal authz.Principal, target authz.Scope, project string, members []store.SecretProjectMember) (secretProjectMemberManager, error) {
	if principal.Subject == "" {
		return secretProjectMemberManager{}, errStatus(http.StatusUnauthorized, "an authenticated principal is required")
	}
	if principal.Can(authz.AccessWrite, target) {
		return secretProjectMemberManager{full: true, perm: authz.AccessWrite}, nil
	}
	if principal.Can(authz.SecretsWrite, target) {
		for _, m := range members {
			if m.Subject == principal.Subject && m.Role == store.SecretProjectRoleAdmin {
				return secretProjectMemberManager{perm: authz.SecretsWrite, environments: append([]string(nil), m.Environments...)}, nil
			}
		}
	}
	return secretProjectMemberManager{}, errStatus(http.StatusForbidden, "managing project "+project+"'s members needs access:write, or secrets:write and the project's admin role")
}

// secretProjectMemberManagerOf resolves the request's manager and evaluates
// the tenant's ABAC policy against the permission the change is made under,
// as route admission does for a route with one real permission: the route's
// computed predicate is never sent through ABAC.
func (a *API) secretProjectMemberManagerOf(ctx context.Context, r *http.Request, project string, members []store.SecretProjectMember) (secretProjectMemberManager, error) {
	principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok {
		return secretProjectMemberManager{}, errStatus(http.StatusUnauthorized, "an authenticated principal is required")
	}
	target, err := requestTargetScope(principal, r, nil)
	if err != nil {
		return secretProjectMemberManager{}, err
	}
	manager, err := secretProjectMemberManagerFor(principal, target, project, members)
	if err != nil {
		return secretProjectMemberManager{}, err
	}
	if err := a.checkABAC(ctx, r, principal, manager.perm, target); err != nil {
		return secretProjectMemberManager{}, err
	}
	return manager, nil
}

// covers reports whether the manager's authority covers a grant of envs
// (empty: every environment). A delegated admin restricted to some
// environments covers only grants inside them.
func (m secretProjectMemberManager) covers(envs []string) bool {
	if m.full || len(m.environments) == 0 {
		return true
	}
	if len(envs) == 0 {
		return false
	}
	for _, env := range envs {
		if !slices.Contains(m.environments, env) {
			return false
		}
	}
	return true
}

// secretScopeAllows reports whether the request's principal may read (or
// write) the secret name. A name outside any project environment, or in an
// unrestricted one, is governed by the route's tenant scope alone. A request
// with no principal is an internal job, checked when it was requested.
func (a *API) secretScopeAllows(ctx context.Context, tenantID, name string, write bool) (bool, error) {
	subject, err := requestPrincipalSubject(ctx)
	if err != nil || a.store == nil {
		return true, nil // no request principal: an internal job
	}
	scope, err := a.store.SecretScopeFor(ctx, tenantID, name, subject)
	if err != nil {
		return false, err
	}
	if !scope.InProject || !scope.Restricted {
		return true, nil
	}
	if write {
		return scope.CanWrite, nil
	}
	return scope.CanRead, nil
}

// errSecretScopeRead is a denied read: indistinguishable from a missing secret.
var errSecretScopeRead = store.ErrSecretNotFound

// requireSecretRead returns store.ErrSecretNotFound when the caller may not
// read name, so every surface answers exactly as for a missing secret.
func (a *API) requireSecretRead(ctx context.Context, tenantID, name string) error {
	ok, err := a.secretScopeAllows(ctx, tenantID, name, false)
	if err != nil {
		return err
	}
	if !ok {
		return errSecretScopeRead
	}
	return nil
}

// requireSecretWrite returns a 403 when the caller may not write name.
func (a *API) requireSecretWrite(ctx context.Context, tenantID, name string) error {
	ok, err := a.secretScopeAllows(ctx, tenantID, name, true)
	if err != nil {
		return err
	}
	if !ok {
		return errStatus(http.StatusForbidden, "this secret is in a restricted environment you are not a member of with write access")
	}
	// A243: until its migration cuts over, the export's system is the
	// secret's one writer.
	return a.requireSecretWriterIsStore(ctx, tenantID, name)
}

// hiddenSecretPrefixes is every restricted environment the caller is not
// granted, so listings leave those names out.
func (a *API) hiddenSecretPrefixes(ctx context.Context, tenantID string) ([]string, error) {
	subject, err := requestPrincipalSubject(ctx)
	if err != nil || a.store == nil {
		return nil, nil // no request principal: nothing to hide from
	}
	return a.store.RestrictedSecretPrefixes(ctx, tenantID, subject)
}

func validateSecretProjectEnvironment(e secretProjectEnvironmentRequest) error {
	if !secretProjectSlug.MatchString(e.Slug) {
		return errors.New("an environment slug is lowercase letters, digits and hyphens (1-63)")
	}
	if len(e.Name) > 128 {
		return errors.New("an environment name is at most 128 characters")
	}
	return nil
}

//trstctl:mutation
func (a *API) createSecretProject(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretProjectCreateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if !secretProjectSlug.MatchString(req.Slug) || len(req.Name) > 128 {
			return 0, nil, errStatus(http.StatusBadRequest, "slug is lowercase letters, digits and hyphens (1-63); name is at most 128 characters")
		}
		if len(req.Environments) == 0 || len(req.Environments) > secretProjectEnvironmentLimit {
			return 0, nil, errStatus(http.StatusBadRequest, "a project has 1-32 environments")
		}
		created := projections.SecretProjectCreated{Slug: req.Slug, Name: strings.TrimSpace(req.Name), OwnerID: strings.TrimSpace(req.OwnerID)}
		seen := map[string]bool{}
		for i, env := range req.Environments {
			if err := validateSecretProjectEnvironment(env); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
			if seen[env.Slug] {
				return 0, nil, errStatus(http.StatusBadRequest, "environment "+env.Slug+" is listed twice")
			}
			seen[env.Slug] = true
			created.Environments = append(created.Environments, projections.SecretProjectEnvironment{
				Slug: env.Slug, Name: strings.TrimSpace(env.Name), Restricted: env.Restricted, Position: i,
			})
		}
		if created.OwnerID != "" {
			if _, err := a.store.GetOwner(ctx, tenantID, created.OwnerID); err != nil {
				if store.IsNotFound(err) {
					return 0, nil, errStatus(http.StatusBadRequest, "owner_id must identify an owner in this tenant")
				}
				return 0, nil, err
			}
		}
		if _, _, _, err := a.store.GetSecretProject(ctx, tenantID, req.Slug); err == nil {
			return 0, nil, errStatus(http.StatusConflict, "a project named "+req.Slug+" already exists")
		} else if !errors.Is(err, store.ErrSecretProjectNotFound) {
			return 0, nil, err
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		created.CreatedBy = subject
		if err := a.orch.CreateSecretProject(ctx, tenantID, created); err != nil {
			return 0, nil, err
		}
		resp, err := a.secretProjectView(ctx, tenantID, req.Slug)
		return http.StatusCreated, resp, err
	})
}

//trstctl:mutation
func (a *API) addSecretProjectEnvironment(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretProjectEnvironmentRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := validateSecretProjectEnvironment(req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		project := r.PathValue("project")
		_, envs, _, err := a.store.GetSecretProject(ctx, tenantID, project)
		if err != nil {
			return 0, nil, secretProjectError(err)
		}
		if len(envs) >= secretProjectEnvironmentLimit {
			return 0, nil, errStatus(http.StatusConflict, "a project has at most 32 environments")
		}
		for _, env := range envs {
			if env.Slug == req.Slug {
				return 0, nil, errStatus(http.StatusConflict, "environment "+req.Slug+" already exists")
			}
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.AddSecretProjectEnvironment(ctx, tenantID, projections.SecretProjectEnvironmentAdded{
			Project: project, AddedBy: subject,
			Environment: projections.SecretProjectEnvironment{Slug: req.Slug, Name: strings.TrimSpace(req.Name), Restricted: req.Restricted, Position: len(envs)},
		}); err != nil {
			return 0, nil, err
		}
		resp, err := a.secretProjectView(ctx, tenantID, project)
		return http.StatusOK, resp, err
	})
}

// secretProjectRenameRequest renames a project or an environment (A235-L3).
type secretProjectRenameRequest struct {
	Name string `json:"name"`
}

// secretProjectNewName validates a new display name: the slug, which every
// secret name in the project begins with, never changes.
func secretProjectNewName(r *http.Request) (string, error) {
	var req secretProjectRenameRequest
	if err := decodeJSON(r, &req); err != nil {
		return "", errWithStatus(http.StatusBadRequest, err)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 128 {
		return "", errStatus(http.StatusBadRequest, "name is 1-128 characters; the slug stays as it is")
	}
	return name, nil
}

// renameSecretProject changes a project's display name (A235-L3).
//
//trstctl:mutation
func (a *API) renameSecretProject(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		name, err := secretProjectNewName(r)
		if err != nil {
			return 0, nil, err
		}
		project := r.PathValue("project")
		current, _, _, err := a.store.GetSecretProject(ctx, tenantID, project)
		if err != nil {
			return 0, nil, secretProjectError(err)
		}
		if current.Name != name {
			subject, err := requestPrincipalSubject(ctx)
			if err != nil {
				return 0, nil, err
			}
			if err := a.orch.RenameSecretProject(ctx, tenantID, projections.SecretProjectRenamed{
				Project: project, Name: name, RenamedBy: subject,
			}); err != nil {
				return 0, nil, err
			}
		}
		resp, err := a.secretProjectView(ctx, tenantID, project)
		return http.StatusOK, resp, err
	})
}

// renameSecretProjectEnvironment changes an environment's display name
// (A235-L3).
//
//trstctl:mutation
func (a *API) renameSecretProjectEnvironment(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		name, err := secretProjectNewName(r)
		if err != nil {
			return 0, nil, err
		}
		project, environment := r.PathValue("project"), r.PathValue("environment")
		_, envs, _, err := a.store.GetSecretProject(ctx, tenantID, project)
		if err != nil {
			return 0, nil, secretProjectError(err)
		}
		var current *store.SecretProjectEnvironment
		for i := range envs {
			if envs[i].Slug == environment {
				current = &envs[i]
			}
		}
		if current == nil {
			return 0, nil, errStatus(http.StatusNotFound, "environment "+environment+" is not in project "+project)
		}
		if current.Name != name {
			subject, err := requestPrincipalSubject(ctx)
			if err != nil {
				return 0, nil, err
			}
			if err := a.orch.RenameSecretProjectEnvironment(ctx, tenantID, projections.SecretProjectEnvironmentRenamed{
				Project: project, Environment: environment, Name: name, RenamedBy: subject,
			}); err != nil {
				return 0, nil, err
			}
		}
		resp, err := a.secretProjectView(ctx, tenantID, project)
		return http.StatusOK, resp, err
	})
}

//trstctl:mutation
func (a *API) putSecretProjectMember(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretProjectMemberRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		project, member := r.PathValue("project"), strings.TrimSpace(r.PathValue("subject"))
		switch req.Role {
		case store.SecretProjectRoleViewer, store.SecretProjectRoleDeveloper, store.SecretProjectRoleAdmin:
		default:
			return 0, nil, errStatus(http.StatusBadRequest, "role is viewer, developer or admin")
		}
		if member == "" || len(member) > 256 {
			return 0, nil, errStatus(http.StatusBadRequest, "subject is required (at most 256 characters)")
		}
		_, envs, members, err := a.store.GetSecretProject(ctx, tenantID, project)
		if err != nil {
			return 0, nil, secretProjectError(err)
		}
		// A235-L1: access:write, or the project's admin within its own grant,
		// for the new grant and for the member's grant it replaces.
		manager, err := a.secretProjectMemberManagerOf(ctx, r, project, members)
		if err != nil {
			return 0, nil, err
		}
		if !manager.covers(req.Environments) {
			return 0, nil, errStatus(http.StatusForbidden, "a project admin grants only environments of its own grant")
		}
		for _, m := range members {
			if m.Subject == member && !manager.covers(m.Environments) {
				return 0, nil, errStatus(http.StatusForbidden, "a project admin changes only members within its own grant")
			}
		}
		known := map[string]bool{}
		for _, env := range envs {
			known[env.Slug] = true
		}
		for _, env := range req.Environments {
			if !known[env] {
				return 0, nil, errStatus(http.StatusBadRequest, "environment "+env+" is not in project "+project)
			}
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.GrantSecretProjectMember(ctx, tenantID, projections.SecretProjectMemberGranted{
			Project: project, Subject: member, Role: req.Role, Environments: req.Environments, GrantedBy: subject,
		}); err != nil {
			return 0, nil, err
		}
		resp, err := a.secretProjectView(ctx, tenantID, project)
		return http.StatusOK, resp, err
	})
}

//trstctl:mutation
func (a *API) deleteSecretProjectMember(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		project, member := r.PathValue("project"), strings.TrimSpace(r.PathValue("subject"))
		_, _, members, err := a.store.GetSecretProject(ctx, tenantID, project)
		if err != nil {
			return 0, nil, secretProjectError(err)
		}
		var target *store.SecretProjectMember
		for i := range members {
			if members[i].Subject == member {
				target = &members[i]
			}
		}
		if target == nil {
			return 0, nil, errStatus(http.StatusNotFound, "no such member of project "+project)
		}
		// A235-L1: access:write, or the project's admin within its own grant.
		manager, err := a.secretProjectMemberManagerOf(ctx, r, project, members)
		if err != nil {
			return 0, nil, err
		}
		if !manager.covers(target.Environments) {
			return 0, nil, errStatus(http.StatusForbidden, "a project admin revokes only members within its own grant")
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.RevokeSecretProjectMember(ctx, tenantID, projections.SecretProjectMemberRevoked{Project: project, Subject: member, RevokedBy: subject}); err != nil {
			return 0, nil, err
		}
		resp, err := a.secretProjectView(ctx, tenantID, project)
		return http.StatusOK, resp, err
	})
}

func (a *API) listSecretProjects(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	projects, err := a.store.ListSecretProjects(r.Context(), tenantID, 500)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]secretProjectResponse, 0, len(projects))
	for _, p := range projects {
		items = append(items, secretProjectResponse{Slug: p.Slug, Name: p.Name, OwnerID: p.OwnerID,
			Owner: a.ownerName(r.Context(), tenantID, p.OwnerID), CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt})
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

func (a *API) getSecretProject(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	resp, err := a.secretProjectView(r.Context(), tenantID, r.PathValue("project"))
	if err != nil {
		a.writeError(w, secretProjectError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, resp)
}

// secretProjectView is one project as the caller may see it: every
// environment, its secrets (names, versions, owners — "unknown" when there is
// none) unless it is restricted and the caller is not granted it, and the
// members.
func (a *API) secretProjectView(ctx context.Context, tenantID, slug string) (secretProjectResponse, error) {
	p, envs, members, err := a.store.GetSecretProject(ctx, tenantID, slug)
	if err != nil {
		return secretProjectResponse{}, err
	}
	resp := secretProjectResponse{Slug: p.Slug, Name: p.Name, OwnerID: p.OwnerID, Owner: a.ownerName(ctx, tenantID, p.OwnerID),
		CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt}
	owners := map[string]string{}
	for _, env := range envs {
		prefix := p.Slug + "/" + env.Slug + "/"
		view := secretProjectEnvironmentResponse{Slug: env.Slug, Name: env.Name, Restricted: env.Restricted, Access: "open", Secrets: []secretProjectSecretResponse{}}
		if env.Restricted {
			readable, err := a.secretScopeAllows(ctx, tenantID, prefix+"_", false)
			if err != nil {
				return secretProjectResponse{}, err
			}
			view.Access = "member"
			if !readable {
				view.Access = "restricted"
				resp.Environments = append(resp.Environments, view)
				continue
			}
		}
		names, err := a.store.ListSecretNamesUnder(ctx, tenantID, []string{prefix}, nil, secretProjectSecretListLimit)
		if err != nil {
			return secretProjectResponse{}, err
		}
		for _, rec := range names {
			owner, cached := owners[rec.OwnerID]
			if !cached {
				owner = a.ownerName(ctx, tenantID, rec.OwnerID)
				owners[rec.OwnerID] = owner
			}
			view.Secrets = append(view.Secrets, secretProjectSecretResponse{
				Name: rec.Name, Key: strings.TrimPrefix(rec.Name, prefix), Version: rec.Version, OwnerID: rec.OwnerID, Owner: owner,
			})
		}
		resp.Environments = append(resp.Environments, view)
	}
	if resp.Owner != secretOwnerUnknown {
		inv, err := a.store.OwnerApplicationInventory(ctx, tenantID, p.OwnerID, 5)
		if err != nil {
			return secretProjectResponse{}, err
		}
		resp.OwnerResources = ownerResourcesView(inv, time.Now())
	}
	for _, m := range members {
		envs := m.Environments
		if envs == nil {
			envs = []string{}
		}
		resp.Members = append(resp.Members, secretProjectMemberResponse{Subject: m.Subject, Role: m.Role, Environments: envs, GrantedBy: m.GrantedBy, GrantedAt: m.GrantedAt})
	}
	if principal, ok := ctx.Value(principalCtxKey).(authz.Principal); ok {
		if manager, err := secretProjectMemberManagerFor(principal, authz.Scope{TenantID: tenantID}, slug, members); err == nil {
			resp.CanManageMembers = true
			if !manager.full {
				resp.ManageableEnvironments = manager.environments
			}
		}
	}
	return resp, nil
}

// ownerName is an owner's name, or "unknown" when there is none or it no
// longer resolves — never a guess.
func (a *API) ownerName(ctx context.Context, tenantID, ownerID string) string {
	if ownerID == "" || a.store == nil {
		return secretOwnerUnknown
	}
	owner, err := a.store.GetOwner(ctx, tenantID, ownerID)
	if err != nil || strings.TrimSpace(owner.Name) == "" {
		return secretOwnerUnknown
	}
	return owner.Name
}

func secretProjectError(err error) error {
	if errors.Is(err, store.ErrSecretProjectNotFound) {
		return errStatus(http.StatusNotFound, "no such project")
	}
	return err
}

// writeSecretScopeError answers a denied scope check: a read as a missing
// secret, a write as 403.
func (a *API) writeSecretScopeError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, errSecretScopeRead):
		a.writeProblem(w, problem.New(http.StatusNotFound, "no such secret"))
	default:
		a.writeError(w, err)
	}
	return true
}

func ownerResourcesView(inv store.OwnerInventory, now time.Time) *secretProjectOwnerResources {
	out := &secretProjectOwnerResources{Certificates: inv.Certificates, Identities: inv.Identities,
		SoonestCertificates: []secretProjectResourceResponse{}, SoonestIdentities: []secretProjectResourceResponse{}}
	health := func(notAfter *time.Time) string {
		switch {
		case notAfter == nil:
			return "ok"
		case notAfter.Before(now):
			return "expired"
		case notAfter.Before(now.Add(30 * 24 * time.Hour)):
			return "expiring"
		default:
			return "ok"
		}
	}
	for _, c := range inv.SoonestCertificate {
		h := health(c.NotAfter)
		if h != "ok" {
			out.CertificatesNeedingWork++
		}
		out.SoonestCertificates = append(out.SoonestCertificates, secretProjectResourceResponse{ID: c.ID, Kind: c.Kind, Name: c.Name, NotAfter: c.NotAfter, Health: h})
	}
	for _, i := range inv.SoonestIdentities {
		out.SoonestIdentities = append(out.SoonestIdentities, secretProjectResourceResponse{ID: i.ID, Kind: i.Kind, Name: i.Name, Status: i.Status, NotAfter: i.NotAfter, Health: health(i.NotAfter)})
	}
	return out
}
