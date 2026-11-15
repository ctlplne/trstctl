// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// A235-L4: a secret in a project environment answers to separate grants that
// must all allow: the subject's trstctl permission, its membership of a
// restricted environment and, on the Vault-compatible KV surface, the tenant's
// Vault ACL policies for its roles. The explain evaluates each for one subject
// and one secret, per surface, and names the layer that denies.

// Layers an access explain names.
const (
	secretAccessLayerPermission  = "permission"
	secretAccessLayerEnvironment = "environment"
	secretAccessLayerACLPolicy   = "acl_policy"
)

// secretAccessExplainTokenPage bounds the read of a subject's API tokens.
const secretAccessExplainTokenPage = 200

type secretAccessLayer struct {
	Layer   string `json:"layer"`
	Allowed bool   `json:"allowed"`
	Detail  string `json:"detail"`
}

type secretAccessSurface struct {
	// Surface is "native" (the trstctl secrets API, CLI and console),
	// "vault_kv" (the Vault-compatible /v1 KV routes) or "reference" (a
	// secret:// reference another configuration keeps).
	Surface  string              `json:"surface"`
	Allowed  bool                `json:"allowed"`
	DeniedBy string              `json:"denied_by,omitempty"`
	Layers   []secretAccessLayer `json:"layers"`
}

type secretAccessExplainResponse struct {
	Project string `json:"project"`
	Subject string `json:"subject"`
	Secret  string `json:"secret"`
	Action  string `json:"action"`
	// Credentials says where the subject's permissions come from: "member"
	// (its tenant member roles), "api_tokens" (the scopes of its live API
	// tokens) or "none".
	Credentials string                `json:"credentials"`
	Roles       []string              `json:"roles"`
	Surfaces    []secretAccessSurface `json:"surfaces"`
}

// secretAccessSubject is what a subject's credentials grant.
type secretAccessSubject struct {
	credentials string
	roles       []string
	can         func(authz.Permission) bool
}

// explainSecretProjectMemberAccess serves GET
// /api/v1/secrets/projects/{project}/members/{subject}/access?secret=&action=.
func (a *API) explainSecretProjectMemberAccess(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	project := strings.TrimSpace(r.PathValue("project"))
	subject := strings.TrimSpace(r.PathValue("subject"))
	secretName := strings.Trim(strings.TrimSpace(r.URL.Query().Get("secret")), "/")
	action := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("action")))
	if action == "" {
		action = "read"
	}
	if action != "read" && action != "write" {
		a.writeError(w, errStatus(http.StatusBadRequest, "action must be read or write"))
		return
	}
	if subject == "" || len(subject) > 256 {
		a.writeError(w, errStatus(http.StatusBadRequest, "a subject is required"))
		return
	}
	if !strings.HasPrefix(secretName, project+"/") || len(secretName) > 512 {
		a.writeError(w, errStatus(http.StatusBadRequest, "secret must name a secret of this project: <project>/<environment>/<key>"))
		return
	}
	if _, _, _, err := a.store.GetSecretProject(r.Context(), tenantID, project); err != nil {
		a.writeError(w, secretProjectError(err))
		return
	}
	resp, err := a.explainSecretAccess(r.Context(), tenantID, subject, secretName, action == "write")
	if err != nil {
		a.writeError(w, err)
		return
	}
	resp.Project = project
	a.writeJSON(w, http.StatusOK, resp)
}

// explainSecretAccess evaluates every layer for subject on secretName.
func (a *API) explainSecretAccess(ctx context.Context, tenantID, subject, secretName string, write bool) (secretAccessExplainResponse, error) {
	who, err := a.secretAccessSubjectOf(ctx, tenantID, subject)
	if err != nil {
		return secretAccessExplainResponse{}, err
	}
	action, perm, capability := "read", authz.SecretsRead, "read"
	if write {
		action, perm, capability = "write", authz.SecretsWrite, "update"
	}
	resp := secretAccessExplainResponse{Subject: subject, Secret: secretName, Action: action, Credentials: who.credentials, Roles: who.roles}
	if resp.Roles == nil {
		resp.Roles = []string{}
	}

	permission := secretAccessLayer{Layer: secretAccessLayerPermission, Allowed: who.can(perm)}
	switch {
	case who.credentials == "none":
		permission.Detail = "the subject is not a tenant member and holds no live API token"
	case permission.Allowed:
		permission.Detail = "its " + secretAccessCredentialsNoun(who.credentials) + " grant " + string(perm)
	default:
		permission.Detail = "its " + secretAccessCredentialsNoun(who.credentials) + " do not grant " + string(perm)
	}

	scope, err := a.store.SecretScopeFor(ctx, tenantID, secretName, subject)
	if err != nil {
		return secretAccessExplainResponse{}, err
	}
	environment := secretAccessLayer{Layer: secretAccessLayerEnvironment, Allowed: true}
	switch {
	case !scope.InProject:
		environment.Detail = "the name is in no environment of the project, so no membership applies"
	case !scope.Restricted:
		environment.Detail = "environment " + scope.Environment + " is not restricted"
	case write:
		environment.Allowed = scope.CanWrite
	default:
		environment.Allowed = scope.CanRead
	}
	if scope.InProject && scope.Restricted {
		switch {
		case environment.Allowed:
			environment.Detail = "a member granted restricted environment " + scope.Environment + " with " + action + " access"
		case scope.Member:
			environment.Detail = "a member of the project, but its grant gives no " + action + " access to restricted environment " + scope.Environment
		default:
			environment.Detail = "not a member granted restricted environment " + scope.Environment
		}
	}

	kvPath := "secret/data/" + secretName
	kvPermission := secretAccessLayer{Layer: secretAccessLayerPermission}
	for _, granted := range vaultPathCapabilities(kvPath, who.can) {
		if granted == capability {
			kvPermission.Allowed = true
		}
	}
	kvPermission.Detail = permission.Detail
	acl := secretAccessLayer{Layer: secretAccessLayerACLPolicy, Allowed: true}
	allowed, governed, err := a.vaultACLDecision(ctx, tenantID, who.roles, kvPath, capability)
	if err != nil {
		return secretAccessExplainResponse{}, err
	}
	switch {
	case !governed:
		acl.Detail = "no Vault ACL policy is named for the subject's roles, so its trstctl permission decides"
	case allowed:
		acl.Detail = "a Vault ACL policy named for its roles allows " + capability + " on " + kvPath
	default:
		acl.Allowed = false
		acl.Detail = "the Vault ACL policies named for its roles do not allow " + capability + " on " + kvPath
	}

	reference := environment
	if reference.Allowed {
		reference.Detail += "; the configuration that keeps the reference still needs its own route's permission"
	}
	resp.Surfaces = []secretAccessSurface{
		secretAccessSurfaceOf("native", permission, environment),
		secretAccessSurfaceOf("vault_kv", kvPermission, environment, acl),
		secretAccessSurfaceOf("reference", reference),
	}
	return resp, nil
}

// secretAccessSurfaceOf allows a surface when every layer does and names the
// first that denies.
func secretAccessSurfaceOf(surface string, layers ...secretAccessLayer) secretAccessSurface {
	out := secretAccessSurface{Surface: surface, Allowed: true, Layers: layers}
	for _, layer := range layers {
		if !layer.Allowed {
			out.Allowed = false
			out.DeniedBy = layer.Layer
			break
		}
	}
	return out
}

func secretAccessCredentialsNoun(credentials string) string {
	if credentials == "member" {
		return "tenant member roles"
	}
	return "live API tokens' scopes"
}

// secretAccessSubjectOf reads what subject's credentials grant: its tenant
// member roles when it is an active member, else the union of its live API
// tokens' scopes (every token answers to Vault ACL policies as the role
// "api-token"), else nothing.
func (a *API) secretAccessSubjectOf(ctx context.Context, tenantID, subject string) (secretAccessSubject, error) {
	member, err := a.store.GetTenantMember(ctx, tenantID, subject)
	switch {
	case err == nil && member.OffboardedAt == nil && member.Status != "offboarded":
		resolved, err := a.resolveRoles(ctx, tenantID, member.Roles)
		if err != nil {
			return secretAccessSubject{}, err
		}
		principal := authz.Principal{TenantID: tenantID, Subject: subject}
		var roles []string
		for _, name := range member.Roles {
			if role, ok := resolved[name]; ok {
				principal.Grants = append(principal.Grants, authz.Grant{Role: role, Scope: authz.Scope{TenantID: tenantID}})
				roles = append(roles, name)
			}
		}
		scope := authz.Scope{TenantID: tenantID}
		return secretAccessSubject{credentials: "member", roles: roles,
			can: func(perm authz.Permission) bool { return principal.Can(perm, scope) }}, nil
	case err != nil && !store.IsNotFound(err):
		return secretAccessSubject{}, err
	}
	tokens, err := a.store.ListAPITokensPage(ctx, tenantID, store.ZeroUUID, subject, false, secretAccessExplainTokenPage)
	if err != nil {
		return secretAccessSubject{}, err
	}
	scopes := map[authz.Permission]bool{}
	live, now := 0, time.Now()
	for _, token := range tokens {
		if token.RevokedAt != nil || (token.ExpiresAt != nil && !token.ExpiresAt.After(now)) {
			continue
		}
		live++
		for _, s := range token.Scopes {
			scopes[authz.Permission(s)] = true
		}
	}
	if live == 0 {
		return secretAccessSubject{credentials: "none", can: func(authz.Permission) bool { return false }}, nil
	}
	principal := authz.Principal{TenantID: tenantID, Subject: subject, Grants: []authz.Grant{{
		Role: authz.Role{Name: "api-token", Permissions: secretAccessPermissions(scopes)}, Scope: authz.Scope{TenantID: tenantID},
	}}}
	scope := authz.Scope{TenantID: tenantID}
	return secretAccessSubject{credentials: "api_tokens", roles: []string{"api-token"},
		can: func(perm authz.Permission) bool { return principal.Can(perm, scope) }}, nil
}

func secretAccessPermissions(set map[authz.Permission]bool) []authz.Permission {
	out := make([]authz.Permission, 0, len(set))
	for perm := range set {
		out = append(out, perm)
	}
	return out
}
