// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Agent access bundles (A251). A bundle is a reusable set of permissions for
// custom agents, CI jobs and private MCP servers; a grant gives it to a user or
// a machine; a run is a short-lived API token minted under some of a
// principal's live grants. A run's authority is derived again from those grants
// at every request (bundleRunPrincipal), so removing a grant, deleting a bundle
// or offboarding a member takes effect on the next request, with no cache to go
// stale.

const (
	accessBundleListLimit       = 500
	accessBundleGrantListLimit  = 500
	accessBundleRunViewLimit    = 50
	accessBundleMaxPermissions  = 64
	accessBundleMaxBundlesInRun = 10
	accessBundleDefaultRunTTL   = 900
	accessBundleMinRunTTL       = 60
	accessBundleMaxRunTTL       = 86400
	accessBundleLabelMax        = 120
	accessBundleMaxTargets      = 16
	accessBundleMaxTargetRoles  = 8
)

// accessBundleTargetTypes are the PAM target types a bundle may delegate
// (A257).
var accessBundleTargetTypes = []string{"aws", "azure", "clickhouse", "gcp", "kubernetes", "mongodb", "mysql", "postgres", "redis", "snowflake", "ssh"}

// accessBundleName is a PAM target ID or role name a bundle may name.
var accessBundleName = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

var accessBundleAudiences = map[string]bool{"custom_agent": true, "ci": true, "mcp_server": true}

// accessBundleRefused are the permissions no bundle may carry: a run must
// never manage access or mint a credential that would outlive its grants.
var accessBundleRefused = map[authz.Permission]bool{
	authz.Wildcard: true, authz.AccessWrite: true, authz.AccessApprove: true, authz.AccessTargetsWrite: true,
	authz.AccessRoleAssign: true, authz.AccessBundleRun: true, authz.AgentsGrantRelay: true, authz.AccessTerminate: true,
}

// The bounds every authority view states. They describe how runs behave, so
// they are the same for every principal.
const (
	accessBoundRevocation = "Removing a grant, deleting a bundle, offboarding a member or revoking a run takes effect on the run's next request: every request derives the run's authority again from the live grants, and nothing caches it."
	accessBoundOutage     = "A run's credential is checked online at every request; while the control plane is unreachable it authorizes nothing, and it never outlives its expiry."
	accessBoundLasting    = "What a run creates (certificates, secrets, enrolled agents) follows its own lifecycle; removing the grant stops the run, not what it already made."
)

func (a *API) accessBundleRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/access/bundles", opID: "createAccessBundle", summary: "Create an access bundle: a reusable set of permissions for custom agents, CI jobs and private MCP servers, with a ceiling on each run's lifetime", handler: a.createAccessBundle, reqSchema: "AccessBundleRequest", resSchema: "AccessBundle", successCode: "201", mutation: true, perm: authz.AccessWrite},
		{method: "GET", path: "/api/v1/access/bundles", opID: "listAccessBundles", summary: "List live access bundles with their live grant and active run counts", handler: a.listAccessBundles, resSchema: "AccessBundleList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/bundles/{id}", opID: "getAccessBundle", summary: "Show an access bundle with its grants and recent runs; a deleted bundle is not found", handler: a.getAccessBundle, pathParams: idPath, resSchema: "AccessBundle", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/bundles/{id}", opID: "updateAccessBundle", summary: "Replace an access bundle at the revision you read; every grant and run sees the new permissions on its next request", handler: a.updateAccessBundle, pathParams: idPath, reqSchema: "AccessBundleRequest", resSchema: "AccessBundle", successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "DELETE", path: "/api/v1/access/bundles/{id}", opID: "deleteAccessBundle", summary: "Delete an access bundle; its grants and runs give nothing from the next request on, and replaying an earlier request cannot bring it back", handler: a.deleteAccessBundle, pathParams: idPath, resSchema: "AccessBundleDeleted", successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "POST", path: "/api/v1/access/bundles/{id}/grants", opID: "grantAccessBundle", summary: "Give an access bundle to a user or a machine, optionally until a time, and return the principal's effective authority after the change", handler: a.grantAccessBundle, pathParams: idPath, reqSchema: "AccessBundleGrantRequest", resSchema: "AccessBundleGrantChange", successCode: "201", mutation: true, perm: authz.AccessWrite},
		{method: "DELETE", path: "/api/v1/access/bundles/{id}/grants/{grant_id}", opID: "ungrantAccessBundle", summary: "Remove one grant of an access bundle and return the principal's effective authority after the change", handler: a.ungrantAccessBundle, pathParams: []param{pathUUID("id"), pathUUID("grant_id")}, query: []param{{name: "reason", typ: "string", desc: "why the grant is removed (at most 200 characters)"}}, resSchema: "AccessBundleGrantChange", successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "GET", path: "/api/v1/access/authority", opID: "getAccessAuthority", summary: "Show a principal's effective authority through access bundles: each permission with the grants that give it, its live grants, active runs with their delegation chain, and the revocation and outage bounds", handler: a.getAccessAuthority, query: []param{{name: "principal", typ: "string", desc: "the user or machine principal", required: true}}, resSchema: "AccessAuthority", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/runs", opID: "issueAccessRun", summary: "Mint a run's short-lived credential under your own live grants of one or more bundles (another principal's needs access:write and every permission the run carries); returned once with launch instructions", handler: a.issueAccessRun, reqSchema: "AccessRunRequest", resSchema: "AccessRunIssued", successCode: "201", mutation: true, sensitiveResponse: true, perm: authz.AccessBundleRun},
		{method: "GET", path: "/api/v1/access/runs", opID: "listAccessRuns", summary: "List runs, newest first, with what each may do now", handler: a.listAccessRuns, query: []param{{name: "principal", typ: "string", desc: "only this principal's runs"}, {name: "bundle", typ: "string", format: "uuid", desc: "only runs minted under this bundle"}, {name: "limit", typ: "integer", desc: "maximum runs (1-100, default 20)"}}, resSchema: "AccessRunList", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/access/runs/{id}/revoke", opID: "revokeAccessRun", summary: "Revoke a run's credential (your own run, or anyone's with access:write); it is refused from the next request", handler: a.revokeAccessRun, pathParams: idPath, resSchema: "AccessRun", successCode: "200", mutation: true, perm: authz.AccessBundleRun},
		{method: "GET", path: "/api/v1/access/activity", opID: "listAccessActivity", summary: "Search access bundle activity, newest first: bundles saved and deleted, grants given and removed, runs issued and revoked, and each run's recorded uses (metadata only)", handler: a.listAccessActivity, query: accessActivityQuery(true), resSchema: "AccessActivityList", successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/access/activity/export", opID: "exportAccessActivity", summary: "Export matching access bundle activity as one JSON document (at most 10,000 rows); it carries metadata only, never a credential, token hash or request body", handler: a.exportAccessActivity, query: accessActivityQuery(false), resSchema: "AccessActivityExport", successCode: "200", perm: authz.AccessRead},
	}
}

func accessActivityQuery(paged bool) []param {
	q := []param{
		{name: "bundle", typ: "string", format: "uuid", desc: "only activity touching this bundle"},
		{name: "principal", typ: "string", desc: "only activity of this principal"},
		{name: "q", typ: "string", desc: "case-insensitive text in the action, bundle names, principal, actor or detail (at most 200 characters)"},
	}
	if paged {
		q = append(q, param{name: "limit", typ: "integer", desc: "maximum rows (1-100, default 20)"},
			param{name: "cursor", typ: "string", desc: "opaque cursor from the previous page"})
	}
	return q
}

type accessBundleRequest struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Permissions      []string `json:"permissions"`
	Audiences        []string `json:"audiences"`
	MaxRunTTLSeconds int      `json:"max_run_ttl_seconds"`
	// AccessTargets are the accounts a run may open privileged sessions to
	// (A257): each a PAM target and the roles allowed on it.
	AccessTargets []store.AccessBundleTarget `json:"access_targets"`
	// Revision is the revision being replaced (PUT only).
	Revision int64 `json:"revision"`
}

type accessBundleView struct {
	ID               string                     `json:"id"`
	Name             string                     `json:"name"`
	Description      string                     `json:"description"`
	Permissions      []string                   `json:"permissions"`
	Audiences        []string                   `json:"audiences"`
	MaxRunTTLSeconds int                        `json:"max_run_ttl_seconds"`
	AccessTargets    []store.AccessBundleTarget `json:"access_targets"`
	Revision         int64                      `json:"revision"`
	CreatedBy        string                     `json:"created_by"`
	CreatedAt        time.Time                  `json:"created_at"`
	UpdatedAt        time.Time                  `json:"updated_at"`
	LiveGrants       int                        `json:"live_grants"`
	ActiveRuns       int                        `json:"active_runs"`
	Grants           []accessBundleGrantView    `json:"grants,omitempty"`
	Runs             []accessRunView            `json:"runs,omitempty"`
}

type accessBundleListResponse struct {
	Items []accessBundleView `json:"items"`
}

type accessBundleDeletedResponse struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Deleted        bool      `json:"deleted"`
	GrantsAffected int       `json:"grants_affected"`
	RunsAffected   int       `json:"runs_affected"`
	DeletedAt      time.Time `json:"deleted_at"`
}

type accessBundleGrantRequest struct {
	PrincipalType string     `json:"principal_type"`
	Principal     string     `json:"principal"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

type accessBundleGrantView struct {
	ID            string     `json:"id"`
	BundleID      string     `json:"bundle_id"`
	PrincipalType string     `json:"principal_type"`
	Principal     string     `json:"principal"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	GrantedBy     string     `json:"granted_by"`
	GrantedAt     time.Time  `json:"granted_at"`
	RemovedAt     *time.Time `json:"removed_at,omitempty"`
	RemovedBy     string     `json:"removed_by,omitempty"`
	RemovedReason string     `json:"removed_reason,omitempty"`
	Live          bool       `json:"live"`
}

type accessBundleGrantChange struct {
	Grant     accessBundleGrantView `json:"grant"`
	Authority accessAuthorityView   `json:"authority"`
}

type accessAuthorityVia struct {
	GrantID    string     `json:"grant_id"`
	BundleID   string     `json:"bundle_id"`
	BundleName string     `json:"bundle_name"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type accessAuthorityPermission struct {
	Permission string               `json:"permission"`
	Via        []accessAuthorityVia `json:"via"`
}

type accessBounds struct {
	Revocation       string `json:"revocation"`
	Outage           string `json:"outage"`
	Lasting          string `json:"lasting"`
	MaxRunTTLSeconds int    `json:"max_run_ttl_seconds"`
}

type accessAuthorityView struct {
	Principal   string                      `json:"principal"`
	Permissions []accessAuthorityPermission `json:"permissions"`
	Grants      []accessBundleGrantView     `json:"grants"`
	Runs        []accessRunView             `json:"runs"`
	Bounds      accessBounds                `json:"bounds"`
	ComputedAt  time.Time                   `json:"computed_at"`
}

type accessRunRequest struct {
	Principal   string   `json:"principal"`
	BundleIDs   []string `json:"bundle_ids"`
	Permissions []string `json:"permissions"`
	TTLSeconds  int      `json:"ttl_seconds"`
	Label       string   `json:"label"`
}

type accessDelegationLink struct {
	Step   string    `json:"step"`
	Actor  string    `json:"actor"`
	At     time.Time `json:"at"`
	Detail string    `json:"detail"`
}

type accessRunView struct {
	ID          string                 `json:"id"`
	Principal   string                 `json:"principal"`
	BundleIDs   []string               `json:"bundle_ids"`
	BundleNames []string               `json:"bundle_names"`
	GrantIDs    []string               `json:"grant_ids"`
	Permissions []string               `json:"permissions"`
	Effective   []string               `json:"effective"`
	Label       string                 `json:"label,omitempty"`
	Status      string                 `json:"status"`
	ExpiresAt   time.Time              `json:"expires_at"`
	IssuedBy    string                 `json:"issued_by"`
	IssuedAt    time.Time              `json:"issued_at"`
	RevokedAt   *time.Time             `json:"revoked_at,omitempty"`
	RevokedBy   string                 `json:"revoked_by,omitempty"`
	Chain       []accessDelegationLink `json:"chain"`
}

type accessRunListResponse struct {
	Items []accessRunView `json:"items"`
}

type accessLaunch struct {
	TokenEnv    string `json:"token_env"`
	ServerEnv   string `json:"server_env"`
	CustomAgent string `json:"custom_agent"`
	CI          string `json:"ci"`
	MCPServer   string `json:"mcp_server"`
}

type accessRunIssued struct {
	Run    accessRunView   `json:"run"`
	Token  secretJSONBytes `json:"token"`
	Launch accessLaunch    `json:"launch"`
	Bounds accessBounds    `json:"bounds"`
}

func (r *accessRunIssued) wipeSecrets() { r.Token.wipe() }

func accessBundleNotFound(err error) error {
	if errors.Is(err, store.ErrAccessBundleNotFound) {
		return errStatus(http.StatusNotFound, "access bundle not found")
	}
	return err
}

func requestAuthzPrincipal(ctx context.Context) (authz.Principal, error) {
	p, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok || p.Subject == "" {
		return authz.Principal{}, errStatus(http.StatusUnauthorized, "an authenticated principal is required")
	}
	return p, nil
}

func plainText(s string, max int, field string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return "", errStatus(http.StatusBadRequest, fmt.Sprintf("%s is longer than %d characters", field, max))
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", errStatus(http.StatusBadRequest, field+" must not contain control characters")
		}
	}
	return s, nil
}

// normalizeAccessBundle checks a bundle request and returns it in canonical
// form. The caller must hold every permission it names (attenuation: nobody can
// hand an agent authority they do not have).
func (a *API) normalizeAccessBundle(ctx context.Context, tenantID string, req accessBundleRequest) (accessBundleRequest, error) {
	var err error
	if req.Name, err = plainText(req.Name, 200, "name"); err != nil {
		return req, err
	}
	if req.Name == "" {
		return req, errStatus(http.StatusBadRequest, "name is required")
	}
	if req.Description, err = plainText(req.Description, 2000, "description"); err != nil {
		return req, err
	}
	if len(req.Permissions) == 0 || len(req.Permissions) > accessBundleMaxPermissions {
		return req, errStatus(http.StatusBadRequest, fmt.Sprintf("a bundle names 1-%d permissions", accessBundleMaxPermissions))
	}
	seen := map[string]bool{}
	perms := make([]string, 0, len(req.Permissions))
	for _, p := range req.Permissions {
		p = strings.TrimSpace(p)
		if seen[p] {
			return req, errStatus(http.StatusBadRequest, "permission "+p+" is listed twice")
		}
		seen[p] = true
		if accessBundleRefused[authz.Permission(p)] {
			return req, errStatus(http.StatusUnprocessableEntity, "a bundle cannot carry "+p+
				": a run must never manage access or mint a credential that outlives its grants")
		}
		perms = append(perms, p)
	}
	if err := a.validatePermissionScopes(perms); err != nil {
		return req, err
	}
	if err := requireHeldAccessPermissions(ctx, tenantID, perms, "a bundle"); err != nil {
		return req, err
	}
	sort.Strings(perms)
	req.Permissions = perms
	audiences := make([]string, 0, len(req.Audiences))
	seenAudience := map[string]bool{}
	for _, au := range req.Audiences {
		au = strings.TrimSpace(au)
		if !accessBundleAudiences[au] {
			return req, errStatus(http.StatusBadRequest, "audience must be custom_agent, ci or mcp_server")
		}
		if !seenAudience[au] {
			seenAudience[au] = true
			audiences = append(audiences, au)
		}
	}
	sort.Strings(audiences)
	req.Audiences = audiences
	if req.MaxRunTTLSeconds == 0 {
		req.MaxRunTTLSeconds = accessBundleDefaultRunTTL
	}
	if req.MaxRunTTLSeconds < accessBundleMinRunTTL || req.MaxRunTTLSeconds > accessBundleMaxRunTTL {
		return req, errStatus(http.StatusBadRequest, fmt.Sprintf("max_run_ttl_seconds must be %d-%d", accessBundleMinRunTTL, accessBundleMaxRunTTL))
	}
	if req.AccessTargets, err = normalizeAccessTargets(req.AccessTargets, req.Permissions); err != nil {
		return req, err
	}
	return req, nil
}

// requireHeldAccessPermissions refuses permissions the caller does not hold.
func requireHeldAccessPermissions(ctx context.Context, tenantID string, perms []string, what string) error {
	principal, err := requestAuthzPrincipal(ctx)
	if err != nil {
		return err
	}
	target := authz.Scope{TenantID: tenantID}
	for _, p := range perms {
		if !principal.Can(authz.Permission(p), target) {
			return errStatus(http.StatusForbidden, "cannot give "+what+" the permission "+p+" that you do not hold")
		}
	}
	return nil
}

//trstctl:mutation
func (a *API) createAccessBundle(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req accessBundleRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req, err := a.normalizeAccessBundle(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		if _, err := a.store.GetAccessBundleByName(ctx, tenantID, req.Name); err == nil {
			return 0, nil, errStatus(http.StatusConflict, "an access bundle named "+req.Name+" already exists")
		} else if !errors.Is(err, store.ErrAccessBundleNotFound) {
			return 0, nil, err
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		id := googleuuid.NewString()
		if err := a.orch.SaveAccessBundle(ctx, tenantID, projections.AccessBundleSaved{
			ID: id, Name: req.Name, Description: req.Description, Permissions: req.Permissions, Audiences: req.Audiences,
			MaxRunTTLSeconds: req.MaxRunTTLSeconds, Revision: 1, SavedBy: subject, AccessTargets: req.AccessTargets,
		}); err != nil {
			return 0, nil, err
		}
		view, err := a.accessBundleDetail(ctx, tenantID, id)
		return http.StatusCreated, view, err
	})
}

//trstctl:mutation
func (a *API) updateAccessBundle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req accessBundleRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		current, err := a.store.GetAccessBundle(ctx, tenantID, id)
		if err != nil {
			return 0, nil, accessBundleNotFound(err)
		}
		if req.Revision != current.Revision {
			return 0, nil, errStatus(http.StatusConflict, fmt.Sprintf(
				"the bundle is at revision %d, not %d; read it again and resend your change", current.Revision, req.Revision))
		}
		req, err = a.normalizeAccessBundle(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		if !strings.EqualFold(req.Name, current.Name) {
			if other, err := a.store.GetAccessBundleByName(ctx, tenantID, req.Name); err == nil && other.ID != id {
				return 0, nil, errStatus(http.StatusConflict, "an access bundle named "+req.Name+" already exists")
			} else if err != nil && !errors.Is(err, store.ErrAccessBundleNotFound) {
				return 0, nil, err
			}
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.SaveAccessBundle(ctx, tenantID, projections.AccessBundleSaved{
			ID: id, Name: req.Name, Description: req.Description, Permissions: req.Permissions, Audiences: req.Audiences,
			MaxRunTTLSeconds: req.MaxRunTTLSeconds, Revision: current.Revision + 1, SavedBy: subject, AccessTargets: req.AccessTargets,
		}); err != nil {
			return 0, nil, err
		}
		view, err := a.accessBundleDetail(ctx, tenantID, id)
		return http.StatusOK, view, err
	})
}

//trstctl:mutation
func (a *API) deleteAccessBundle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		bundle, err := a.store.GetAccessBundle(ctx, tenantID, id)
		if err != nil {
			return 0, nil, accessBundleNotFound(err)
		}
		stats, err := a.store.AccessBundleStatsFor(ctx, tenantID, time.Now())
		if err != nil {
			return 0, nil, err
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.DeleteAccessBundle(ctx, tenantID, projections.AccessBundleDeleted{ID: id, DeletedBy: subject}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, accessBundleDeletedResponse{
			ID: id, Name: bundle.Name, Deleted: true, GrantsAffected: stats[id].LiveGrants, RunsAffected: stats[id].ActiveRuns,
			DeletedAt: time.Now().UTC(),
		}, nil
	})
}

func (a *API) listAccessBundles(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	bundles, err := a.store.ListAccessBundles(r.Context(), tenantID, accessBundleListLimit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	stats, err := a.store.AccessBundleStatsFor(r.Context(), tenantID, time.Now())
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]accessBundleView, 0, len(bundles))
	for _, b := range bundles {
		items = append(items, toAccessBundleView(b, stats[b.ID]))
	}
	a.writeJSON(w, http.StatusOK, accessBundleListResponse{Items: items})
}

func (a *API) getAccessBundle(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	view, err := a.accessBundleDetail(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, accessBundleNotFound(err))
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

func toAccessBundleView(b store.AccessBundle, st store.AccessBundleStats) accessBundleView {
	return accessBundleView{
		ID: b.ID, Name: b.Name, Description: b.Description, Permissions: nonNilStringSlice(b.Permissions),
		Audiences: nonNilStringSlice(b.Audiences), MaxRunTTLSeconds: b.MaxRunTTLSeconds, Revision: b.Revision,
		CreatedBy: b.CreatedBy, CreatedAt: b.CreatedAt.UTC(), UpdatedAt: b.UpdatedAt.UTC(), LiveGrants: st.LiveGrants, ActiveRuns: st.ActiveRuns,
		AccessTargets: nonNilAccessTargets(b.AccessTargets),
	}
}

func nonNilAccessTargets(t []store.AccessBundleTarget) []store.AccessBundleTarget {
	if t == nil {
		return []store.AccessBundleTarget{}
	}
	return t
}

// normalizeAccessTargets checks and sorts the accounts a bundle delegates:
// at most accessBundleMaxTargets PAM targets, each named once with one to
// accessBundleMaxTargetRoles roles. Naming any needs the bundle to carry
// access:sessions.open, without which a run could open none of them.
func normalizeAccessTargets(targets []store.AccessBundleTarget, perms []string) ([]store.AccessBundleTarget, error) {
	if len(targets) == 0 {
		return []store.AccessBundleTarget{}, nil
	}
	if len(targets) > accessBundleMaxTargets {
		return nil, errStatus(http.StatusBadRequest, fmt.Sprintf("a bundle names at most %d access targets", accessBundleMaxTargets))
	}
	if !slices.Contains(perms, string(authz.AccessSessionsOpen)) {
		return nil, errStatus(http.StatusUnprocessableEntity, "a bundle that names access targets carries access:sessions.open, without which its runs could open none")
	}
	out := make([]store.AccessBundleTarget, 0, len(targets))
	seen := map[string]bool{}
	for _, t := range targets {
		t.TargetType, t.TargetID = strings.TrimSpace(t.TargetType), strings.TrimSpace(t.TargetID)
		if !slices.Contains(accessBundleTargetTypes, t.TargetType) {
			return nil, errStatus(http.StatusBadRequest, "access target type "+t.TargetType+" is not a privileged access target type")
		}
		if !accessBundleName.MatchString(t.TargetID) {
			return nil, errStatus(http.StatusBadRequest, "access target id must be 1-64 lowercase letters, digits, - or _")
		}
		key := t.TargetType + "/" + t.TargetID
		if seen[key] {
			return nil, errStatus(http.StatusBadRequest, "access target "+key+" is listed twice")
		}
		seen[key] = true
		if len(t.Roles) == 0 || len(t.Roles) > accessBundleMaxTargetRoles {
			return nil, errStatus(http.StatusBadRequest, fmt.Sprintf("access target %s names 1-%d roles", key, accessBundleMaxTargetRoles))
		}
		roles := make([]string, 0, len(t.Roles))
		for _, role := range t.Roles {
			role = strings.TrimSpace(role)
			if !accessBundleName.MatchString(role) {
				return nil, errStatus(http.StatusBadRequest, "access target role must be 1-64 lowercase letters, digits, - or _")
			}
			if !slices.Contains(roles, role) {
				roles = append(roles, role)
			}
		}
		sort.Strings(roles)
		out = append(out, store.AccessBundleTarget{TargetType: t.TargetType, TargetID: t.TargetID, Roles: roles})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].TargetType+"/"+out[i].TargetID < out[j].TargetType+"/"+out[j].TargetID
	})
	return out, nil
}

func (a *API) accessBundleDetail(ctx context.Context, tenantID, id string) (accessBundleView, error) {
	b, err := a.store.GetAccessBundle(ctx, tenantID, id)
	if err != nil {
		return accessBundleView{}, err
	}
	now := time.Now()
	stats, err := a.store.AccessBundleStatsFor(ctx, tenantID, now)
	if err != nil {
		return accessBundleView{}, err
	}
	view := toAccessBundleView(b, stats[id])
	grants, err := a.store.ListAccessBundleGrants(ctx, tenantID, id, "", accessBundleGrantListLimit)
	if err != nil {
		return accessBundleView{}, err
	}
	live, err := a.liveGrantIDs(ctx, tenantID, grants, now)
	if err != nil {
		return accessBundleView{}, err
	}
	view.Grants = make([]accessBundleGrantView, 0, len(grants))
	for _, g := range grants {
		view.Grants = append(view.Grants, toAccessBundleGrantView(g, live[g.ID]))
	}
	runs, err := a.store.ListAccessBundleRuns(ctx, tenantID, "", id, accessBundleRunViewLimit)
	if err != nil {
		return accessBundleView{}, err
	}
	view.Runs, err = a.accessRunViews(ctx, tenantID, runs, now)
	return view, err
}

// liveGrantIDs marks which of grants give anything now (per principal, with the
// store's live-grant rule, so the view never disagrees with authorization).
func (a *API) liveGrantIDs(ctx context.Context, tenantID string, grants []store.AccessBundleGrant, now time.Time) (map[string]bool, error) {
	live := map[string]bool{}
	checked := map[string]bool{}
	for _, g := range grants {
		if g.RemovedAt != nil || checked[g.Principal] {
			continue
		}
		checked[g.Principal] = true
		liveGrants, err := a.store.LiveAccessBundleGrants(ctx, tenantID, g.Principal, now)
		if err != nil {
			return nil, err
		}
		for _, lg := range liveGrants {
			live[lg.ID] = true
		}
	}
	return live, nil
}

func toAccessBundleGrantView(g store.AccessBundleGrant, live bool) accessBundleGrantView {
	return accessBundleGrantView{
		ID: g.ID, BundleID: g.BundleID, PrincipalType: g.PrincipalType, Principal: g.Principal, ExpiresAt: utcTime(g.ExpiresAt),
		GrantedBy: g.GrantedBy, GrantedAt: g.GrantedAt.UTC(), RemovedAt: utcTime(g.RemovedAt), RemovedBy: g.RemovedBy,
		RemovedReason: g.RemovedReason, Live: live,
	}
}

func utcTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func validAccessPrincipal(principal string) (string, error) {
	principal, err := plainText(principal, 320, "principal")
	if err != nil {
		return "", err
	}
	if principal == "" {
		return "", errStatus(http.StatusBadRequest, "principal is required")
	}
	if strings.HasPrefix(principal, orchestrator.BundleRunSubjectPrefix) {
		return "", errStatus(http.StatusBadRequest, "a run is not a principal that can hold grants")
	}
	return principal, nil
}

//trstctl:mutation
func (a *API) grantAccessBundle(w http.ResponseWriter, r *http.Request) {
	bundleID := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req accessBundleGrantRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		bundle, err := a.store.GetAccessBundle(ctx, tenantID, bundleID)
		if err != nil {
			return 0, nil, accessBundleNotFound(err)
		}
		principal, err := validAccessPrincipal(req.Principal)
		if err != nil {
			return 0, nil, err
		}
		now := time.Now()
		switch req.PrincipalType {
		case "user":
			member, err := a.store.GetTenantMember(ctx, tenantID, principal)
			if err != nil || member.Status != "active" {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, "a user grant needs an active member of this tenant")
			}
		case "machine":
		default:
			return 0, nil, errStatus(http.StatusBadRequest, "principal_type must be user or machine")
		}
		if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
			return 0, nil, errStatus(http.StatusBadRequest, "expires_at must be in the future")
		}
		// Granting delegates the bundle's permissions: the granter must hold them.
		if err := requireHeldAccessPermissions(ctx, tenantID, bundle.Permissions, "a grant"); err != nil {
			return 0, nil, err
		}
		existing, err := a.store.ListAccessBundleGrants(ctx, tenantID, bundleID, principal, accessBundleGrantListLimit)
		if err != nil {
			return 0, nil, err
		}
		for _, g := range existing {
			if g.RemovedAt == nil && (g.ExpiresAt == nil || g.ExpiresAt.After(now)) {
				return 0, nil, errStatus(http.StatusConflict, "this principal already holds the bundle through grant "+g.ID)
			}
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		id := googleuuid.NewString()
		var expires *time.Time
		if req.ExpiresAt != nil {
			t := req.ExpiresAt.UTC()
			expires = &t
		}
		if err := a.orch.GrantAccessBundle(ctx, tenantID, projections.AccessBundleGranted{
			ID: id, BundleID: bundleID, PrincipalType: req.PrincipalType, Principal: principal, ExpiresAt: expires, GrantedBy: subject,
		}); err != nil {
			return 0, nil, err
		}
		change, err := a.accessGrantChange(ctx, tenantID, id)
		return http.StatusCreated, change, err
	})
}

//trstctl:mutation
func (a *API) ungrantAccessBundle(w http.ResponseWriter, r *http.Request) {
	bundleID, grantID := r.PathValue("id"), r.PathValue("grant_id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		reason, err := plainText(r.URL.Query().Get("reason"), 200, "reason")
		if err != nil {
			return 0, nil, err
		}
		grant, err := a.store.GetAccessBundleGrant(ctx, tenantID, grantID)
		if err != nil || grant.BundleID != bundleID {
			return 0, nil, errStatus(http.StatusNotFound, "access bundle grant not found")
		}
		if grant.RemovedAt == nil {
			subject, err := requestPrincipalSubject(ctx)
			if err != nil {
				return 0, nil, err
			}
			if err := a.orch.UngrantAccessBundle(ctx, tenantID, projections.AccessBundleUngranted{
				ID: grantID, BundleID: bundleID, RemovedBy: subject, Reason: reason,
			}); err != nil {
				return 0, nil, err
			}
		}
		change, err := a.accessGrantChange(ctx, tenantID, grantID)
		return http.StatusOK, change, err
	})
}

func (a *API) accessGrantChange(ctx context.Context, tenantID, grantID string) (accessBundleGrantChange, error) {
	grant, err := a.store.GetAccessBundleGrant(ctx, tenantID, grantID)
	if err != nil {
		return accessBundleGrantChange{}, err
	}
	authority, err := a.accessAuthority(ctx, tenantID, grant.Principal)
	if err != nil {
		return accessBundleGrantChange{}, err
	}
	live := false
	for _, g := range authority.Grants {
		live = live || g.ID == grantID
	}
	return accessBundleGrantChange{Grant: toAccessBundleGrantView(grant, live), Authority: authority}, nil
}

func (a *API) getAccessAuthority(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	principal, err := validAccessPrincipal(r.URL.Query().Get("principal"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	view, err := a.accessAuthority(r.Context(), tenantID, principal)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

// accessAuthority is what principal holds now through access bundles.
func (a *API) accessAuthority(ctx context.Context, tenantID, principal string) (accessAuthorityView, error) {
	now := time.Now()
	held, err := a.store.EffectiveAuthority(ctx, tenantID, principal, now)
	if err != nil {
		return accessAuthorityView{}, err
	}
	view := accessAuthorityView{Principal: principal, Permissions: []accessAuthorityPermission{}, Grants: []accessBundleGrantView{},
		Runs: []accessRunView{}, ComputedAt: now.UTC()}
	names := make([]string, 0, len(held))
	for p := range held {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		via := make([]accessAuthorityVia, 0, len(held[p]))
		for _, src := range held[p] {
			via = append(via, accessAuthorityVia{GrantID: src.GrantID, BundleID: src.BundleID, BundleName: src.BundleName, ExpiresAt: utcTime(src.ExpiresAt)})
		}
		view.Permissions = append(view.Permissions, accessAuthorityPermission{Permission: p, Via: via})
	}
	grants, err := a.store.LiveAccessBundleGrants(ctx, tenantID, principal, now)
	if err != nil {
		return accessAuthorityView{}, err
	}
	maxTTL := 0
	for _, g := range grants {
		view.Grants = append(view.Grants, toAccessBundleGrantView(g, true))
		if b, err := a.store.GetAccessBundle(ctx, tenantID, g.BundleID); err == nil && b.MaxRunTTLSeconds > maxTTL {
			maxTTL = b.MaxRunTTLSeconds
		}
	}
	runs, err := a.store.ListAccessBundleRuns(ctx, tenantID, principal, "", accessBundleRunViewLimit)
	if err != nil {
		return accessAuthorityView{}, err
	}
	all, err := a.accessRunViews(ctx, tenantID, runs, now)
	if err != nil {
		return accessAuthorityView{}, err
	}
	for _, run := range all {
		if run.Status == "active" {
			view.Runs = append(view.Runs, run)
		}
	}
	view.Bounds = accessBounds{Revocation: accessBoundRevocation, Outage: accessBoundOutage, Lasting: accessBoundLasting, MaxRunTTLSeconds: maxTTL}
	return view, nil
}

// accessRunViews says what each run may do now and how it came to.
func (a *API) accessRunViews(ctx context.Context, tenantID string, runs []store.AccessBundleRun, now time.Time) ([]accessRunView, error) {
	out := make([]accessRunView, 0, len(runs))
	bundles := map[string]store.AccessBundle{}
	for _, run := range runs {
		_, effective, err := a.store.RunAuthority(ctx, tenantID, run.ID, now)
		if err != nil {
			return nil, err
		}
		view := accessRunView{
			ID: run.ID, Principal: run.Principal, BundleIDs: nonNilStringSlice(run.BundleIDs), BundleNames: []string{},
			GrantIDs: nonNilStringSlice(run.GrantIDs), Permissions: nonNilStringSlice(run.Permissions),
			Effective: nonNilStringSlice(effective), Label: run.Label, ExpiresAt: run.ExpiresAt.UTC(), IssuedBy: run.IssuedBy,
			IssuedAt: run.IssuedAt.UTC(), RevokedAt: utcTime(run.RevokedAt), RevokedBy: run.RevokedBy, Chain: []accessDelegationLink{},
		}
		tok, err := a.store.GetAPIToken(ctx, tenantID, run.ID)
		switch {
		case run.RevokedAt != nil || (err == nil && tok.RevokedAt != nil):
			view.Status = "revoked"
			view.Effective = []string{}
		case !run.ExpiresAt.After(now):
			view.Status = "expired"
		case len(effective) == 0:
			view.Status = "no_authority"
		default:
			view.Status = "active"
		}
		for _, id := range run.BundleIDs {
			b, ok := bundles[id]
			if !ok {
				if got, err := a.store.GetAccessBundle(ctx, tenantID, id); err == nil {
					b, ok = got, true
					bundles[id] = got
				}
			}
			if ok {
				view.BundleNames = append(view.BundleNames, b.Name)
				view.Chain = append(view.Chain, accessDelegationLink{Step: "bundle_saved", Actor: b.CreatedBy, At: b.UpdatedAt.UTC(),
					Detail: fmt.Sprintf("%s, revision %d", b.Name, b.Revision)})
			} else {
				view.Chain = append(view.Chain, accessDelegationLink{Step: "bundle_saved", Detail: "bundle " + id + " is deleted"})
			}
		}
		for _, id := range run.GrantIDs {
			if g, err := a.store.GetAccessBundleGrant(ctx, tenantID, id); err == nil {
				detail := g.PrincipalType + " grant to " + g.Principal
				if g.RemovedAt != nil {
					detail += ", removed"
				}
				view.Chain = append(view.Chain, accessDelegationLink{Step: "granted", Actor: g.GrantedBy, At: g.GrantedAt.UTC(), Detail: detail})
			}
		}
		view.Chain = append(view.Chain, accessDelegationLink{Step: "run_issued", Actor: run.IssuedBy, At: run.IssuedAt.UTC(),
			Detail: "for " + run.Principal + " until " + run.ExpiresAt.UTC().Format(time.RFC3339)})
		out = append(out, view)
	}
	return out, nil
}

//trstctl:mutation
func (a *API) issueAccessRun(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req accessRunRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		caller, err := requestAuthzPrincipal(ctx)
		if err != nil {
			return 0, nil, err
		}
		if _, isRun := orchestrator.BundleRunPrincipal(caller.Subject); isRun {
			return 0, nil, errStatus(http.StatusForbidden, "a run cannot mint another run")
		}
		if strings.TrimSpace(req.Principal) == "" {
			req.Principal = caller.Subject
		}
		principal, err := validAccessPrincipal(req.Principal)
		if err != nil {
			return 0, nil, err
		}
		label, err := plainText(req.Label, accessBundleLabelMax, "label")
		if err != nil {
			return 0, nil, err
		}
		if len(req.BundleIDs) == 0 || len(req.BundleIDs) > accessBundleMaxBundlesInRun {
			return 0, nil, errStatus(http.StatusBadRequest, fmt.Sprintf("a run names 1-%d bundle_ids", accessBundleMaxBundlesInRun))
		}
		now := time.Now()
		bundleIDs := map[string]bool{}
		offered := map[string]bool{}
		maxTTL := accessBundleMaxRunTTL
		for _, id := range req.BundleIDs {
			if _, err := googleuuid.Parse(id); err != nil || bundleIDs[id] {
				return 0, nil, errStatus(http.StatusBadRequest, "bundle_ids must be distinct bundle IDs")
			}
			b, err := a.store.GetAccessBundle(ctx, tenantID, id)
			if err != nil {
				return 0, nil, accessBundleNotFound(err)
			}
			bundleIDs[id] = true
			for _, p := range b.Permissions {
				offered[p] = true
			}
			maxTTL = min(maxTTL, b.MaxRunTTLSeconds)
		}
		var grantIDs []string
		held := map[string]bool{}
		live, err := a.store.LiveAccessBundleGrants(ctx, tenantID, principal, now)
		if err != nil {
			return 0, nil, err
		}
		for _, g := range live {
			if bundleIDs[g.BundleID] {
				grantIDs = append(grantIDs, g.ID)
				held[g.BundleID] = true
			}
		}
		for id := range bundleIDs {
			if !held[id] {
				return 0, nil, errStatus(http.StatusForbidden, principal+" holds no live grant of bundle "+id)
			}
		}
		perms := req.Permissions
		if len(perms) == 0 {
			for p := range offered {
				perms = append(perms, p)
			}
		}
		seen := map[string]bool{}
		for _, p := range perms {
			if !offered[p] || seen[p] {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, "permission "+p+" is not given by the named bundles, or is listed twice")
			}
			seen[p] = true
		}
		sort.Strings(perms)
		// A run for someone else is an administrative act, attenuated like a token.
		if principal != caller.Subject {
			if !caller.Can(authz.AccessWrite, authz.Scope{TenantID: tenantID}) {
				return 0, nil, errStatus(http.StatusForbidden, "minting a run for another principal needs access:write")
			}
			if err := requireHeldAccessPermissions(ctx, tenantID, perms, "a run"); err != nil {
				return 0, nil, err
			}
		}
		ttl := req.TTLSeconds
		if ttl == 0 {
			ttl = min(accessBundleDefaultRunTTL, maxTTL)
		}
		if ttl < accessBundleMinRunTTL || ttl > maxTTL {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, fmt.Sprintf("ttl_seconds must be %d-%d for these bundles", accessBundleMinRunTTL, maxTTL))
		}
		expires := now.Add(time.Duration(ttl) * time.Second).UTC().Truncate(time.Second)
		if limit := a.apiTokenMaxLifetime; limit > 0 && expires.After(now.Add(limit)) {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "ttl_seconds is longer than the maximum API token lifetime (auth.api_tokens.max_lifetime)")
		}
		ids := make([]string, 0, len(bundleIDs))
		for id := range bundleIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		sort.Strings(grantIDs)
		rec, raw, err := a.orch.IssueAccessBundleRun(ctx, tenantID, projections.AccessBundleRunIssued{
			Principal: principal, BundleIDs: ids, GrantIDs: grantIDs, Permissions: perms, Label: label, ExpiresAt: expires,
			IssuedBy: caller.Subject,
		})
		if err != nil {
			return 0, nil, err
		}
		resp := &accessRunIssued{Token: secretJSONBytes(raw), Launch: accessRunLaunch(),
			Bounds: accessBounds{Revocation: accessBoundRevocation, Outage: accessBoundOutage, Lasting: accessBoundLasting, MaxRunTTLSeconds: maxTTL}}
		run, err := a.store.GetAccessBundleRun(ctx, tenantID, rec.ID)
		if err != nil {
			resp.wipeSecrets()
			return 0, nil, err
		}
		views, err := a.accessRunViews(ctx, tenantID, []store.AccessBundleRun{run}, time.Now())
		if err != nil {
			resp.wipeSecrets()
			return 0, nil, err
		}
		resp.Run = views[0]
		return http.StatusCreated, resp, nil
	})
}

// accessRunLaunch is how to hand a run's credential to what it runs. The
// token itself is the response's token field; the lines name only variables.
func accessRunLaunch() accessLaunch {
	return accessLaunch{ // #nosec G101 -- environment variable names and placeholder launch lines; no credential value present (CWE-798)
		TokenEnv:    "TRSTCTL_TOKEN",
		ServerEnv:   "TRSTCTL_SERVER",
		CustomAgent: `TRSTCTL_SERVER=<control plane URL> TRSTCTL_TOKEN=<this run's token> ./your-agent`,
		CI:          `Put this run's token in a masked CI variable named TRSTCTL_TOKEN for this job only; the job's trstctl-cli and SDK calls use it, and it stops working at expires_at`,
		MCPServer:   `{"command": "trstctl-cli", "args": ["mcp", "serve"], "env": {"TRSTCTL_SERVER": "<control plane URL>", "TRSTCTL_CA_FILE": "<control plane CA bundle>", "TRSTCTL_TOKEN": "<this run's token>"}}`,
	}
}

func (a *API) listAccessRuns(w http.ResponseWriter, r *http.Request) {
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
	q := r.URL.Query()
	bundle := strings.TrimSpace(q.Get("bundle"))
	if bundle != "" {
		if _, err := googleuuid.Parse(bundle); err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "bundle must be a bundle ID"))
			return
		}
	}
	runs, err := a.store.ListAccessBundleRuns(r.Context(), tenantID, strings.TrimSpace(q.Get("principal")), bundle, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	views, err := a.accessRunViews(r.Context(), tenantID, runs, time.Now())
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, accessRunListResponse{Items: views})
}

//trstctl:mutation
func (a *API) revokeAccessRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mutateDurable(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		run, err := a.store.GetAccessBundleRun(ctx, tenantID, id)
		if err != nil {
			return 0, nil, errStatus(http.StatusNotFound, "access run not found")
		}
		caller, err := requestAuthzPrincipal(ctx)
		if err != nil {
			return 0, nil, err
		}
		if caller.Subject != run.Principal && !caller.Can(authz.AccessWrite, authz.Scope{TenantID: tenantID}) {
			return 0, nil, errStatus(http.StatusForbidden, "revoking another principal's run needs access:write")
		}
		if run.RevokedAt == nil {
			if err := a.orch.RevokeAccessBundleRun(ctx, tenantID, id, caller.Subject); err != nil {
				return 0, nil, err
			}
			if run, err = a.store.GetAccessBundleRun(ctx, tenantID, id); err != nil {
				return 0, nil, err
			}
		}
		views, err := a.accessRunViews(ctx, tenantID, []store.AccessBundleRun{run}, time.Now())
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, views[0], nil
	})
}

// bundleRunPrincipal is a run token's principal (A251): its scopes are the
// run's issued permissions that its grants still give, derived again for this
// request. A run with nothing left, or one never recorded, is refused like an
// unknown token.
func (a *API) bundleRunPrincipal(ctx context.Context, rec store.APITokenRecord) (authz.Principal, error) {
	_, allowed, err := a.store.RunAuthority(ctx, rec.TenantID, rec.ID, time.Now())
	if err != nil {
		if errors.Is(err, store.ErrAccessBundleNotFound) {
			return authz.Principal{}, errors.New("api: access bundle run is not recorded")
		}
		return authz.Principal{}, err
	}
	scopes := make([]string, 0, len(allowed))
	for _, p := range allowed {
		if !accessBundleRefused[authz.Permission(p)] {
			scopes = append(scopes, p)
		}
	}
	if len(scopes) == 0 {
		return authz.Principal{}, errors.New("api: access bundle run holds no authority")
	}
	principal := auth.APIToken{TenantID: rec.TenantID, Subject: rec.Subject, Scopes: scopes, Delegated: rec.Delegated}.Principal()
	principal.RunID = rec.ID
	return principal, nil
}

// accessActivityExportMax bounds one export; narrow the filters for more.
const accessActivityExportMax = 10000

// accessActivityExcludes is what an activity row never carries, stated in
// every export.
var accessActivityExcludes = []string{"credentials", "token values and token hashes", "request and response bodies", "secret values"}

type accessActivityRow struct {
	At          time.Time `json:"at"`
	Action      string    `json:"action"`
	BundleIDs   []string  `json:"bundle_ids"`
	BundleNames []string  `json:"bundle_names"`
	GrantID     string    `json:"grant_id,omitempty"`
	RunID       string    `json:"run_id,omitempty"`
	Principal   string    `json:"principal,omitempty"`
	Actor       string    `json:"actor,omitempty"`
	Detail      string    `json:"detail,omitempty"`
}

type accessActivityList struct {
	Items      []accessActivityRow `json:"items"`
	NextCursor string              `json:"next_cursor"`
}

type accessActivityFilters struct {
	Bundle    string `json:"bundle,omitempty"`
	Principal string `json:"principal,omitempty"`
	Query     string `json:"q,omitempty"`
}

type accessActivityExport struct {
	Kind        string                `json:"kind"`
	GeneratedAt time.Time             `json:"generated_at"`
	Filters     accessActivityFilters `json:"filters"`
	Fields      []string              `json:"fields"`
	Excludes    []string              `json:"excludes"`
	Rows        int                   `json:"rows"`
	Truncated   bool                  `json:"truncated"`
	Items       []accessActivityRow   `json:"items"`
}

func toAccessActivityRow(a store.AccessBundleActivity) accessActivityRow {
	return accessActivityRow{
		At: a.At.UTC(), Action: a.Action, BundleIDs: nonNilStringSlice(a.BundleIDs), BundleNames: nonNilStringSlice(a.BundleNames),
		GrantID: a.GrantID, RunID: a.RunID, Principal: a.Principal, Actor: a.Actor, Detail: a.Detail,
	}
}

func accessActivityFilter(r *http.Request) (store.AccessBundleActivityFilter, error) {
	q := r.URL.Query()
	f := store.AccessBundleActivityFilter{BundleID: strings.TrimSpace(q.Get("bundle")), Principal: strings.TrimSpace(q.Get("principal"))}
	if f.BundleID != "" {
		if _, err := googleuuid.Parse(f.BundleID); err != nil {
			return f, errStatus(http.StatusBadRequest, "bundle must be a bundle ID")
		}
	}
	text, err := plainText(q.Get("q"), 200, "q")
	if err != nil {
		return f, err
	}
	f.Query = text
	return f, nil
}

func (a *API) listAccessActivity(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	f, err := accessActivityFilter(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if f.Limit, err = pageLimit(r); err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	if c := r.URL.Query().Get("cursor"); c != "" {
		raw, decodeErr := base64.RawURLEncoding.DecodeString(c)
		at, seq, parseErr := store.ParseAccessBundleActivityCursor(string(raw))
		if decodeErr != nil || parseErr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
			return
		}
		f.BeforeAt, f.BeforeSequence = &at, seq
	}
	rows, err := a.store.ListAccessBundleActivity(r.Context(), tenantID, f)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := accessActivityList{Items: make([]accessActivityRow, 0, len(rows))}
	for _, row := range rows {
		out.Items = append(out.Items, toAccessActivityRow(row))
	}
	if len(rows) == f.Limit {
		out.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(store.AccessBundleActivityCursor(rows[len(rows)-1])))
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) exportAccessActivity(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	f, err := accessActivityFilter(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := accessActivityExport{
		Kind: "trstctl.access-activity-export/v1", GeneratedAt: time.Now().UTC(),
		Filters:  accessActivityFilters{Bundle: f.BundleID, Principal: f.Principal, Query: f.Query},
		Fields:   []string{"at", "action", "bundle_ids", "bundle_names", "grant_id", "run_id", "principal", "actor", "detail"},
		Excludes: accessActivityExcludes, Items: []accessActivityRow{},
	}
	f.Limit = 500
	for len(out.Items) < accessActivityExportMax {
		rows, err := a.store.ListAccessBundleActivity(r.Context(), tenantID, f)
		if err != nil {
			a.writeError(w, err)
			return
		}
		for _, row := range rows {
			if len(out.Items) == accessActivityExportMax {
				out.Truncated = true
				break
			}
			out.Items = append(out.Items, toAccessActivityRow(row))
		}
		if len(rows) < f.Limit || out.Truncated {
			break
		}
		last := rows[len(rows)-1]
		at := last.At
		f.BeforeAt, f.BeforeSequence = &at, last.Sequence
	}
	out.Rows = len(out.Items)
	w.Header().Set("Content-Disposition", `attachment; filename="access-activity.json"`)
	a.writeJSON(w, http.StatusOK, out)
}

func accessBundleSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	boolean := func() *Schema { return &Schema{Type: "boolean"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	list := func(item *Schema) *Schema { return &Schema{Type: "array", Items: item} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	audience := &Schema{Type: "string", Enum: []string{"custom_agent", "ci", "mcp_server"}}
	grant := object(map[string]*Schema{"id": str(), "bundle_id": str(), "principal_type": {Type: "string", Enum: []string{"user", "machine"}},
		"principal": str(), "expires_at": ts(), "granted_by": str(), "granted_at": ts(), "removed_at": ts(), "removed_by": str(),
		"removed_reason": str(), "live": boolean()}, "id", "bundle_id", "principal_type", "principal", "granted_by", "granted_at", "live")
	link := object(map[string]*Schema{"step": {Type: "string", Enum: []string{"bundle_saved", "granted", "run_issued"}}, "actor": str(),
		"at": ts(), "detail": str()}, "step", "actor", "at", "detail")
	run := object(map[string]*Schema{"id": str(), "principal": str(), "bundle_ids": list(str()), "bundle_names": list(str()),
		"grant_ids": list(str()), "permissions": list(str()), "effective": list(str()), "label": str(),
		"status": {Type: "string", Enum: []string{"active", "no_authority", "expired", "revoked"}}, "expires_at": ts(),
		"issued_by": str(), "issued_at": ts(), "revoked_at": ts(), "revoked_by": str(), "chain": list(link)},
		"id", "principal", "bundle_ids", "bundle_names", "grant_ids", "permissions", "effective", "status", "expires_at", "issued_by", "issued_at", "chain")
	// A257: the accounts a run may open privileged sessions to.
	accessTarget := object(map[string]*Schema{"target_type": {Type: "string", Enum: accessBundleTargetTypes},
		"target_id": str(), "roles": {Type: "array", Items: str(), MinItems: 1, MaxItems: accessBundleMaxTargetRoles}},
		"target_type", "target_id", "roles")
	accessTargets := &Schema{Type: "array", Items: accessTarget, MaxItems: accessBundleMaxTargets,
		Description: "the accounts this bundle's runs may open privileged sessions to; none means none (A257)"}
	bundle := object(map[string]*Schema{"id": str(), "name": str(), "description": str(), "permissions": list(str()),
		"audiences": list(audience), "max_run_ttl_seconds": integer(), "access_targets": accessTargets, "revision": integer(), "created_by": str(),
		"created_at": ts(), "updated_at": ts(), "live_grants": integer(), "active_runs": integer(), "grants": list(grant), "runs": list(run)},
		"id", "name", "description", "permissions", "audiences", "max_run_ttl_seconds", "access_targets", "revision", "created_by", "created_at", "updated_at",
		"live_grants", "active_runs")
	bounds := object(map[string]*Schema{"revocation": str(), "outage": str(), "lasting": str(), "max_run_ttl_seconds": integer()},
		"revocation", "outage", "lasting", "max_run_ttl_seconds")
	via := object(map[string]*Schema{"grant_id": str(), "bundle_id": str(), "bundle_name": str(), "expires_at": ts()}, "grant_id", "bundle_id", "bundle_name")
	authority := object(map[string]*Schema{"principal": str(),
		"permissions": list(object(map[string]*Schema{"permission": str(), "via": list(via)}, "permission", "via")),
		"grants":      list(grant), "runs": list(run), "bounds": bounds, "computed_at": ts()},
		"principal", "permissions", "grants", "runs", "bounds", "computed_at")
	activity := object(map[string]*Schema{"at": ts(), "action": {Type: "string", Enum: []string{"saved", "deleted", "granted", "ungranted",
		"run_issued", "run_revoked", "run_used"}}, "bundle_ids": list(str()), "bundle_names": list(str()), "grant_id": str(), "run_id": str(),
		"principal": str(), "actor": str(), "detail": str()}, "at", "action", "bundle_ids", "bundle_names")
	return map[string]*Schema{
		"AccessActivityList": object(map[string]*Schema{"items": list(activity), "next_cursor": str()}, "items", "next_cursor"),
		"AccessActivityExport": object(map[string]*Schema{"kind": str(), "generated_at": ts(),
			"filters": object(map[string]*Schema{"bundle": str(), "principal": str(), "q": str()}),
			"fields":  list(str()), "excludes": list(str()), "rows": integer(), "truncated": boolean(), "items": list(activity)},
			"kind", "generated_at", "filters", "fields", "excludes", "rows", "truncated", "items"),
		"AccessBundleRequest": object(map[string]*Schema{"name": str(), "description": str(), "permissions": list(str()),
			"audiences": list(audience), "max_run_ttl_seconds": integer(), "access_targets": accessTargets, "revision": integer()}, "name", "permissions"),
		"AccessBundle":     bundle,
		"AccessBundleList": object(map[string]*Schema{"items": list(bundle)}, "items"),
		"AccessBundleDeleted": object(map[string]*Schema{"id": str(), "name": str(), "deleted": boolean(), "grants_affected": integer(),
			"runs_affected": integer(), "deleted_at": ts()}, "id", "name", "deleted", "grants_affected", "runs_affected", "deleted_at"),
		"AccessBundleGrantRequest": object(map[string]*Schema{"principal_type": {Type: "string", Enum: []string{"user", "machine"}},
			"principal": str(), "expires_at": ts()}, "principal_type", "principal"),
		"AccessBundleGrantChange": object(map[string]*Schema{"grant": grant, "authority": authority}, "grant", "authority"),
		"AccessAuthority":         authority,
		"AccessRunRequest": object(map[string]*Schema{"principal": str(), "bundle_ids": list(str()), "permissions": list(str()),
			"ttl_seconds": integer(), "label": str()}, "bundle_ids"),
		"AccessRun":     run,
		"AccessRunList": object(map[string]*Schema{"items": list(run)}, "items"),
		"AccessRunIssued": object(map[string]*Schema{"run": run, "token": str(),
			"launch": object(map[string]*Schema{"token_env": str(), "server_env": str(), "custom_agent": str(), "ci": str(), "mcp_server": str()},
				"token_env", "server_env", "custom_agent", "ci", "mcp_server"),
			"bounds": bounds}, "run", "token", "launch", "bounds"),
	}
}
