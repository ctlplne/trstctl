package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type roleResponse struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type roleListResponse struct {
	Items []roleResponse `json:"items"`
}

type oidcMappingResponse struct {
	Enabled            bool                `json:"enabled"`
	TenantClaim        string              `json:"tenant_claim,omitempty"`
	GroupsClaim        string              `json:"groups_claim,omitempty"`
	ClaimIsTenant      bool                `json:"claim_is_tenant"`
	DefaultRoles       []string            `json:"default_roles,omitempty"`
	DefaultTenant      string              `json:"default_tenant,omitempty"`
	AllowDefaultTenant bool                `json:"allow_default_tenant"`
	TenantMappings     []AuthTenantMapping `json:"tenant_mappings"`
}

type memberRequest struct {
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Source      string   `json:"source"`
}

type memberResponse struct {
	TenantID       string     `json:"tenant_id"`
	Subject        string     `json:"subject"`
	DisplayName    string     `json:"display_name,omitempty"`
	Email          string     `json:"email,omitempty"`
	Roles          []string   `json:"roles"`
	Source         string     `json:"source"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	OffboardedAt   *time.Time `json:"offboarded_at,omitempty"`
	OffboardedBy   string     `json:"offboarded_by,omitempty"`
	OffboardReason string     `json:"offboard_reason,omitempty"`
}

type memberListResponse struct {
	Items      []memberResponse `json:"items"`
	NextCursor string           `json:"next_cursor"`
}

type offboardMemberRequest struct {
	Reason string `json:"reason"`
}

type offboardMemberResponse struct {
	Member            memberResponse `json:"member"`
	RevokedTokenCount int            `json:"revoked_token_count"`
	RotationEvidence  string         `json:"rotation_evidence"`
}

type apiTokenCreateRequest struct {
	Subject   string     `json:"subject"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type apiTokenResponse struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id"`
	Subject          string     `json:"subject"`
	Scopes           []string   `json:"scopes"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedBy        string     `json:"revoked_by,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
}

type apiTokenCreateResponse struct {
	apiTokenResponse
	Token string `json:"token"`
}

func (r *apiTokenCreateResponse) wipeSecrets() { r.Token = "" }

type apiTokenListResponse struct {
	Items      []apiTokenResponse `json:"items"`
	NextCursor string             `json:"next_cursor"`
}

type apiTokenRevokeRequest struct {
	Reason string `json:"reason"`
}

func (a *API) listAccessRoles(w http.ResponseWriter, _ *http.Request) {
	roles := a.roles.Roles()
	items := make([]roleResponse, 0, len(roles))
	for _, role := range roles {
		perms := make([]string, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			perms = append(perms, string(p))
		}
		items = append(items, roleResponse{Name: role.Name, Permissions: perms})
	}
	a.writeJSON(w, http.StatusOK, roleListResponse{Items: items})
}

func (a *API) getOIDCMappingStatus(w http.ResponseWriter, _ *http.Request) {
	if a.auth == nil {
		a.writeJSON(w, http.StatusOK, oidcMappingResponse{Enabled: false, TenantMappings: []AuthTenantMapping{}})
		return
	}
	a.writeJSON(w, http.StatusOK, oidcMappingResponse{
		Enabled: a.auth.OIDCEnabled, TenantClaim: a.auth.TenantClaim, GroupsClaim: a.auth.GroupsClaim,
		ClaimIsTenant: a.auth.ClaimIsTenant, DefaultRoles: append([]string(nil), a.auth.DefaultRoles...),
		DefaultTenant: a.auth.DefaultTenant, AllowDefaultTenant: a.auth.AllowDefaultTenant,
		TenantMappings: append([]AuthTenantMapping(nil), a.auth.TenantMappings...),
	})
}

func (a *API) listMembers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	after, err := accessCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid cursor"))
		return
	}
	includeOffboarded := r.URL.Query().Get("include_offboarded") == "true"
	members, err := a.store.ListTenantMembersPage(r.Context(), tenantID, after, includeOffboarded, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]memberResponse, 0, len(members))
	for _, m := range members {
		items = append(items, toMemberResponse(m))
	}
	next := ""
	if len(members) == limit {
		next = encodeAccessCursor(members[len(members)-1].Subject)
	}
	a.writeJSON(w, http.StatusOK, memberListResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) upsertMember(w http.ResponseWriter, r *http.Request) {
	subject := strings.TrimSpace(r.PathValue("subject"))
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if subject == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "member subject is required")
		}
		var req memberRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := a.validateRoleNames(req.Roles); err != nil {
			return 0, nil, err
		}
		if err := a.authorizeRoleAssignment(ctx, tenantID, subject, req.Roles, req.Roles != nil); err != nil {
			return 0, nil, err
		}
		source := req.Source
		if source == "" {
			source = "manual"
		}
		member, err := a.orch.UpsertTenantMember(ctx, tenantID, store.TenantMember{
			Subject: subject, DisplayName: req.DisplayName, Email: req.Email,
			Roles: req.Roles, Source: source,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toMemberResponse(member), nil
	})
}

func (a *API) authorizeRoleAssignment(ctx context.Context, tenantID, subject string, roles []string, rolesProvided bool) error {
	if !rolesProvided {
		return nil
	}
	principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok || principal.Subject == "" {
		return errStatus(http.StatusUnauthorized, "missing authenticated principal for role assignment")
	}
	if principal.Subject == subject {
		if err := a.recordRoleAssignDecision(ctx, tenantID, principal, subject, roles, "deny", "self role assignment is not allowed"); err != nil {
			return err
		}
		return errStatus(http.StatusForbidden, "self role assignment is not allowed")
	}
	target := authz.Scope{TenantID: tenantID}
	if !principal.Can(authz.AccessRoleAssign, target) {
		reason := string(authz.AccessRoleAssign) + " is required to assign member roles"
		if err := a.recordRoleAssignDecision(ctx, tenantID, principal, subject, roles, "deny", reason); err != nil {
			return err
		}
		return errStatus(http.StatusForbidden, reason)
	}
	return a.recordRoleAssignDecision(ctx, tenantID, principal, subject, roles, "allow", "")
}

func (a *API) recordRoleAssignDecision(ctx context.Context, tenantID string, principal authz.Principal, subject string, roles []string, decision, reason string) error {
	if a.orch == nil {
		return nil
	}
	return a.orch.RecordAuthzDecision(ctx, tenantID, orchestrator.AuthzDecision{
		Actor:      principal.Subject,
		Permission: string(authz.AccessRoleAssign),
		Resource:   "tenant_member",
		Target:     subject,
		Decision:   decision,
		Reason:     reason,
		Roles:      append([]string(nil), roles...),
	})
}

//trstctl:mutation
func (a *API) offboardMember(w http.ResponseWriter, r *http.Request) {
	subject := strings.TrimSpace(r.PathValue("subject"))
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if subject == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "member subject is required")
		}
		var req offboardMemberRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		member, revoked, err := a.orch.OffboardTenantMember(ctx, tenantID, subject, req.Reason)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, offboardMemberResponse{
			Member:            toMemberResponse(member),
			RevokedTokenCount: revoked,
			RotationEvidence:  "active API tokens for the offboarded subject were revoked; replacement tokens must be minted explicitly through this served admin surface",
		}, nil
	})
}

func (a *API) listAPITokens(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	subject := r.URL.Query().Get("subject")
	includeRevoked := r.URL.Query().Get("include_revoked") == "true"
	tokens, err := a.store.ListAPITokensPage(r.Context(), tenantID, after, subject, includeRevoked, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]apiTokenResponse, 0, len(tokens))
	for _, tok := range tokens {
		items = append(items, toAPITokenResponse(tok))
	}
	next := ""
	if len(tokens) == limit {
		next = encodeCursor(tokens[len(tokens)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, apiTokenListResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) createAPIToken(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req apiTokenCreateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Subject = strings.TrimSpace(req.Subject)
		if req.Subject == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "subject is required")
		}
		if len(req.Scopes) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "at least one scope is required")
		}
		if err := a.validatePermissionScopes(req.Scopes); err != nil {
			return 0, nil, err
		}
		rec, raw, err := a.orch.CreateAPIToken(ctx, tenantID, req.Subject, req.Scopes, req.ExpiresAt)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, &apiTokenCreateResponse{apiTokenResponse: toAPITokenResponse(rec), Token: raw}, nil
	})
}

//trstctl:mutation
func (a *API) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req apiTokenRevokeRequest
		if r.Body != nil && r.ContentLength != 0 {
			if err := decodeJSON(r, &req); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
		}
		if err := a.orch.RevokeAPIToken(ctx, tenantID, id, req.Reason); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) validateRoleNames(roles []string) error {
	for _, name := range roles {
		if name == "" {
			return errStatus(http.StatusBadRequest, "role names must be non-empty")
		}
		if _, ok := a.roles.Role(name); !ok {
			return errStatus(http.StatusUnprocessableEntity, "unknown role "+name)
		}
	}
	return nil
}

func (a *API) validatePermissionScopes(scopes []string) error {
	allowed := map[string]bool{string(authz.Wildcard): true}
	for _, role := range a.roles.Roles() {
		for _, p := range role.Permissions {
			allowed[string(p)] = true
		}
	}
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "" {
			return errStatus(http.StatusBadRequest, "scopes must be non-empty")
		}
		if !allowed[scope] {
			return errStatus(http.StatusUnprocessableEntity, "unknown permission scope "+scope)
		}
	}
	return nil
}

func toMemberResponse(m store.TenantMember) memberResponse {
	return memberResponse{
		TenantID: m.TenantID, Subject: m.Subject, DisplayName: m.DisplayName, Email: m.Email,
		Roles: append([]string(nil), m.Roles...), Source: m.Source, Status: m.Status,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt, OffboardedAt: m.OffboardedAt,
		OffboardedBy: m.OffboardedBy, OffboardReason: m.OffboardReason,
	}
}

func toAPITokenResponse(t store.APITokenRecord) apiTokenResponse {
	return apiTokenResponse{
		ID: t.ID, TenantID: t.TenantID, Subject: t.Subject, Scopes: append([]string(nil), t.Scopes...),
		ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt, RevokedAt: t.RevokedAt,
		RevokedBy: t.RevokedBy, RevocationReason: t.RevocationReason,
	}
}

func accessCursor(c string) (string, error) {
	if c == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func encodeAccessCursor(v string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(v))
}
