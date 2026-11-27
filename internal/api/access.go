// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

type roleResponse struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
	// Custom marks a tenant custom role (A207).
	Custom bool `json:"custom,omitempty"`
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
	DisplayName  string              `json:"display_name"`
	Email        string              `json:"email"`
	Roles        []string            `json:"roles"`
	Source       string              `json:"source"`
	SCIMIdentity *store.SCIMIdentity `json:"scim_identity,omitempty"`
}

type memberResponse struct {
	TenantID       string              `json:"tenant_id"`
	Subject        string              `json:"subject"`
	DisplayName    string              `json:"display_name,omitempty"`
	Email          string              `json:"email,omitempty"`
	Roles          []string            `json:"roles"`
	Source         string              `json:"source"`
	SCIMIdentity   *store.SCIMIdentity `json:"scim_identity,omitempty"`
	Status         string              `json:"status"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
	OffboardedAt   *time.Time          `json:"offboarded_at,omitempty"`
	OffboardedBy   string              `json:"offboarded_by,omitempty"`
	OffboardReason string              `json:"offboard_reason,omitempty"`
	// LastSignInAt and LastSignInNetwork (M1-L2) are the member's last
	// recorded browser sign-in and the client network it came from.
	LastSignInAt      *time.Time `json:"last_sign_in_at,omitempty"`
	LastSignInNetwork string     `json:"last_sign_in_network,omitempty"`
	// LastSignInSeeded (M1-L4) says the last sign-in was read from the
	// session store when usage began, not observed from a network.
	LastSignInSeeded bool `json:"last_sign_in_seeded,omitempty"`
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
	MintedBy         string     `json:"minted_by"`
	Scopes           []string   `json:"scopes"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokedBy        string     `json:"revoked_by,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
}

type apiTokenCreateResponse struct {
	apiTokenResponse
	Token secretJSONBytes `json:"token"`
}

func (r *apiTokenCreateResponse) wipeSecrets() { r.Token.wipe() }

type apiTokenListResponse struct {
	Items      []apiTokenResponse `json:"items"`
	NextCursor string             `json:"next_cursor"`
}

type apiTokenRevokeRequest struct {
	Reason string `json:"reason"`
}

func (a *API) listAccessRoles(w http.ResponseWriter, r *http.Request) {
	roles := a.roles.Roles()
	items := make([]roleResponse, 0, len(roles))
	for _, role := range roles {
		perms := make([]string, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			perms = append(perms, string(p))
		}
		items = append(items, roleResponse{Name: role.Name, Permissions: perms})
	}
	if tenantID, ok := a.tenant(r); ok && a.store != nil {
		custom, err := a.store.ListTenantCustomRoles(r.Context(), tenantID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		for _, role := range custom {
			items = append(items, roleResponse{Name: role.Name, Description: role.Description, Permissions: role.Permissions, Custom: true})
		}
	}
	a.writeJSON(w, http.StatusOK, roleListResponse{Items: items})
}

func (a *API) getOIDCMappingStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.auth == nil {
		a.writeJSON(w, http.StatusOK, oidcMappingResponse{Enabled: false, TenantMappings: []AuthTenantMapping{}})
		return
	}
	// Authentication mappings are deployment configuration, so database RLS does
	// not filter them. Publish only the authenticated tenant's rules; subjects,
	// groups and the fallback tenant can identify other customers.
	mappings := make([]AuthTenantMapping, 0)
	for _, mapping := range a.auth.TenantMappings {
		if mapping.TenantID == tenantID {
			mappings = append(mappings, mapping)
		}
	}
	defaultTenant := ""
	allowDefaultTenant := false
	if a.auth.DefaultTenant == tenantID {
		defaultTenant = a.auth.DefaultTenant
		allowDefaultTenant = a.auth.AllowDefaultTenant
	}
	a.writeJSON(w, http.StatusOK, oidcMappingResponse{
		Enabled: a.auth.OIDCEnabled, TenantClaim: a.auth.TenantClaim, GroupsClaim: a.auth.GroupsClaim,
		ClaimIsTenant: a.auth.ClaimIsTenant, DefaultRoles: append([]string(nil), a.auth.DefaultRoles...),
		DefaultTenant: defaultTenant, AllowDefaultTenant: allowDefaultTenant,
		TenantMappings: mappings,
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
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
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
	// M1-L2: each member's last browser sign-in, read by its subject reference.
	refs := make([]string, 0, len(members))
	for _, m := range members {
		refs = append(refs, privacy.SubjectRef(tenantID, m.Subject))
	}
	signIns, err := a.store.CredentialUsageFor(r.Context(), tenantID, store.CredentialUsageBrowserSession, refs)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]memberResponse, 0, len(members))
	for i, m := range members {
		item := toMemberResponse(m)
		if use, ok := signIns[refs[i]]; ok && !use.LastUsedAt.IsZero() {
			at := use.LastUsedAt.UTC()
			item.LastSignInAt = &at
			// A sign-in seeded from the session store (M1-L4) has no network.
			if _, err := netip.ParsePrefix(use.LastSource); err == nil {
				item.LastSignInNetwork = use.LastSource
			}
			item.LastSignInSeeded = use.LastSource == store.CredentialUsageSeedSessionStore
		}
		items = append(items, item)
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
		if len(subject) > 1024 || len(req.DisplayName) > 1024 || len(req.Email) > 320 || len(req.Roles) > 128 {
			return 0, nil, errStatus(http.StatusBadRequest,
				"member subject/display_name is limited to 1024 bytes, email to 320 bytes, and roles to 128 entries")
		}
		// Member upsert replaces the entire record. A missing/null roles array
		// would erase a restricted role set without role-assignment authorization
		// and can restore broader OIDC sign-in defaults. OpenAPI requires roles;
		// callers use [] to request a deliberate, authorized clear.
		if req.Roles == nil {
			return 0, nil, errStatus(http.StatusBadRequest, "roles array is required for member upsert; use [] to clear roles")
		}
		if err := a.validateRoleNames(ctx, tenantID, req.Roles); err != nil {
			return 0, nil, err
		}
		if err := a.authorizeRoleAssignment(ctx, tenantID, subject, req.Roles, req.Roles != nil); err != nil {
			return 0, nil, err
		}
		source := req.Source
		if source == "" {
			source = "manual"
		}
		if source == "scim" {
			if req.SCIMIdentity == nil {
				return 0, nil, errStatus(http.StatusBadRequest, "adopting a SCIM member requires the exact scim_identity binding")
			}
			identity := *req.SCIMIdentity
			identity.UserName = strings.TrimSpace(identity.UserName)
			identity.ExternalID = strings.TrimSpace(identity.ExternalID)
			if identity.UserName == "" ||
				(identity.SubjectAttribute != "userName" && identity.SubjectAttribute != "externalId") ||
				(identity.SubjectAttribute == "userName" && identity.UserName != subject) ||
				(identity.SubjectAttribute == "externalId" && identity.ExternalID != subject) {
				return 0, nil, errStatus(http.StatusBadRequest, "scim_identity must bind the selected login-subject attribute to this exact member subject")
			}
			req.SCIMIdentity = &identity
		} else if req.SCIMIdentity != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "scim_identity requires source scim")
		}
		member, err := a.orch.UpsertTenantMember(ctx, tenantID, store.TenantMember{
			Subject: subject, DisplayName: req.DisplayName, Email: req.Email,
			Roles: req.Roles, Source: source, SCIM: req.SCIMIdentity,
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
	reason, err := a.roleAssignmentRefusal(ctx, tenantID, principal, subject, roles)
	if err != nil {
		return err
	}
	if reason != "" {
		if err := a.recordRoleAssignDecision(ctx, tenantID, principal, subject, roles, "deny", reason); err != nil {
			return err
		}
		return errStatus(http.StatusForbidden, reason)
	}
	return a.recordRoleAssignDecision(ctx, tenantID, principal, subject, roles, "allow", "")
}

// roleAssignmentRefusal is why principal may not grant roles to subject, or ""
// when it may: the checks authorizeRoleAssignment records, run without
// recording, so a reviewed change set's plan (A248) refuses what applying it
// would.
func (a *API) roleAssignmentRefusal(ctx context.Context, tenantID string, principal authz.Principal, subject string, roles []string) (string, error) {
	if principal.Subject == subject {
		return "self role assignment is not allowed", nil
	}
	target := authz.Scope{TenantID: tenantID}
	if !principal.Can(authz.AccessRoleAssign, target) {
		return string(authz.AccessRoleAssign) + " is required to assign member roles", nil
	}
	// Only a caller that holds every permission may grant a role that holds every
	// permission, so an operator or a role-provisioning token cannot create an
	// administrator (F266). Other roles stay assignable with access:role.assign.
	if !principal.Can(authz.Wildcard, target) {
		resolved, err := a.resolveRoles(ctx, tenantID, roles)
		if err != nil {
			return "", err
		}
		for _, name := range roles {
			role, ok := resolved[strings.TrimSpace(name)]
			if !ok {
				continue
			}
			if role.Allows(authz.Wildcard) {
				return "only an administrator can grant the " + role.Name + " role, which holds every permission", nil
			}
			// A207/CR-023: the same hold-what-you-grant rule applies to
			// built-in and custom roles. Built-in names are not trusted grants.
			for _, p := range role.Permissions {
				if !principal.Can(p, target) {
					return "granting the " + role.Name + " role needs " + string(p) + ", which you do not hold", nil
				}
			}
		}
	}
	return "", nil
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
		if len(subject) > 1024 || len(req.Reason) > 2048 {
			return 0, nil, errStatus(http.StatusBadRequest,
				"member subject is limited to 1024 bytes and offboard reason to 2048 bytes")
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
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
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
		principal, err := requestAuthzPrincipal(ctx)
		if err != nil {
			return 0, nil, err
		}
		if principal.RunID != "" {
			return 0, nil, errStatus(http.StatusForbidden, "an access bundle run cannot mint a lasting API token")
		}
		if req.Subject != principal.Subject {
			return 0, nil, errStatus(http.StatusForbidden, "API token subject must be your authenticated subject; authenticate as the service identity to mint its key")
		}
		if len(req.Scopes) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "at least one scope is required")
		}
		if err := a.validatePermissionScopes(req.Scopes); err != nil {
			return 0, nil, err
		}
		if err := a.authorizeTokenScopeGrant(ctx, tenantID, req.Scopes); err != nil {
			return 0, nil, err
		}
		if !principal.TokenExpiresAt.IsZero() {
			if req.ExpiresAt == nil {
				expiry := principal.TokenExpiresAt
				req.ExpiresAt = &expiry
			} else if req.ExpiresAt.After(principal.TokenExpiresAt) {
				return 0, nil, errStatus(http.StatusUnprocessableEntity,
					"expires_at is later than the calling API token's expiry")
			}
		}
		// A served token expires (F267): without expires_at it gets the deployment's
		// maximum lifetime, and a later expiry is refused.
		if limit := a.apiTokenMaxLifetime; limit > 0 {
			latest := time.Now().Add(limit)
			if req.ExpiresAt == nil {
				req.ExpiresAt = &latest
			} else if req.ExpiresAt.After(latest) {
				return 0, nil, errStatus(http.StatusUnprocessableEntity, fmt.Sprintf(
					"expires_at is later than the maximum API token lifetime of %s (auth.api_tokens.max_lifetime); ask for an earlier expiry",
					formatTokenLifetime(limit)))
			}
		}
		rec, raw, err := a.orch.CreateAPIToken(ctx, tenantID, req.Subject, req.Scopes, req.ExpiresAt)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, &apiTokenCreateResponse{apiTokenResponse: toAPITokenResponse(rec), Token: secretJSONBytes(raw)}, nil
	})
}

//trstctl:mutation
func (a *API) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutateDurable(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
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

func (a *API) validateRoleNames(ctx context.Context, tenantID string, roles []string) error {
	for _, name := range roles {
		if name == "" {
			return errStatus(http.StatusBadRequest, "role names must be non-empty")
		}
	}
	resolved, err := a.resolveRoles(ctx, tenantID, roles)
	if err != nil {
		return err
	}
	for _, name := range roles {
		if _, ok := resolved[name]; !ok {
			return errStatus(http.StatusUnprocessableEntity, "unknown role "+name)
		}
	}
	return nil
}

// authorizeTokenScopeGrant enforces privilege ATTENUATION: a caller may only
// put scopes into a token that the caller itself holds.
//
// Without it, minting a token was an escalation primitive. validatePermissionScopes
// accepts authz.Wildcard, so any holder of access:write could mint a "*" token
// and then act with authority the platform deliberately withheld from them —
// access:role.assign and agents:relay.grant are separated precisely so one
// principal cannot both assign roles and grant relay capability, and a wildcard
// token collapses that separation in a single call.
func (a *API) authorizeTokenScopeGrant(ctx context.Context, tenantID string, scopes []string) error {
	principal, ok := ctx.Value(principalCtxKey).(authz.Principal)
	if !ok || principal.Subject == "" {
		return errStatus(http.StatusUnauthorized, "missing authenticated principal for token creation")
	}
	target := authz.Scope{TenantID: tenantID}
	for _, scope := range scopes {
		if !principal.Can(authz.Permission(scope), target) {
			return errStatus(http.StatusForbidden,
				"cannot grant a token the scope "+scope+" that you do not hold")
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
		Roles: append([]string{}, m.Roles...), Source: m.Source, SCIMIdentity: m.SCIM, Status: m.Status,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt, OffboardedAt: m.OffboardedAt,
		OffboardedBy: m.OffboardedBy, OffboardReason: m.OffboardReason,
	}
}

func toAPITokenResponse(t store.APITokenRecord) apiTokenResponse {
	return apiTokenResponse{
		ID: t.ID, TenantID: t.TenantID, Subject: t.Subject, MintedBy: t.MintedBy, Scopes: append([]string(nil), t.Scopes...),
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

// formatTokenLifetime renders a lifetime in whole days when it is one.
func formatTokenLifetime(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		days := int(d / (24 * time.Hour))
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	return d.String()
}
