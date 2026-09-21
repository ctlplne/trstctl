// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/scim"
	"trstctl.com/trstctl/internal/store"
)

const (
	scimMaxBody         = 1 << 20
	scimProvisionerRole = "scim-provisioner"
)

type SCIMConfig struct {
	Enabled bool
	Tokens  []SCIMToken
}

type SCIMToken struct {
	SubjectAttribute string
	Name             string
	TenantID         string
	TokenHash        string
}

type scimToken struct {
	SubjectAttribute string
	Name             string
	TenantID         string
	TokenHash        string
}

type scimHTTPError struct {
	status   int
	scimType string
	detail   string
}

func (e scimHTTPError) Error() string { return e.detail }

func WithSCIM(cfg SCIMConfig) Option {
	return func(c *config) { c.scim = &cfg }
}

func normalizeSCIM(cfg *SCIMConfig) map[string]scimToken {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	out := map[string]scimToken{}
	for _, tok := range cfg.Tokens {
		if tok.TenantID == "" || tok.TokenHash == "" {
			continue
		}
		name := tok.Name
		if name == "" {
			name = "scim"
		}
		attribute := strings.TrimSpace(tok.SubjectAttribute)
		if attribute == "" {
			attribute = "userName"
		}
		if attribute != "userName" && attribute != "externalId" {
			continue
		}
		out[tok.TokenHash] = scimToken{Name: name, TenantID: tok.TenantID, TokenHash: tok.TokenHash, SubjectAttribute: attribute}
	}
	return out
}

func (a *API) scimTenant(r *http.Request) (scimToken, string, bool) {
	if len(a.scimTokens) == 0 {
		return scimToken{}, "", false
	}
	raw := bearerTokenBytes(r)
	if len(raw) == 0 {
		return scimToken{}, "", false
	}
	defer secret.Wipe(raw)
	hash := crypto.SHA256Hex(raw)
	got, ok := a.scimTokens[hash]
	return got, hash, ok
}

func (a *API) scimServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	tok, hash, ok := a.scimTenant(r)
	if !a.allowSCIMSpecialRouteRequest(w, r, tok, hash, ok) {
		return
	}
	if !ok {
		writeSCIMError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
		return
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":          []string{scim.SchemaSPConfig},
		"documentationUri": "https://docs.trstctl.local/configuration/#scim-provisioning",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []any{map[string]any{
			"type": "oauthbearertoken", "name": "OAuth Bearer Token",
			"description": "Per-tenant SCIM bearer token",
		}},
	})
}

func (a *API) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	tok, raw, ok := a.prepareSCIMMutation(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	var in scim.User
	if !decodeSCIMRaw(w, raw, &in) {
		return
	}
	if !bytes.Contains(raw, []byte(`"active"`)) {
		in.Active = true
	}
	subject, err := scimLoginSubject(tok, in)
	if err != nil {
		writeSCIMMappedError(w, err)
		return
	}
	key, prevKey := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, prevKey, raw, func(ctx context.Context, tenantID string) (int, any, error) {
		member, err := a.applySCIMUser(ctx, tok, subject, in)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, userToSCIM(member, scimBase(r)), nil
	})
}

func (a *API) scimListUsers(w http.ResponseWriter, r *http.Request) {
	tok, ok := a.scimRead(w, r)
	if !ok {
		return
	}
	filter := scimEqFilter(r.URL.Query().Get("filter"), "userName")
	start := atoiDefault(r.URL.Query().Get("startIndex"), 1)
	count := atoiDefault(r.URL.Query().Get("count"), 100)
	if count < 0 {
		count = 100
	}
	base := scimBase(r)
	members, err := a.store.ListTenantMembersPage(r.Context(), tok.TenantID, "", true, 5000)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "list users failed")
		return
	}
	filtered := members[:0]
	for _, m := range members {
		if scimMemberVisible(tok, m) && (filter == "" || strings.EqualFold(userToSCIM(m, base).UserName, filter)) {
			filtered = append(filtered, m)
		}
	}
	total := len(filtered)
	filtered = pageMembers(filtered, start, count)
	resources := make([]any, 0, len(filtered))
	for _, m := range filtered {
		resources = append(resources, userToSCIM(m, base))
	}
	writeSCIM(w, http.StatusOK, scim.NewList(resources, total, start, len(resources)))
}

func (a *API) scimGetUser(w http.ResponseWriter, r *http.Request) {
	tok, ok := a.scimRead(w, r)
	if !ok {
		return
	}
	m, err := a.store.GetTenantMember(r.Context(), tok.TenantID, r.PathValue("id"))
	if err != nil || !scimMemberVisible(tok, m) {
		writeSCIMError(w, http.StatusNotFound, "", "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, userToSCIM(m, scimBase(r)))
}

func (a *API) scimPutUser(w http.ResponseWriter, r *http.Request) {
	tok, raw, ok := a.prepareSCIMMutation(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	var in scim.User
	if !decodeSCIMRaw(w, raw, &in) {
		return
	}
	subject := strings.TrimSpace(r.PathValue("id"))
	if subject == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "user id is required")
		return
	}
	if in.UserName == "" && tok.SubjectAttribute == "userName" {
		in.UserName = subject
	}
	key, prevKey := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, prevKey, raw, func(ctx context.Context, tenantID string) (int, any, error) {
		member, err := a.applySCIMUser(ctx, tok, subject, in)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, userToSCIM(member, scimBase(r)), nil
	})
}

func (a *API) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	tok, raw, ok := a.prepareSCIMMutation(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	var patch scim.PatchOp
	if !decodeSCIMRaw(w, raw, &patch) {
		return
	}
	subject := strings.TrimSpace(r.PathValue("id"))
	if subject == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "user id is required")
		return
	}
	key, prevKey := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, prevKey, raw, func(ctx context.Context, tenantID string) (int, any, error) {
		cur, err := a.store.GetTenantMember(ctx, tenantID, subject)
		if err != nil || !scimMemberVisible(tok, cur) {
			return 0, nil, scimHTTPError{status: http.StatusNotFound, detail: "user not found"}
		}
		su := userToSCIM(cur, scimBase(r))
		if err := scim.ApplyUserPatch(&su, patch.Operations); err != nil {
			return 0, nil, scimHTTPError{status: http.StatusBadRequest, scimType: "invalidValue", detail: "invalid user patch"}
		}
		member, err := a.applySCIMUser(ctx, tok, subject, su)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, userToSCIM(member, scimBase(r)), nil
	})
}

func (a *API) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	tok, raw, ok := a.prepareSCIMMutation(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	subject := strings.TrimSpace(r.PathValue("id"))
	if subject == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "user id is required")
		return
	}
	key, prevKey := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, prevKey, raw, func(ctx context.Context, tenantID string) (int, any, error) {
		if cur, err := a.store.GetTenantMember(ctx, tenantID, subject); err != nil || !scimMemberVisible(tok, cur) {
			return 0, nil, scimHTTPError{status: http.StatusNotFound, detail: "user not found"}
		}
		if _, _, err := a.orch.OffboardTenantMember(ctx, tenantID, subject, "scim delete"); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) applySCIMUser(ctx context.Context, tok scimToken, subject string, in scim.User) (store.TenantMember, error) {
	// Validate alias uniqueness and append its event under one cross-replica
	// fence. Ordinary role changes never claim aliases and need no such lock.
	var member store.TenantMember
	err := a.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		var err error
		member, err = a.applySCIMUserLocked(lockCtx, tok, subject, in)
		return err
	})
	return member, err
}

func (a *API) applySCIMUserLocked(ctx context.Context, tok scimToken, subject string, in scim.User) (store.TenantMember, error) {
	tenantID := tok.TenantID
	boundSubject, err := scimLoginSubject(tok, in)
	if err != nil {
		return store.TenantMember{}, err
	}
	if boundSubject != subject {
		return store.TenantMember{}, scimHTTPError{status: http.StatusBadRequest, scimType: "mutability", detail: "the configured login-subject attribute cannot change for an existing SCIM resource"}
	}
	current, currentErr := a.store.GetTenantMember(ctx, tenantID, subject)
	if currentErr != nil && !store.IsNotFound(currentErr) {
		return store.TenantMember{}, currentErr
	}
	if currentErr == nil && current.SCIM != nil && current.SCIM.SubjectAttribute != tok.SubjectAttribute {
		return store.TenantMember{}, scimHTTPError{status: http.StatusConflict, scimType: "mutability", detail: "this principal already has a different explicit SCIM subject binding"}
	}
	identity := &store.SCIMIdentity{UserName: strings.TrimSpace(in.UserName), ExternalID: strings.TrimSpace(in.ExternalID), SubjectAttribute: tok.SubjectAttribute}
	exists, err := a.store.TenantMemberSCIMUserNameExists(ctx, tenantID, identity.UserName, subject)
	if err != nil {
		return store.TenantMember{}, err
	}
	if exists {
		return store.TenantMember{}, scimHTTPError{status: http.StatusConflict, scimType: "uniqueness", detail: "userName is already bound to another SCIM principal in this tenant"}
	}
	if !in.Active {
		member, _, err := a.orch.OffboardSCIMTenantMember(ctx, tenantID, subject, "scim active=false", identity)
		return member, err
	}
	roles := []string{}
	if currentErr == nil && current.Status == "active" {
		roles = append(roles, current.Roles...)
	}
	displayName := in.DisplayName
	if displayName == "" && in.Name != nil {
		displayName = in.Name.Formatted
	}
	email := in.PrimaryEmail()
	if email == "" {
		email = in.UserName
	}
	return a.orch.UpsertTenantMember(ctx, tenantID, store.TenantMember{
		Subject: subject, DisplayName: displayName, Email: email, Roles: roles, Source: "scim", SCIM: identity,
	})
}

func (a *API) scimCreateGroup(w http.ResponseWriter, r *http.Request) {
	tok, raw, ok := a.prepareSCIMMutation(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	var in scim.Group
	if !decodeSCIMRaw(w, raw, &in) {
		return
	}
	roleName := strings.TrimSpace(in.DisplayName)
	if roleName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}
	if _, ok := a.roles.Role(roleName); !ok {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "SCIM group must match a configured RBAC role")
		return
	}
	key, prevKey := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, prevKey, raw, func(ctx context.Context, tenantID string) (int, any, error) {
		for _, m := range in.Members {
			if strings.TrimSpace(m.Value) == "" {
				continue
			}
			if err := a.addRoleToMember(ctx, tok, m.Value, roleName); err != nil {
				return 0, nil, err
			}
		}
		g, err := a.groupToSCIM(ctx, tok, roleName, scimBase(r))
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, g, nil
	})
}

func (a *API) scimListGroups(w http.ResponseWriter, r *http.Request) {
	tok, ok := a.scimRead(w, r)
	if !ok {
		return
	}
	base := scimBase(r)
	roles := a.roles.Roles()
	resources := make([]any, 0, len(roles))
	for _, role := range roles {
		g, err := a.groupToSCIM(r.Context(), tok, role.Name, base)
		if err != nil {
			writeSCIMError(w, http.StatusInternalServerError, "", "list groups failed")
			return
		}
		resources = append(resources, g)
	}
	writeSCIM(w, http.StatusOK, scim.NewList(resources, len(resources), 1, len(resources)))
}

func (a *API) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	tok, ok := a.scimRead(w, r)
	if !ok {
		return
	}
	roleName := strings.TrimSpace(r.PathValue("id"))
	if _, ok := a.roles.Role(roleName); !ok {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}
	g, err := a.groupToSCIM(r.Context(), tok, roleName, scimBase(r))
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "get group failed")
		return
	}
	writeSCIM(w, http.StatusOK, g)
}

func (a *API) scimPatchGroup(w http.ResponseWriter, r *http.Request) {
	tok, raw, ok := a.prepareSCIMMutation(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	roleName := strings.TrimSpace(r.PathValue("id"))
	if _, ok := a.roles.Role(roleName); !ok {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}
	var patch scim.PatchOp
	if !decodeSCIMRaw(w, raw, &patch) {
		return
	}
	gp := scim.ParseGroupPatch(patch.Operations)
	if gp.DisplayName != nil && strings.TrimSpace(*gp.DisplayName) != roleName {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "renaming SCIM groups is not supported; group id is the RBAC role name")
		return
	}
	key, prevKey := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, prevKey, raw, func(ctx context.Context, tenantID string) (int, any, error) {
		if gp.ReplaceAll != nil {
			current, err := a.store.ListTenantMembersByRole(ctx, tenantID, roleName)
			if err != nil {
				return 0, nil, err
			}
			want := map[string]bool{}
			for _, m := range *gp.ReplaceAll {
				if strings.TrimSpace(m) != "" {
					want[m] = true
				}
			}
			for _, m := range current {
				if scimMemberVisible(tok, m) && !want[m.Subject] {
					if err := a.removeRoleFromMember(ctx, tok, m.Subject, roleName); err != nil {
						return 0, nil, err
					}
				}
			}
			for m := range want {
				if err := a.addRoleToMember(ctx, tok, m, roleName); err != nil {
					return 0, nil, err
				}
			}
		}
		for _, m := range gp.Add {
			if err := a.addRoleToMember(ctx, tok, m, roleName); err != nil {
				return 0, nil, err
			}
		}
		for _, m := range gp.Remove {
			if err := a.removeRoleFromMember(ctx, tok, m, roleName); err != nil {
				return 0, nil, err
			}
		}
		g, err := a.groupToSCIM(ctx, tok, roleName, scimBase(r))
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, g, nil
	})
}

func (a *API) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	tok, raw, ok := a.prepareSCIMMutation(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	roleName := strings.TrimSpace(r.PathValue("id"))
	if _, ok := a.roles.Role(roleName); !ok {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}
	key, prevKey := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, prevKey, raw, func(ctx context.Context, tenantID string) (int, any, error) {
		members, err := a.store.ListTenantMembersByRole(ctx, tenantID, roleName)
		if err != nil {
			return 0, nil, err
		}
		for _, m := range members {
			if err := a.removeRoleFromMember(ctx, tok, m.Subject, roleName); err != nil {
				return 0, nil, err
			}
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) addRoleToMember(ctx context.Context, tok scimToken, subject, roleName string) error {
	tenantID := tok.TenantID
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil
	}
	member, err := a.store.GetTenantMember(ctx, tenantID, subject)
	if err != nil && !store.IsNotFound(err) {
		return err
	}
	// A group delta is not an account-reactivation command. In explicit mapping
	// mode, a group member must also name a previously bound SCIM resource.
	if err == nil && member.Status == "offboarded" {
		return scimHTTPError{status: http.StatusConflict, scimType: "invalidValue", detail: "provision the user as active before adding group membership"}
	}
	if tok.SubjectAttribute == "externalId" && (err != nil || !scimMemberVisible(tok, member)) {
		return scimHTTPError{status: http.StatusNotFound, detail: "bound SCIM user not found"}
	}
	roles := appendRole(member.Roles, roleName)
	if member.DisplayName == "" {
		member.DisplayName = subject
	}
	if member.Email == "" && strings.Contains(subject, "@") {
		member.Email = subject
	}
	_, err = a.orch.UpsertTenantMember(ctx, tenantID, store.TenantMember{
		Subject: subject, DisplayName: member.DisplayName, Email: member.Email, Roles: roles, Source: "scim",
	})
	return err
}

func (a *API) removeRoleFromMember(ctx context.Context, tok scimToken, subject, roleName string) error {
	tenantID := tok.TenantID
	member, err := a.store.GetTenantMember(ctx, tenantID, subject)
	if err != nil {
		if store.IsNotFound(err) {
			return nil
		}
		return err
	}
	// Offboarding already removes all effective permissions. A delayed group
	// removal must remain a no-op, not emit the active-member upsert below.
	if member.Status == "offboarded" || !scimMemberVisible(tok, member) {
		return nil
	}
	roles := removeRole(member.Roles, roleName)
	_, err = a.orch.UpsertTenantMember(ctx, tenantID, store.TenantMember{
		Subject: member.Subject, DisplayName: member.DisplayName, Email: member.Email, Roles: roles, Source: "scim",
	})
	return err
}

func (a *API) groupToSCIM(ctx context.Context, tok scimToken, roleName, base string) (scim.Group, error) {
	tenantID := tok.TenantID
	members, err := a.store.ListTenantMembersByRole(ctx, tenantID, roleName)
	if err != nil {
		return scim.Group{}, err
	}
	g := scim.Group{
		Schemas:     []string{scim.SchemaGroup},
		ID:          roleName,
		DisplayName: roleName,
		Meta:        &scim.Meta{ResourceType: "Group", Location: base + "/Groups/" + roleName},
	}
	for _, m := range members {
		if scimMemberVisible(tok, m) {
			g.Members = append(g.Members, scim.Member{Value: m.Subject, Display: m.DisplayName, Ref: base + "/Users/" + url.PathEscape(m.Subject)})
		}
	}
	return g, nil
}

func (a *API) scimRead(w http.ResponseWriter, r *http.Request) (scimToken, bool) {
	tok, hash, ok := a.scimTenant(r)
	if !a.allowSCIMSpecialRouteRequest(w, r, tok, hash, ok) {
		return scimToken{}, false
	}
	if !ok {
		writeSCIMError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
		return scimToken{}, false
	}
	if a.store == nil {
		writeSCIMError(w, http.StatusServiceUnavailable, "", "SCIM store is not configured")
		return scimToken{}, false
	}
	return tok, true
}

func (a *API) allowSCIMSpecialRouteRequest(w http.ResponseWriter, r *http.Request, tok scimToken, tokenHash string, matched bool) bool {
	req := specialRouteAbuseRequest{}
	if tokenHash != "" {
		req.TokenKey = "scim:" + tokenHash
	}
	if matched {
		req.TenantID = tok.TenantID
	}
	return a.allowSpecialRouteRequest(w, r, req)
}

func (a *API) prepareSCIMMutation(w http.ResponseWriter, r *http.Request) (scimToken, []byte, bool) {
	tok, ok := a.scimRead(w, r)
	if !ok {
		return scimToken{}, nil, false
	}
	raw, ok := readSCIMBody(w, r)
	if !ok {
		return scimToken{}, nil, false
	}
	return tok, raw, true
}

func (a *API) scimMutate(w http.ResponseWriter, r *http.Request, tok scimToken, idempotencyKey, previousBucketKey string, requestBody []byte, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	if a.idem == nil || a.orch == nil {
		writeSCIMError(w, http.StatusServiceUnavailable, "", "SCIM mutation spine is not configured")
		return
	}
	if idempotencyKey == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "Idempotency-Key header or deterministic SCIM request body is required")
		return
	}
	binding, err := scimMutationBinding(tok, r, requestBody)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "SCIM request binding failed")
		return
	}
	ctx := events.ContextWithActor(r.Context(), events.Actor{Subject: "scim:" + tok.Name, Roles: []string{scimProvisionerRole}})
	if previousBucketKey != "" {
		// A derived key is a wall-clock bucket; a byte-identical retry sent
		// moments after the boundary hashes into a fresh bucket. Consult the
		// previous bucket's COMPLETED result first so the promised dedupe
		// holds across exactly one boundary (I3/V9).
		if cached, found, lookErr := a.idem.LookupBound(ctx, tok.TenantID, previousBucketKey, binding); lookErr == nil && found {
			a.writeSCIMCached(w, cached, binding)
			return
		}
	}
	cacheRaw, err := a.idem.DoBound(ctx, tok.TenantID, idempotencyKey, binding, func(ctx context.Context) ([]byte, error) {
		status, body, err := fn(ctx, tok.TenantID)
		if err != nil {
			return nil, err
		}
		bodyJSON := json.RawMessage("null")
		if body != nil {
			bj, mErr := json.Marshal(body)
			if mErr != nil {
				return nil, mErr
			}
			defer secret.Wipe(bj)
			bodyJSON = bj
		}
		return json.Marshal(cachedResponse{Status: status, Body: bodyJSON, Binding: binding})
	})
	if err != nil {
		writeSCIMMappedError(w, err)
		return
	}
	a.writeSCIMCached(w, cacheRaw, binding)
}

// writeSCIMCached decodes and serves one recorded mutation result, verifying
// the stored binding against the authenticated request.
func (a *API) writeSCIMCached(w http.ResponseWriter, cacheRaw []byte, binding string) {
	defer secret.Wipe(cacheRaw)
	var c cachedResponse
	if err := json.Unmarshal(cacheRaw, &c); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "SCIM replay cache decode failed")
		return
	}
	defer secret.Wipe(c.Body)
	if !crypto.ConstantTimeEqual([]byte(c.Binding), []byte(binding)) {
		writeSCIMError(w, http.StatusConflict, "", "Idempotency-Key was already used for a different authenticated SCIM request")
		return
	}
	if c.Status == http.StatusNoContent {
		w.WriteHeader(c.Status)
		return
	}
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(c.Status)
	_, _ = w.Write(c.Body)
}

func readSCIMBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}
	defer func() { _ = r.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(r.Body, scimMaxBody+1))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "failed to read SCIM body")
		return nil, false
	}
	if len(raw) > scimMaxBody {
		secret.Wipe(raw)
		writeSCIMError(w, http.StatusRequestEntityTooLarge, "tooLarge", "SCIM body exceeds size cap")
		return nil, false
	}
	return raw, true
}

func decodeSCIMRaw(w http.ResponseWriter, raw []byte, dst any) bool {
	if len(raw) == 0 {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "SCIM body is required")
		return false
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM body")
		return false
	}
	return true
}

// scimRetryWindow bounds how long an AUTO-DERIVED SCIM idempotency key dedupes.
//
// A provider that sends no Idempotency-Key gets one derived from its request. If
// that derivation is over method+path+body alone, it is stable FOREVER — so two
// genuinely separate operations that happen to look identical collapse into one.
// The realistic sequence is deprovision -> reprovision -> deprovision: the second
// deprovision has a byte-identical body, so it was treated as a replay of the
// first, returned its recorded result, and never ran. The user stayed
// provisioned while SCIM reported success.
//
// Bucketing by time keeps the property that actually matters — a retry lands
// in the same OR the immediately previous bucket and dedupes (scimMutate
// consults the previous bucket's recorded result before executing, so a retry
// that straddles a bucket boundary is still deduplicated; AUD-201 follow-up
// I3/V9) — while a deliberate repeat more than a full window later is its own
// operation.
const scimRetryWindow = 5 * time.Minute

// scimRetryStraddleGrace bounds how far into a bucket the previous-bucket dedupe
// consult stays active. Only a retry within this grace of the boundary can
// straddle it; past it a byte-identical request is a deliberate repeat and must
// execute rather than be deduped against a result up to a full window old.
const scimRetryStraddleGrace = 10 * time.Second

// scimNow is the derivation clock, injectable so boundary behavior is
// testable without wall-time flakiness.
var scimNow = time.Now

// scimIdempotencyKey derives the operation key and, for derived keys, the
// PREVIOUS bucket's key. An explicit Idempotency-Key is used verbatim and has
// no previous bucket — the provider owns dedupe entirely.
func scimIdempotencyKey(r *http.Request, body []byte) (key, previous string) {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return key, ""
	}
	derive := func(bucket time.Time) string {
		material := []byte(r.Method + "\x00" + r.URL.Path + "\x00" + bucket.UTC().Format(time.RFC3339) + "\x00")
		material = append(material, body...)
		defer secret.Wipe(material)
		return "scim:" + crypto.SHA256Hex(material)
	}
	now := scimNow().UTC()
	bucket := now.Truncate(scimRetryWindow)
	// The previous bucket is consulted only for a retry that STRADDLES the
	// boundary — such a retry arrives moments into the new bucket. Past the grace
	// period a byte-identical request is a deliberate repeat (e.g. a second
	// deprovision after an out-of-band re-enable) and must execute, not be
	// deduped against a result up to a full window old (AUD-201 follow-up,
	// previous-bucket recency bound).
	if now.Sub(bucket) > scimRetryStraddleGrace {
		return derive(bucket), ""
	}
	return derive(bucket), derive(bucket.Add(-scimRetryWindow))
}

func scimMutationBinding(tok scimToken, r *http.Request, body []byte) (string, error) {
	escapedPath := ""
	if r.URL != nil {
		escapedPath = r.URL.EscapedPath()
	}
	material, err := json.Marshal(struct {
		Domain           string `json:"domain"`
		TokenHash        string `json:"token_hash"`
		Method           string `json:"method"`
		EscapedPath      string `json:"escaped_path"`
		BodySHA256       string `json:"body_sha256"`
		SubjectAttribute string `json:"subject_attribute,omitempty"`
	}{
		Domain:           "trstctl.api.scim-mutation-binding.v1",
		TokenHash:        tok.TokenHash,
		Method:           r.Method,
		EscapedPath:      escapedPath,
		BodySHA256:       crypto.SHA256Hex(body),
		SubjectAttribute: scimNonLegacySubjectAttribute(tok),
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func writeSCIMMappedError(w http.ResponseWriter, err error) {
	var scimErr scimHTTPError
	if errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		writeSCIMError(w, http.StatusConflict, "", "Idempotency-Key was already used for a different authenticated SCIM request")
		return
	}
	if errors.As(err, &scimErr) {
		writeSCIMError(w, scimErr.status, scimErr.scimType, scimErr.detail)
		return
	}
	if store.IsNotFound(err) {
		writeSCIMError(w, http.StatusNotFound, "", "resource not found")
		return
	}
	writeSCIMError(w, http.StatusInternalServerError, "", "SCIM mutation failed")
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scim.NewError(status, scimType, detail))
}

func userToSCIM(m store.TenantMember, base string) scim.User {
	active := m.Status != "offboarded"
	u := scim.User{
		Schemas:     []string{scim.SchemaUser},
		ID:          m.Subject,
		UserName:    m.Subject,
		DisplayName: m.DisplayName,
		Active:      active,
		Meta: &scim.Meta{
			ResourceType: "User",
			Created:      ptrTime(m.CreatedAt),
			LastModified: ptrTime(m.UpdatedAt),
			Location:     base + "/Users/" + url.PathEscape(m.Subject),
		},
	}
	if m.SCIM != nil {
		u.UserName = m.SCIM.UserName
		u.ExternalID = m.SCIM.ExternalID
	}
	if m.Email != "" {
		u.Emails = []scim.Email{{Value: m.Email, Primary: true}}
	}
	if m.DisplayName != "" {
		u.Name = &scim.Name{Formatted: m.DisplayName}
	}
	return u
}

func scimBase(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/scim/v2"
}

func scimEqFilter(filter, attr string) string {
	f := strings.TrimSpace(filter)
	low := strings.ToLower(f)
	prefix := strings.ToLower(attr) + " eq "
	if !strings.HasPrefix(low, prefix) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(f[len(prefix):]), `"`)
}

func pageMembers(m []store.TenantMember, start, count int) []store.TenantMember {
	if start < 1 {
		start = 1
	}
	i := start - 1
	if i >= len(m) {
		return nil
	}
	m = m[i:]
	if count >= 0 && count < len(m) {
		m = m[:count]
	}
	return m
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func appendRole(roles []string, role string) []string {
	for _, got := range roles {
		if got == role {
			return append([]string(nil), roles...)
		}
	}
	out := append([]string(nil), roles...)
	return append(out, role)
}

func removeRole(roles []string, role string) []string {
	out := make([]string, 0, len(roles))
	for _, got := range roles {
		if got != role {
			out = append(out, got)
		}
	}
	return out
}

func ptrTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// externalId is client-issued, not inherently an OIDC subject. Only the explicit
// tenant-token configuration selects it; payloads cannot select their own mode.
func scimLoginSubject(tok scimToken, in scim.User) (string, error) {
	if strings.TrimSpace(in.UserName) == "" {
		return "", scimHTTPError{status: http.StatusBadRequest, scimType: "invalidValue", detail: "userName is required"}
	}
	if tok.SubjectAttribute == "externalId" {
		subject := strings.TrimSpace(in.ExternalID)
		if subject == "" {
			return "", scimHTTPError{status: http.StatusBadRequest, scimType: "invalidValue", detail: "externalId is required because this provisioning token explicitly uses it as the login subject"}
		}
		return subject, nil
	}
	return strings.TrimSpace(in.UserName), nil
}

func scimNonLegacySubjectAttribute(tok scimToken) string {
	if tok.SubjectAttribute == "externalId" {
		return tok.SubjectAttribute
	}
	// Keep the pre-upgrade request binding byte-identical for default userName.
	return ""
}

func scimMemberVisible(tok scimToken, member store.TenantMember) bool {
	if member.SCIM == nil {
		return tok.SubjectAttribute != "externalId"
	}
	return member.SCIM.SubjectAttribute == tok.SubjectAttribute
}
