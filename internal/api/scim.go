package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
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
	Name      string
	TenantID  string
	TokenHash string
}

type scimToken struct {
	Name      string
	TenantID  string
	TokenHash string
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
		out[tok.TokenHash] = scimToken{Name: name, TenantID: tok.TenantID, TokenHash: tok.TokenHash}
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
	subject := strings.TrimSpace(in.UserName)
	if subject == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	key := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, func(ctx context.Context, tenantID string) (int, any, error) {
		member, err := a.applySCIMUser(ctx, tenantID, subject, in)
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
		if filter == "" || strings.EqualFold(m.Subject, filter) {
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
	if err != nil {
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
	if in.UserName == "" {
		in.UserName = subject
	}
	key := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, func(ctx context.Context, tenantID string) (int, any, error) {
		member, err := a.applySCIMUser(ctx, tenantID, subject, in)
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
	key := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, func(ctx context.Context, tenantID string) (int, any, error) {
		cur, err := a.store.GetTenantMember(ctx, tenantID, subject)
		if err != nil {
			return 0, nil, scimHTTPError{status: http.StatusNotFound, detail: "user not found"}
		}
		su := userToSCIM(cur, scimBase(r))
		if err := scim.ApplyUserPatch(&su, patch.Operations); err != nil {
			return 0, nil, scimHTTPError{status: http.StatusBadRequest, scimType: "invalidValue", detail: "invalid user patch"}
		}
		member, err := a.applySCIMUser(ctx, tenantID, subject, su)
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
	key := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetTenantMember(ctx, tenantID, subject); err != nil {
			return 0, nil, scimHTTPError{status: http.StatusNotFound, detail: "user not found"}
		}
		if _, _, err := a.orch.OffboardTenantMember(ctx, tenantID, subject, "scim delete"); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) applySCIMUser(ctx context.Context, tenantID, subject string, in scim.User) (store.TenantMember, error) {
	if !in.Active {
		member, _, err := a.orch.OffboardTenantMember(ctx, tenantID, subject, "scim active=false")
		return member, err
	}
	roles := []string{}
	if cur, err := a.store.GetTenantMember(ctx, tenantID, subject); err == nil && cur.Status == "active" {
		roles = append(roles, cur.Roles...)
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
		Subject: subject, DisplayName: displayName, Email: email, Roles: roles, Source: "scim",
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
	key := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, func(ctx context.Context, tenantID string) (int, any, error) {
		for _, m := range in.Members {
			if strings.TrimSpace(m.Value) == "" {
				continue
			}
			if err := a.addRoleToMember(ctx, tenantID, m.Value, roleName); err != nil {
				return 0, nil, err
			}
		}
		g, err := a.groupToSCIM(ctx, tenantID, roleName, scimBase(r))
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
		g, err := a.groupToSCIM(r.Context(), tok.TenantID, role.Name, base)
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
	g, err := a.groupToSCIM(r.Context(), tok.TenantID, roleName, scimBase(r))
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
	key := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, func(ctx context.Context, tenantID string) (int, any, error) {
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
				if !want[m.Subject] {
					if err := a.removeRoleFromMember(ctx, tenantID, m.Subject, roleName); err != nil {
						return 0, nil, err
					}
				}
			}
			for m := range want {
				if err := a.addRoleToMember(ctx, tenantID, m, roleName); err != nil {
					return 0, nil, err
				}
			}
		}
		for _, m := range gp.Add {
			if err := a.addRoleToMember(ctx, tenantID, m, roleName); err != nil {
				return 0, nil, err
			}
		}
		for _, m := range gp.Remove {
			if err := a.removeRoleFromMember(ctx, tenantID, m, roleName); err != nil {
				return 0, nil, err
			}
		}
		g, err := a.groupToSCIM(ctx, tenantID, roleName, scimBase(r))
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
	key := scimIdempotencyKey(r, raw)
	a.scimMutate(w, r, tok, key, func(ctx context.Context, tenantID string) (int, any, error) {
		members, err := a.store.ListTenantMembersByRole(ctx, tenantID, roleName)
		if err != nil {
			return 0, nil, err
		}
		for _, m := range members {
			if err := a.removeRoleFromMember(ctx, tenantID, m.Subject, roleName); err != nil {
				return 0, nil, err
			}
		}
		return http.StatusNoContent, nil, nil
	})
}

func (a *API) addRoleToMember(ctx context.Context, tenantID, subject, roleName string) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil
	}
	member, err := a.store.GetTenantMember(ctx, tenantID, subject)
	if err != nil && !store.IsNotFound(err) {
		return err
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

func (a *API) removeRoleFromMember(ctx context.Context, tenantID, subject, roleName string) error {
	member, err := a.store.GetTenantMember(ctx, tenantID, subject)
	if err != nil {
		if store.IsNotFound(err) {
			return nil
		}
		return err
	}
	roles := removeRole(member.Roles, roleName)
	_, err = a.orch.UpsertTenantMember(ctx, tenantID, store.TenantMember{
		Subject: member.Subject, DisplayName: member.DisplayName, Email: member.Email, Roles: roles, Source: "scim",
	})
	return err
}

func (a *API) groupToSCIM(ctx context.Context, tenantID, roleName, base string) (scim.Group, error) {
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
		g.Members = append(g.Members, scim.Member{Value: m.Subject, Display: m.DisplayName, Ref: base + "/Users/" + m.Subject})
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

func (a *API) scimMutate(w http.ResponseWriter, r *http.Request, tok scimToken, idempotencyKey string, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	if a.idem == nil || a.orch == nil {
		writeSCIMError(w, http.StatusServiceUnavailable, "", "SCIM mutation spine is not configured")
		return
	}
	if idempotencyKey == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "Idempotency-Key header or deterministic SCIM request body is required")
		return
	}
	ctx := events.ContextWithActor(r.Context(), events.Actor{Subject: "scim:" + tok.Name, Roles: []string{scimProvisionerRole}})
	raw, err := a.idem.Do(ctx, tok.TenantID, idempotencyKey, func(ctx context.Context) ([]byte, error) {
		status, body, ferr := fn(ctx, tok.TenantID)
		if ferr != nil {
			return nil, ferr
		}
		bodyJSON := json.RawMessage("null")
		if body != nil {
			bj, mErr := json.Marshal(body)
			if mErr != nil {
				return nil, mErr
			}
			bodyJSON = bj
		}
		return json.Marshal(cachedResponse{Status: status, Body: bodyJSON})
	})
	if err != nil {
		writeSCIMMappedError(w, err)
		return
	}
	defer secret.Wipe(raw)
	var c cachedResponse
	if err := json.Unmarshal(raw, &c); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "SCIM replay cache decode failed")
		return
	}
	defer secret.Wipe(c.Body)
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

func scimIdempotencyKey(r *http.Request, body []byte) string {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return key
	}
	material := []byte(r.Method + "\x00" + r.URL.Path + "\x00")
	material = append(material, body...)
	defer secret.Wipe(material)
	return "scim:" + crypto.SHA256Hex(material)
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
			Location:     base + "/Users/" + m.Subject,
		},
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
