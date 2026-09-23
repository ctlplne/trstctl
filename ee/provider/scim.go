// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const providerSCIMMaxBody = 1 << 20

var providerSCIMNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("trstctl.com/provider/scim/operator"))

// SCIMConfig contains hashes, never live bearer tokens. The attach seam loads
// each token file into wipeable bytes, hashes it, wipes it, and passes only this
// verifier material into the long-lived HTTP handler.
type SCIMConfig struct {
	Tokens []SCIMToken
}

type SCIMToken struct {
	Name      string
	TokenHash string
}

type providerSCIMHandler struct {
	tokens    []SCIMToken
	access    OperatorAccessStore
	mutations MutationSink
	clock     func() time.Time
}

type providerSCIMRole struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type providerSCIMUser struct {
	scim.User
	Roles []providerSCIMRole `json:"roles,omitempty"`
}

func newSCIMHandler(cfg *SCIMConfig, access OperatorAccessStore, mutations MutationSink, clock func() time.Time) *providerSCIMHandler {
	if cfg == nil || len(cfg.Tokens) == 0 {
		return nil
	}
	if clock == nil {
		clock = time.Now
	}
	tokens := make([]SCIMToken, 0, len(cfg.Tokens))
	for _, token := range cfg.Tokens {
		if strings.TrimSpace(token.Name) != "" && strings.TrimSpace(token.TokenHash) != "" {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return nil
	}
	return &providerSCIMHandler{tokens: tokens, access: access, mutations: mutations, clock: clock}
}

func (h *providerSCIMHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := h.authenticate(r)
	if !ok {
		writeProviderSCIMError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/provider/scim/v2")
	switch {
	case r.Method == http.MethodGet && path == "/ServiceProviderConfig":
		writeProviderSCIM(w, http.StatusOK, map[string]any{
			"schemas": []string{scim.SchemaSPConfig}, "patch": map[string]bool{"supported": true},
			"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":         map[string]any{"supported": true, "maxResults": 200},
			"changePassword": map[string]bool{"supported": false}, "sort": map[string]bool{"supported": false},
			"etag":                  map[string]bool{"supported": false},
			"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "OAuth Bearer Token"}},
		})
	case path == "/Users" && r.Method == http.MethodPost:
		h.createUser(w, r, token)
	case path == "/Users" && r.Method == http.MethodGet:
		h.listUsers(w, r)
	case strings.HasPrefix(path, "/Users/"):
		h.userByID(w, r, token, path)
	case path == "/Groups" && r.Method == http.MethodGet:
		h.listGroups(w, r)
	case strings.HasPrefix(path, "/Groups/"):
		h.groupByRole(w, r, token, path)
	default:
		http.NotFound(w, r)
	}
}

func (h *providerSCIMHandler) authenticate(r *http.Request) (SCIMToken, bool) {
	if h == nil || r == nil {
		return SCIMToken{}, false
	}
	header := r.Header.Get("Authorization")
	if len(header) < len("Bearer ") || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		return SCIMToken{}, false
	}
	raw := bytes.TrimSpace([]byte(header[len("Bearer "):]))
	if len(raw) == 0 {
		return SCIMToken{}, false
	}
	defer secret.Wipe(raw)
	wanted := crypto.SHA256Hex(raw)
	for _, token := range h.tokens {
		if crypto.ConstantTimeEqual([]byte(wanted), []byte(token.TokenHash)) {
			return token, true
		}
	}
	return SCIMToken{}, false
}

func (h *providerSCIMHandler) createUser(w http.ResponseWriter, r *http.Request, token SCIMToken) {
	raw, ok := readProviderSCIMBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	in, activePresent, err := decodeProviderSCIMUser(raw)
	if err != nil {
		writeProviderSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM user")
		return
	}
	if !activePresent {
		in.Active = true
	}
	identity, err := h.upsertUser(r.Context(), token, "", in, providerSCIMMutationKey(r, token, raw), providerSCIMBinding(r, token, raw))
	if err != nil {
		h.writeMutationError(w, err)
		return
	}
	w.Header().Set("Location", providerSCIMBase(r)+"/Users/"+url.PathEscape(identity.ID))
	writeProviderSCIM(w, http.StatusCreated, operatorIdentityToSCIM(identity, providerSCIMBase(r)))
}

func (h *providerSCIMHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	if h.access == nil {
		writeProviderSCIMError(w, http.StatusServiceUnavailable, "", "provider operator directory is not configured")
		return
	}
	rows, err := h.access.ListOperatorAccess(r.Context())
	if err != nil {
		writeProviderSCIMError(w, http.StatusInternalServerError, "", "list users failed")
		return
	}
	filter := providerSCIMEqFilter(r.URL.Query().Get("filter"), "userName")
	resources := make([]any, 0, len(rows))
	for _, row := range rows {
		if filter == "" || strings.EqualFold(row.Identity.UserName, filter) {
			resources = append(resources, operatorIdentityToSCIM(row.Identity, providerSCIMBase(r)))
		}
	}
	writeProviderSCIM(w, http.StatusOK, scim.NewList(resources, len(resources), 1, len(resources)))
}

func (h *providerSCIMHandler) userByID(w http.ResponseWriter, r *http.Request, token SCIMToken, path string) {
	id, err := url.PathUnescape(strings.TrimPrefix(path, "/Users/"))
	if err != nil || strings.TrimSpace(id) == "" {
		writeProviderSCIMError(w, http.StatusBadRequest, "invalidValue", "user id is required")
		return
	}
	if h.access == nil {
		writeProviderSCIMError(w, http.StatusServiceUnavailable, "", "provider operator directory is not configured")
		return
	}
	current, err := h.access.ResolveOperator(r.Context(), id)
	if err != nil {
		writeProviderSCIMError(w, http.StatusNotFound, "", "user not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeProviderSCIM(w, http.StatusOK, operatorIdentityToSCIM(current, providerSCIMBase(r)))
	case http.MethodPut:
		raw, ok := readProviderSCIMBody(w, r)
		if !ok {
			return
		}
		defer secret.Wipe(raw)
		in, activePresent, decodeErr := decodeProviderSCIMUser(raw)
		if decodeErr != nil {
			writeProviderSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM user")
			return
		}
		if !activePresent {
			in.Active = current.Active
		}
		identity, mutateErr := h.upsertUser(r.Context(), token, current.ID, in, providerSCIMMutationKey(r, token, raw), providerSCIMBinding(r, token, raw))
		if mutateErr != nil {
			h.writeMutationError(w, mutateErr)
			return
		}
		writeProviderSCIM(w, http.StatusOK, operatorIdentityToSCIM(identity, providerSCIMBase(r)))
	case http.MethodPatch:
		raw, ok := readProviderSCIMBody(w, r)
		if !ok {
			return
		}
		defer secret.Wipe(raw)
		var patch scim.PatchOp
		if json.Unmarshal(raw, &patch) != nil {
			writeProviderSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM patch")
			return
		}
		in := operatorIdentityToSCIM(current, "")
		if err := scim.ApplyUserPatch(&in.User, patch.Operations); err != nil {
			writeProviderSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid SCIM user patch")
			return
		}
		identity, mutateErr := h.upsertUser(r.Context(), token, current.ID, in, providerSCIMMutationKey(r, token, raw), providerSCIMBinding(r, token, raw))
		if mutateErr != nil {
			h.writeMutationError(w, mutateErr)
			return
		}
		writeProviderSCIM(w, http.StatusOK, operatorIdentityToSCIM(identity, providerSCIMBase(r)))
	case http.MethodDelete:
		identity := current
		identity.Active = false
		identity.UpdatedAt = h.clock().UTC()
		identity.DeprovisionedAt = identity.UpdatedAt
		identity.Source = "scim:" + token.Name
		_, mutateErr := h.emitIdentity(r.Context(), token, EventOperatorOffboarded, identity,
			providerSCIMMutationKey(r, token, nil), providerSCIMBinding(r, token, nil))
		if mutateErr != nil {
			h.writeMutationError(w, mutateErr)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func decodeProviderSCIMUser(raw []byte) (providerSCIMUser, bool, error) {
	var in providerSCIMUser
	if err := json.Unmarshal(raw, &in); err != nil {
		return providerSCIMUser{}, false, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return providerSCIMUser{}, false, err
	}
	for name := range fields {
		if strings.EqualFold(name, "active") {
			return in, true, nil
		}
	}
	return in, false, nil
}

func (h *providerSCIMHandler) upsertUser(ctx context.Context, token SCIMToken, pathID string, in providerSCIMUser, key, binding string) (OperatorIdentity, error) {
	if h.access == nil || h.mutations == nil {
		return OperatorIdentity{}, errors.New("provider SCIM mutation spine is not configured")
	}
	userName := strings.TrimSpace(in.UserName)
	externalID := strings.TrimSpace(in.ExternalID)
	if userName == "" {
		return OperatorIdentity{}, errors.New("userName is required")
	}
	lookup := strings.TrimSpace(pathID)
	if lookup == "" {
		lookup = externalID
		if lookup == "" {
			lookup = userName
		}
	}
	current, currentErr := h.access.ResolveOperator(ctx, lookup)
	if currentErr != nil && !errors.Is(currentErr, ErrNotFound) {
		return OperatorIdentity{}, currentErr
	}
	role := providerRoleFromSCIM(in.Roles)
	if role == "" && currentErr == nil {
		role = current.Role
	}
	if !validOperatorRole(role) {
		return OperatorIdentity{}, errors.New("roles must contain provider admin or operator")
	}
	now := h.clock().UTC()
	identity := current
	if currentErr != nil {
		stable := externalID
		if stable == "" {
			stable = userName
		}
		identity.ID = uuid.NewSHA1(providerSCIMNamespace, []byte(token.Name+"\x00"+stable)).String()
		identity.CreatedAt = now
	}
	if strings.TrimSpace(pathID) != "" && identity.ID != strings.TrimSpace(pathID) {
		return OperatorIdentity{}, ErrNotFound
	}
	if externalID == "" {
		externalID = identity.ExternalID
		if externalID == "" {
			externalID = userName
		}
	}
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" && in.Name != nil {
		displayName = strings.TrimSpace(in.Name.Formatted)
	}
	email := strings.TrimSpace(in.PrimaryEmail())
	if email == "" {
		email = userName
	}
	identity.ExternalID, identity.UserName, identity.Email = externalID, userName, email
	identity.DisplayName, identity.Role, identity.Active = displayName, role, in.Active
	identity.Source, identity.UpdatedAt = "scim:"+token.Name, now
	typ := EventOperatorUpserted
	if !identity.Active {
		typ = EventOperatorOffboarded
		identity.DeprovisionedAt = now
	} else {
		identity.DeprovisionedAt = time.Time{}
	}
	return h.emitIdentity(ctx, token, typ, identity, key, binding)
}

func (h *providerSCIMHandler) emitIdentity(ctx context.Context, token SCIMToken, typ string, identity OperatorIdentity, key, binding string) (OperatorIdentity, error) {
	if h.mutations == nil {
		return OperatorIdentity{}, errors.New("provider SCIM event sink is not configured")
	}
	now := h.clock().UTC()
	payload := AuthorityEvent{
		Operator: &identity, EffectiveAt: now, RequestBinding: binding,
		Audit: AuditEvent{Type: typ, TenantID: providerAuthorityTenant, OperatorID: "scim:" + token.Name,
			Subject: identity.ID, At: now},
	}
	event, err := h.mutations.Append(ContextWithMutationKey(ctx, key), key, typ, providerAuthorityTenant, payload)
	if err != nil {
		return OperatorIdentity{}, err
	}
	var canonical AuthorityEvent
	if err := json.Unmarshal(event.Data, &canonical); err != nil || canonical.Operator == nil {
		return OperatorIdentity{}, errors.New("provider SCIM canonical operator event is invalid")
	}
	return *canonical.Operator, nil
}

func providerRoleFromSCIM(roles []providerSCIMRole) OperatorRole {
	role := OperatorRole("")
	for _, item := range roles {
		switch strings.ToLower(strings.TrimSpace(item.Value)) {
		case "admin", "provider-admin", "provider_admin":
			return OperatorAdmin
		case "operator", "provider-operator", "provider_operator":
			role = OperatorOperator
		}
	}
	return role
}

func operatorIdentityToSCIM(identity OperatorIdentity, base string) providerSCIMUser {
	location := ""
	if base != "" {
		location = base + "/Users/" + url.PathEscape(identity.ID)
	}
	created, updated := identity.CreatedAt, identity.UpdatedAt
	return providerSCIMUser{
		User: scim.User{
			Schemas: []string{scim.SchemaUser}, ID: identity.ID, ExternalID: identity.ExternalID,
			UserName: identity.UserName, DisplayName: identity.DisplayName, Active: identity.Active,
			Emails: []scim.Email{{Value: identity.Email, Primary: true}},
			Meta:   &scim.Meta{ResourceType: "User", Created: &created, LastModified: &updated, Location: location},
		},
		Roles: []providerSCIMRole{{Value: string(identity.Role), Primary: true}},
	}
}

func (h *providerSCIMHandler) listGroups(w http.ResponseWriter, r *http.Request) {
	resources := []any{}
	for _, role := range []OperatorRole{OperatorAdmin, OperatorOperator} {
		group, err := h.scimGroup(r.Context(), role, providerSCIMBase(r))
		if err != nil {
			writeProviderSCIMError(w, http.StatusInternalServerError, "", "list groups failed")
			return
		}
		resources = append(resources, group)
	}
	writeProviderSCIM(w, http.StatusOK, scim.NewList(resources, len(resources), 1, len(resources)))
}

func (h *providerSCIMHandler) groupByRole(w http.ResponseWriter, r *http.Request, token SCIMToken, path string) {
	rawRole, err := url.PathUnescape(strings.TrimPrefix(path, "/Groups/"))
	role := OperatorRole(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rawRole)), "provider-"))
	if err != nil || !validOperatorRole(role) {
		writeProviderSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}
	if r.Method == http.MethodGet {
		group, groupErr := h.scimGroup(r.Context(), role, providerSCIMBase(r))
		if groupErr != nil {
			writeProviderSCIMError(w, http.StatusInternalServerError, "", "get group failed")
			return
		}
		writeProviderSCIM(w, http.StatusOK, group)
		return
	}
	if r.Method != http.MethodPatch {
		http.NotFound(w, r)
		return
	}
	raw, ok := readProviderSCIMBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	var patch scim.PatchOp
	if json.Unmarshal(raw, &patch) != nil {
		writeProviderSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM group patch")
		return
	}
	parsed := scim.ParseGroupPatch(patch.Operations)
	if len(parsed.Remove) > 0 || parsed.ReplaceAll != nil {
		writeProviderSCIMError(w, http.StatusBadRequest, "mutability", "remove/replace group membership is refused; send Users active=false so leaver revocation is explicit")
		return
	}
	baseKey, binding := providerSCIMMutationKey(r, token, raw), providerSCIMBinding(r, token, raw)
	for _, member := range parsed.Add {
		identity, resolveErr := h.access.ResolveOperator(r.Context(), member)
		if resolveErr != nil {
			writeProviderSCIMError(w, http.StatusNotFound, "", "group member not found")
			return
		}
		identity.Role, identity.Active, identity.UpdatedAt = role, true, h.clock().UTC()
		identity.DeprovisionedAt = time.Time{}
		if _, emitErr := h.emitIdentity(r.Context(), token, EventOperatorUpserted, identity, baseKey+":"+identity.ID, binding); emitErr != nil {
			h.writeMutationError(w, emitErr)
			return
		}
	}
	group, err := h.scimGroup(r.Context(), role, providerSCIMBase(r))
	if err != nil {
		writeProviderSCIMError(w, http.StatusInternalServerError, "", "get group failed")
		return
	}
	writeProviderSCIM(w, http.StatusOK, group)
}

func (h *providerSCIMHandler) scimGroup(ctx context.Context, role OperatorRole, base string) (scim.Group, error) {
	if h.access == nil {
		return scim.Group{}, errors.New("provider operator directory is not configured")
	}
	rows, err := h.access.ListOperatorAccess(ctx)
	if err != nil {
		return scim.Group{}, err
	}
	group := scim.Group{Schemas: []string{scim.SchemaGroup}, ID: string(role), DisplayName: "provider-" + string(role),
		Meta: &scim.Meta{ResourceType: "Group", Location: base + "/Groups/" + string(role)}}
	for _, row := range rows {
		if row.Identity.Active && row.Identity.Role == role {
			group.Members = append(group.Members, scim.Member{Value: row.Identity.ID, Display: row.Identity.DisplayName,
				Ref: base + "/Users/" + url.PathEscape(row.Identity.ID)})
		}
	}
	return group, nil
}

func readProviderSCIMBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, providerSCIMMaxBody+1))
	if err != nil {
		writeProviderSCIMError(w, http.StatusBadRequest, "invalidSyntax", "failed to read SCIM body")
		return nil, false
	}
	if len(raw) > providerSCIMMaxBody {
		secret.Wipe(raw)
		writeProviderSCIMError(w, http.StatusRequestEntityTooLarge, "tooLarge", "SCIM body exceeds 1 MiB")
		return nil, false
	}
	return raw, true
}

func providerSCIMMutationKey(r *http.Request, token SCIMToken, body []byte) string {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return "scim:" + token.Name + ":" + key
	}
	material := append([]byte(r.Method+"\x00"+r.URL.EscapedPath()+"\x00"), body...)
	defer secret.Wipe(material)
	return "scim:" + token.Name + ":" + crypto.SHA256Hex(material)
}

func providerSCIMBinding(r *http.Request, token SCIMToken, body []byte) string {
	material := []byte(token.TokenHash + "\x00" + r.Method + "\x00" + r.URL.EscapedPath() + "\x00" + crypto.SHA256Hex(body))
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material)
}

func providerSCIMBase(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/provider/scim/v2"
}

func providerSCIMEqFilter(filter, attribute string) string {
	filter = strings.TrimSpace(filter)
	prefix := strings.ToLower(attribute) + " eq "
	if !strings.HasPrefix(strings.ToLower(filter), prefix) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(filter[len(prefix):]), `"`)
}

func (h *providerSCIMHandler) writeMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeProviderSCIMError(w, http.StatusNotFound, "", "user not found")
	case errors.Is(err, ErrMutationConflict):
		writeProviderSCIMError(w, http.StatusConflict, "uniqueness", "idempotency key was reused for a different SCIM command")
	case errors.Is(err, ErrMutationPersistence):
		writeProviderSCIMError(w, http.StatusInternalServerError, "", "provider workforce change could not be recorded; retry the same command")
	default:
		writeProviderSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
	}
}

func writeProviderSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func writeProviderSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scim.NewError(status, scimType, detail))
}
