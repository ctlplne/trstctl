// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

var (
	milvusRole = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)
	milvusUser = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
)

// ParseMilvusRoles reads a role binding: the Milvus roles a lease's user is
// granted, comma separated, for example "orders_reader". Each role must exist
// in Milvus with the privileges the lease should carry.
func ParseMilvusRoles(binding string) ([]string, error) {
	var roles []string
	for _, role := range strings.Split(binding, ",") {
		role = strings.TrimSpace(role)
		if !milvusRole.MatchString(role) {
			return nil, fmt.Errorf("role %q is not a Milvus role name", role)
		}
		roles = append(roles, role)
	}
	return roles, nil
}

// MilvusConfig configures the Milvus provider (A239): each lease is a Milvus
// user with a generated password and only its role's Milvus roles, created
// through the RESTful API v2; revocation drops the user, and Milvus refuses its
// next request.
type MilvusConfig struct {
	// Endpoint is the Milvus proxy's RESTful API, https://<host>:19530.
	Endpoint              string
	AdminUser             string
	AdminPassword         []byte
	RoleBindings          map[string]string
	UsernamePrefix        string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// MilvusBackend issues Milvus users.
type MilvusBackend struct {
	endpoint      string
	adminUser     string
	adminPassword *secret.Buffer
	roles         map[string][]string
	prefix        string
	client        *http.Client
}

// NewMilvusBackend validates cfg.
func NewMilvusBackend(cfg MilvusConfig) (*MilvusBackend, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret milvus: endpoint: %w", err)
	}
	if strings.TrimSpace(cfg.AdminUser) == "" || strings.Contains(cfg.AdminUser, ":") || len(cfg.AdminPassword) == 0 || cfg.HTTPClient == nil {
		return nil, errors.New("dynsecret milvus: the administrator user, password and an HTTP client are required")
	}
	b := &MilvusBackend{endpoint: strings.TrimRight(cfg.Endpoint, "/"), adminUser: cfg.AdminUser,
		roles: map[string][]string{}, prefix: cfg.UsernamePrefix, client: cfg.HTTPClient}
	for role, binding := range cfg.RoleBindings {
		roles, err := ParseMilvusRoles(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret milvus: role %q: %w", role, err)
		}
		b.roles[role] = roles
	}
	if len(b.roles) == 0 {
		return nil, errors.New("dynsecret milvus: every allowed role needs Milvus roles in role_bindings")
	}
	var err error
	if b.adminPassword, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend.
func (b *MilvusBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user's name derives from the
// lease. Milvus refuses to create a user that exists and lets no one reset a
// password without the old one, so the lease's user is dropped first (dropping
// a user that is gone succeeds): a retry after an uncertain attempt replaces
// the user instead of adding one. If a role grant fails, the new user is
// dropped again.
func (b *MilvusBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret milvus: static credentials are not served")
	}
	roles, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret milvus: role %q has no Milvus roles", req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 32, "_")
	if err != nil {
		return "", nil, err
	}
	if !milvusUser.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret milvus: generated user name %q is not plain", user)
	}
	if err := b.call(ctx, "/v2/vectordb/users/drop", map[string]string{"userName": user}); err != nil {
		return "", nil, fmt.Errorf("dynsecret milvus: replace an earlier attempt's user: %w", err)
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if err := b.call(ctx, "/v2/vectordb/users/create", struct { // #nosec G117 -- the new user's password goes to the Milvus API over the guarded client and is not kept (CWE-200)
		UserName string           `json:"userName"`
		Password secret.JSONBytes `json:"password"`
	}{UserName: user, Password: password}); err != nil {
		return "", nil, fmt.Errorf("dynsecret milvus: create user: %w", err)
	}
	for _, role := range roles {
		if err := b.call(ctx, "/v2/vectordb/users/grant_role", map[string]string{"userName": user, "roleName": role}); err != nil {
			_ = b.call(ctx, "/v2/vectordb/users/drop", map[string]string{"userName": user})
			return "", nil, fmt.Errorf("dynsecret milvus: grant role %s: %w", role, err)
		}
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Username: user, Password: password})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// Revoke implements Backend: the user is dropped, with its role grants, and
// Milvus refuses its next request. Only users this provider names are dropped;
// Milvus answers success for a user already gone.
func (b *MilvusBackend) Revoke(ctx context.Context, ref string) error {
	if !milvusUser.MatchString(ref) || !strings.HasPrefix(ref, sanitizeFragment(b.prefix, defaultDynsecretPrefix)+"_") {
		return fmt.Errorf("dynsecret milvus: refusing to drop %q, which this provider did not create", ref)
	}
	if err := b.call(ctx, "/v2/vectordb/users/drop", map[string]string{"userName": ref}); err != nil {
		return fmt.Errorf("dynsecret milvus: drop user: %w", err)
	}
	return nil
}

// call POSTs one RESTful API v2 request as the administrator. Milvus answers
// HTTP 200 with a result code, which is 0 on success.
func (b *MilvusBackend) call(ctx context.Context, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := b.adminPassword.Use(func(password []byte) error {
		req.Header.Set("Authorization", "Bearer "+b.adminUser+":"+string(password))
		return nil
	}); err != nil {
		return err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return fmt.Errorf("dynsecret milvus: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result) != nil {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if result.Code != 0 {
		return fmt.Errorf("milvus code %d: %s", result.Code, result.Message)
	}
	return nil
}

// Close wipes the administrator password.
func (b *MilvusBackend) Close() { b.adminPassword.Destroy() }
