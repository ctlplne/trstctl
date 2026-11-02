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
	"net/url"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

var (
	couchbaseRole     = regexp.MustCompile(`^[a-z][a-z_]{1,63}$`)
	couchbaseKeyspace = regexp.MustCompile(`^[A-Za-z0-9._%-]{1,100}(:[A-Za-z0-9_%-]{1,251}){0,2}$`)
	couchbaseUser     = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
)

// ParseCouchbaseRoles reads a role binding: "<roles> on <keyspaces>", for
// example "bucket_full_access on orders" (the Community Edition's data role) or
// "data_reader,query_select on orders" (Enterprise Edition); a keyspace is a
// bucket, or bucket:scope:collection where the edition grants that finely. It
// returns Couchbase's roles parameter: each role on each keyspace.
func ParseCouchbaseRoles(binding string) (string, error) {
	roles, keyspaces, ok := strings.Cut(strings.TrimSpace(binding), " on ")
	if !ok {
		return "", errors.New(`expected "<roles> on <buckets>", for example "bucket_full_access on orders"`)
	}
	var out []string
	for _, role := range strings.Split(roles, ",") {
		role = strings.TrimSpace(role)
		if !couchbaseRole.MatchString(role) {
			return "", fmt.Errorf("role %q is not a Couchbase role name", role)
		}
		for _, keyspace := range strings.Split(keyspaces, ",") {
			keyspace = strings.TrimSpace(keyspace)
			if !couchbaseKeyspace.MatchString(keyspace) {
				return "", fmt.Errorf("keyspace %q is not a bucket or bucket:scope:collection", keyspace)
			}
			out = append(out, role+"["+keyspace+"]")
		}
	}
	return strings.Join(out, ","), nil
}

// CouchbaseConfig configures the Couchbase provider (A239): each lease is a
// local Couchbase user with a generated password and only its role's roles on
// the named buckets, created through the cluster's management REST API;
// revocation deletes the user, and Couchbase refuses its next request.
type CouchbaseConfig struct {
	// Endpoint is the management REST API, https://<node>:18091.
	Endpoint              string
	AdminUser             string
	AdminPassword         []byte
	RoleBindings          map[string]string
	UsernamePrefix        string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// CouchbaseBackend issues Couchbase users.
type CouchbaseBackend struct {
	endpoint      string
	adminUser     string
	adminPassword *secret.Buffer
	roles         map[string]string
	prefix        string
	client        *http.Client
}

// NewCouchbaseBackend validates cfg.
func NewCouchbaseBackend(cfg CouchbaseConfig) (*CouchbaseBackend, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret couchbase: endpoint: %w", err)
	}
	if strings.TrimSpace(cfg.AdminUser) == "" || len(cfg.AdminPassword) == 0 || cfg.HTTPClient == nil {
		return nil, errors.New("dynsecret couchbase: the administrator user, password and an HTTP client are required")
	}
	b := &CouchbaseBackend{endpoint: strings.TrimRight(cfg.Endpoint, "/"), adminUser: cfg.AdminUser,
		roles: map[string]string{}, prefix: cfg.UsernamePrefix, client: cfg.HTTPClient}
	for role, binding := range cfg.RoleBindings {
		roles, err := ParseCouchbaseRoles(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret couchbase: role %q: %w", role, err)
		}
		b.roles[role] = roles
	}
	if len(b.roles) == 0 {
		return nil, errors.New("dynsecret couchbase: every allowed role needs roles in role_bindings")
	}
	var err error
	if b.adminPassword, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend.
func (b *CouchbaseBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user's name derives from the
// lease, and Couchbase's user PUT replaces an existing user, so a retry after
// an uncertain attempt replaces the same user's password and roles instead of
// adding a user.
func (b *CouchbaseBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret couchbase: static credentials are not served")
	}
	roles, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret couchbase: role %q has no roles", req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 128, "_")
	if err != nil {
		return "", nil, err
	}
	if !couchbaseUser.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret couchbase: generated user name %q is not plain", user)
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	body := appendFormEscaped([]byte("password="), password)
	body = append(body, "&roles="+url.QueryEscape(roles)+"&name="+url.QueryEscape("trstctl dynamic secret")...)
	status, err := b.call(ctx, http.MethodPut, "/settings/rbac/users/local/"+url.PathEscape(user), body)
	secret.Wipe(body)
	if err != nil {
		return "", nil, err
	}
	if status != http.StatusOK {
		return "", nil, fmt.Errorf("dynsecret couchbase: create user: HTTP %d", status)
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

// Revoke implements Backend: the user is deleted, and Couchbase refuses its
// next request. Only users this provider names are deleted; a user already gone
// counts as deleted.
func (b *CouchbaseBackend) Revoke(ctx context.Context, ref string) error {
	if !couchbaseUser.MatchString(ref) || !strings.HasPrefix(ref, sanitizeFragment(b.prefix, defaultDynsecretPrefix)+"_") {
		return fmt.Errorf("dynsecret couchbase: refusing to delete %q, which this provider did not create", ref)
	}
	status, err := b.call(ctx, http.MethodDelete, "/settings/rbac/users/local/"+url.PathEscape(ref), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("dynsecret couchbase: delete user: HTTP %d", status)
	}
	return nil
}

func (b *CouchbaseBackend) call(ctx context.Context, method, path string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := b.adminPassword.Use(func(password []byte) error {
		req.SetBasicAuth(b.adminUser, string(password))
		return nil
	}); err != nil {
		return 0, err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, fmt.Errorf("dynsecret couchbase: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// appendFormEscaped appends src percent-encoded for a form body without making
// a string of it (the generated password stays in wipeable bytes).
func appendFormEscaped(dst, src []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, c := range src {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			dst = append(dst, c)
		default:
			dst = append(dst, '%', hex[c>>4], hex[c&15])
		}
	}
	return dst
}

// Close wipes the administrator password.
func (b *CouchbaseBackend) Close() { b.adminPassword.Destroy() }
