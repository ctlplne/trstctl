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
	rabbitmqPermission = regexp.MustCompile(`^(configure|write|read)$`)
	rabbitmqResource   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)
	rabbitmqVHost      = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)
	rabbitmqUser       = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
)

// RabbitMQGrant is a role binding's virtual host and the permission patterns
// RabbitMQ matches resource names against; a permission not granted is "^$".
type RabbitMQGrant struct {
	VHost                  string
	Configure, Write, Read string
}

// ParseRabbitMQGrant reads a role binding: "<permission>[,<permission>] on
// <resource>[,<resource>] in <vhost>", for example "read on orders in /". The
// permissions are configure, write and read; resources are literal queue or
// exchange names, matched exactly.
func ParseRabbitMQGrant(binding string) (RabbitMQGrant, error) {
	perms, rest, ok := strings.Cut(strings.TrimSpace(binding), " on ")
	names, vhost, ok2 := strings.Cut(rest, " in ")
	if !ok || !ok2 {
		return RabbitMQGrant{}, errors.New(`expected "<permissions> on <resources> in <vhost>"`)
	}
	vhost = strings.TrimSpace(vhost)
	if !rabbitmqVHost.MatchString(vhost) {
		return RabbitMQGrant{}, fmt.Errorf("virtual host %q is not a plain name", vhost)
	}
	var escaped []string
	for _, n := range strings.Split(names, ",") {
		n = strings.TrimSpace(n)
		if !rabbitmqResource.MatchString(n) {
			return RabbitMQGrant{}, fmt.Errorf("resource %q is not a literal queue or exchange name", n)
		}
		escaped = append(escaped, strings.ReplaceAll(n, ".", `\.`))
	}
	pattern := "^(" + strings.Join(escaped, "|") + ")$"
	grant := RabbitMQGrant{VHost: vhost, Configure: "^$", Write: "^$", Read: "^$"}
	for _, p := range strings.Split(perms, ",") {
		switch p = strings.TrimSpace(p); {
		case !rabbitmqPermission.MatchString(p):
			return RabbitMQGrant{}, fmt.Errorf("permission %q is not configure, write or read", p)
		case p == "configure":
			grant.Configure = pattern
		case p == "write":
			grant.Write = pattern
		default:
			grant.Read = pattern
		}
	}
	return grant, nil
}

// RabbitMQConfig configures the RabbitMQ provider (A239): each lease is a
// RabbitMQ user with a generated password and its role's permissions in one
// virtual host, created through the management API; revocation deletes the user
// and closes its open connections.
type RabbitMQConfig struct {
	Endpoint              string
	AdminUser             string
	AdminPassword         []byte
	RoleBindings          map[string]string
	UsernamePrefix        string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// RabbitMQBackend issues RabbitMQ users.
type RabbitMQBackend struct {
	endpoint      string
	adminUser     string
	adminPassword *secret.Buffer
	grants        map[string]RabbitMQGrant
	prefix        string
	client        *http.Client
}

// NewRabbitMQBackend validates cfg.
func NewRabbitMQBackend(cfg RabbitMQConfig) (*RabbitMQBackend, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret rabbitmq: endpoint: %w", err)
	}
	if strings.TrimSpace(cfg.AdminUser) == "" || len(cfg.AdminPassword) == 0 || cfg.HTTPClient == nil {
		return nil, errors.New("dynsecret rabbitmq: the administrator user, password and an HTTP client are required")
	}
	b := &RabbitMQBackend{endpoint: strings.TrimRight(cfg.Endpoint, "/"), adminUser: cfg.AdminUser,
		grants: map[string]RabbitMQGrant{}, prefix: cfg.UsernamePrefix, client: cfg.HTTPClient}
	for role, binding := range cfg.RoleBindings {
		grant, err := ParseRabbitMQGrant(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret rabbitmq: role %q: %w", role, err)
		}
		b.grants[role] = grant
	}
	var err error
	if b.adminPassword, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend.
func (b *RabbitMQBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user's name derives from the
// lease, so a retry after an uncertain attempt replaces the same user's
// password instead of adding a user.
func (b *RabbitMQBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret rabbitmq: static credentials are not served")
	}
	grant, ok := b.grants[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret rabbitmq: role %q has no grant", req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 64, "_")
	if err != nil {
		return "", nil, err
	}
	if !rabbitmqUser.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret rabbitmq: generated user name %q is not plain", user)
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	body, err := json.Marshal(struct { // #nosec G117 -- the new user's password goes to the management API over the guarded client and is not kept (CWE-200)
		Password secret.JSONBytes `json:"password"`
		Tags     string           `json:"tags"`
	}{Password: password, Tags: ""})
	if err != nil {
		return "", nil, err
	}
	status, err := b.call(ctx, http.MethodPut, "/api/users/"+url.PathEscape(user), body)
	secret.Wipe(body)
	if err != nil {
		return "", nil, err
	}
	if status != http.StatusCreated && status != http.StatusNoContent {
		return "", nil, fmt.Errorf("dynsecret rabbitmq: create user: HTTP %d", status)
	}
	permissions, err := json.Marshal(map[string]string{"configure": grant.Configure, "write": grant.Write, "read": grant.Read})
	if err != nil {
		return "", nil, err
	}
	status, err = b.call(ctx, http.MethodPut, "/api/permissions/"+url.PathEscape(grant.VHost)+"/"+url.PathEscape(user), permissions)
	if err == nil && status != http.StatusCreated && status != http.StatusNoContent {
		err = fmt.Errorf("HTTP %d", status)
	}
	if err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("dynsecret rabbitmq: set permissions: %w", err)
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
		VHost    string           `json:"vhost"`
	}{Username: user, Password: password, VHost: grant.VHost})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// Revoke implements Backend: the user is deleted, so RabbitMQ refuses its next
// connection, and its open connections are closed. Only users this provider
// names are ever deleted; a user already gone counts as deleted.
func (b *RabbitMQBackend) Revoke(ctx context.Context, ref string) error {
	if !rabbitmqUser.MatchString(ref) || !strings.HasPrefix(ref, sanitizeFragment(b.prefix, defaultDynsecretPrefix)+"_") {
		return fmt.Errorf("dynsecret rabbitmq: refusing to delete %q, which this provider did not create", ref)
	}
	status, err := b.call(ctx, http.MethodDelete, "/api/users/"+url.PathEscape(ref), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("dynsecret rabbitmq: delete user: HTTP %d", status)
	}
	return b.closeConnections(ctx, ref)
}

// closeConnections closes the user's open connections: deleting a RabbitMQ
// user refuses new connections but leaves established ones open.
func (b *RabbitMQBackend) closeConnections(ctx context.Context, user string) error {
	req, err := b.request(ctx, http.MethodGet, "/api/connections?columns=name,user", nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return fmt.Errorf("dynsecret rabbitmq: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var connections []struct {
		Name string `json:"name"`
		User string `json:"user"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&connections) != nil {
		return fmt.Errorf("dynsecret rabbitmq: list connections: HTTP %d", resp.StatusCode)
	}
	for _, c := range connections {
		if c.User != user {
			continue
		}
		status, err := b.call(ctx, http.MethodDelete, "/api/connections/"+url.PathEscape(c.Name), nil)
		if err != nil {
			return err
		}
		if status != http.StatusNoContent && status != http.StatusNotFound {
			return fmt.Errorf("dynsecret rabbitmq: close a connection of %s: HTTP %d", user, status)
		}
	}
	return nil
}

func (b *RabbitMQBackend) request(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Reason", "trstctl dynamic-secret lease revoked")
	if err := b.adminPassword.Use(func(password []byte) error {
		req.SetBasicAuth(b.adminUser, string(password))
		return nil
	}); err != nil {
		return nil, err
	}
	return req, nil
}

func (b *RabbitMQBackend) call(ctx context.Context, method, path string, body []byte) (int, error) {
	req, err := b.request(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, fmt.Errorf("dynsecret rabbitmq: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// Close wipes the administrator password.
func (b *RabbitMQBackend) Close() { b.adminPassword.Destroy() }
