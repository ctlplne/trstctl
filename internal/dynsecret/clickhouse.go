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
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

// clickHouseIdentifier is the identifier form the ClickHouse provider accepts
// for users and roles: no quoting is needed, so nothing can be injected.
var clickHouseIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// clickHouseErrorCode keeps only the numeric code of a server error: the error
// text can echo the statement, which carries the generated password.
var clickHouseErrorCode = regexp.MustCompile(`Code: ([0-9]{1,5})\b`)

// ClickHouseConfig configures the ClickHouse provider (A239): each lease is a
// ClickHouse user with a generated password, valid until the provider's maximum
// lifetime, holding the ClickHouse role its lease role is bound to; revocation
// drops the user. It speaks ClickHouse's HTTP interface as an administrator.
type ClickHouseConfig struct {
	Endpoint      string
	AdminUser     string
	AdminPassword []byte
	// RoleBindings maps each allowed role to an existing ClickHouse role that
	// holds its grants.
	RoleBindings          map[string]string
	UsernamePrefix        string
	MaxLifetime           time.Duration
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
	Now                   func() time.Time
}

// ClickHouseBackend issues ClickHouse users.
type ClickHouseBackend struct {
	endpoint      string
	adminUser     string
	adminPassword *secret.Buffer
	roles         map[string]string
	prefix        string
	maxLifetime   time.Duration
	client        *http.Client
	now           func() time.Time
}

// NewClickHouseBackend validates cfg.
func NewClickHouseBackend(cfg ClickHouseConfig) (*ClickHouseBackend, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret clickhouse: endpoint: %w", err)
	}
	if !clickHouseIdentifier.MatchString(cfg.AdminUser) || len(cfg.AdminPassword) == 0 {
		return nil, errors.New("dynsecret clickhouse: the administrator user and password are required")
	}
	if cfg.HTTPClient == nil || cfg.MaxLifetime <= 0 {
		return nil, errors.New("dynsecret clickhouse: an HTTP client and the maximum lifetime are required")
	}
	b := &ClickHouseBackend{endpoint: cfg.Endpoint, adminUser: cfg.AdminUser, roles: map[string]string{},
		prefix: cfg.UsernamePrefix, maxLifetime: cfg.MaxLifetime, client: cfg.HTTPClient, now: cfg.Now}
	if b.now == nil {
		b.now = time.Now
	}
	for role, binding := range cfg.RoleBindings {
		if !clickHouseIdentifier.MatchString(binding) {
			return nil, fmt.Errorf("dynsecret clickhouse: role %q must be bound to a ClickHouse role name", role)
		}
		b.roles[role] = binding
	}
	var err error
	if b.adminPassword, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend.
func (b *ClickHouseBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user's name derives from the
// lease, so a retry after an uncertain attempt replaces the same user (and its
// password) instead of adding another.
func (b *ClickHouseBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret clickhouse: static credentials are not served")
	}
	grant, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret clickhouse: role %q has no ClickHouse role", req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 63, "_")
	if err != nil {
		return "", nil, err
	}
	if !clickHouseIdentifier.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret clickhouse: generated user name %q is not an identifier", user)
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	validUntil := b.now().UTC().Add(b.maxLifetime).Truncate(time.Second).Format(time.RFC3339)
	create := make([]byte, 0, 160+len(password))
	create = append(create, "CREATE USER OR REPLACE "+user+" IDENTIFIED WITH sha256_password BY '"...)
	create = append(create, password...)
	create = append(create, "' VALID UNTIL '"+validUntil+"'"...)
	err = b.exec(ctx, create)
	secret.Wipe(create)
	if err != nil {
		return "", nil, fmt.Errorf("dynsecret clickhouse: create user: %w", err)
	}
	for _, statement := range []string{"GRANT " + grant + " TO " + user, "SET DEFAULT ROLE " + grant + " TO " + user} {
		if err := b.exec(ctx, []byte(statement)); err != nil {
			_ = b.Revoke(ctx, user)
			return "", nil, fmt.Errorf("dynsecret clickhouse: grant: %w", err)
		}
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username   string           `json:"username"`
		Password   secret.JSONBytes `json:"password"`
		ValidUntil string           `json:"valid_until"`
	}{Username: user, Password: password, ValidUntil: validUntil})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// Revoke implements Backend: the user is dropped, so ClickHouse refuses its
// next login. Only users this provider names are ever dropped.
func (b *ClickHouseBackend) Revoke(ctx context.Context, ref string) error {
	if !clickHouseIdentifier.MatchString(ref) || !strings.HasPrefix(ref, sanitizeFragment(b.prefix, defaultDynsecretPrefix)+"_") {
		return fmt.Errorf("dynsecret clickhouse: refusing to drop %q, which this provider did not create", ref)
	}
	if err := b.exec(ctx, []byte("DROP USER IF EXISTS "+ref)); err != nil {
		return fmt.Errorf("dynsecret clickhouse: drop user: %w", err)
	}
	return nil
}

// exec runs one statement through the HTTP interface as the administrator. A
// failure reports the HTTP status and ClickHouse's error code only.
func (b *ClickHouseBackend) exec(ctx context.Context, statement []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(statement))
	if err != nil {
		return err
	}
	if err := b.adminPassword.Use(func(password []byte) error {
		req.SetBasicAuth(b.adminUser, string(password))
		return nil
	}); err != nil {
		return err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	defer secret.Wipe(body)
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if m := clickHouseErrorCode.FindSubmatch(body); m != nil {
		return fmt.Errorf("HTTP %d, ClickHouse error code %s", resp.StatusCode, m[1])
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}

// Close wipes the administrator password.
func (b *ClickHouseBackend) Close() { b.adminPassword.Destroy() }
