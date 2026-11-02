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
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

const elasticsearchRefPrefix = "es-apikey:"

var (
	elasticsearchPrivilege = regexp.MustCompile(`^[a-z_]{1,64}$`)
	elasticsearchPattern   = regexp.MustCompile(`^[A-Za-z0-9._*-]{1,255}$`)
	elasticsearchKeyID     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// ElasticsearchIndexGrant is a role binding's index privileges and patterns.
type ElasticsearchIndexGrant struct {
	Privileges []string
	Names      []string
}

// ParseElasticsearchIndexGrant reads a role binding: "<privilege>[,<privilege>]
// on <index pattern>[,<index pattern>]", for example "read on logs-*".
func ParseElasticsearchIndexGrant(binding string) (ElasticsearchIndexGrant, error) {
	privileges, names, ok := strings.Cut(strings.TrimSpace(binding), " on ")
	if !ok {
		return ElasticsearchIndexGrant{}, errors.New(`expected "<privileges> on <index patterns>"`)
	}
	var grant ElasticsearchIndexGrant
	for _, p := range strings.Split(strings.TrimSpace(privileges), ",") {
		if !elasticsearchPrivilege.MatchString(strings.TrimSpace(p)) {
			return ElasticsearchIndexGrant{}, fmt.Errorf("index privilege %q is not a privilege name", p)
		}
		grant.Privileges = append(grant.Privileges, strings.TrimSpace(p))
	}
	for _, n := range strings.Split(strings.TrimSpace(names), ",") {
		if !elasticsearchPattern.MatchString(strings.TrimSpace(n)) {
			return ElasticsearchIndexGrant{}, fmt.Errorf("index pattern %q is not an index name or pattern", n)
		}
		grant.Names = append(grant.Names, strings.TrimSpace(n))
	}
	return grant, nil
}

// ElasticsearchConfig configures the Elasticsearch provider (A239): each lease
// is an API key that expires with the provider's maximum lifetime and holds
// only its role's index privileges; revocation invalidates it. Keys are
// created by the administrator, so they never exceed the administrator's own
// privileges either.
type ElasticsearchConfig struct {
	Endpoint              string
	AdminUser             string
	AdminPassword         []byte
	RoleBindings          map[string]string
	MaxLifetime           time.Duration
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
	Now                   func() time.Time
}

// ElasticsearchBackend issues Elasticsearch API keys.
type ElasticsearchBackend struct {
	endpoint      string
	adminUser     string
	adminPassword *secret.Buffer
	grants        map[string]ElasticsearchIndexGrant
	maxLifetime   time.Duration
	client        *http.Client
	now           func() time.Time
}

// NewElasticsearchBackend validates cfg.
func NewElasticsearchBackend(cfg ElasticsearchConfig) (*ElasticsearchBackend, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret elasticsearch: endpoint: %w", err)
	}
	if strings.TrimSpace(cfg.AdminUser) == "" || len(cfg.AdminPassword) == 0 {
		return nil, errors.New("dynsecret elasticsearch: the administrator user and password are required")
	}
	if cfg.HTTPClient == nil || cfg.MaxLifetime < time.Second {
		return nil, errors.New("dynsecret elasticsearch: an HTTP client and the maximum lifetime are required")
	}
	b := &ElasticsearchBackend{endpoint: strings.TrimRight(cfg.Endpoint, "/"), adminUser: cfg.AdminUser,
		grants: map[string]ElasticsearchIndexGrant{}, maxLifetime: cfg.MaxLifetime, client: cfg.HTTPClient, now: cfg.Now}
	if b.now == nil {
		b.now = time.Now
	}
	for role, binding := range cfg.RoleBindings {
		grant, err := ParseElasticsearchIndexGrant(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret elasticsearch: role %q: %w", role, err)
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
func (b *ElasticsearchBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The key's name derives from the
// lease: a retry first invalidates any key an uncertain earlier attempt left
// under that name, so a lease never has two live keys.
func (b *ElasticsearchBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret elasticsearch: static credentials are not served")
	}
	grant, ok := b.grants[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret elasticsearch: role %q has no index grant", req.Role)
	}
	name := "trstctl-" + req.Role + "-" + crypto.SHA256Hex([]byte(req.LeaseID + "\x00" + req.Role))[:24]
	var existing struct {
		APIKeys []struct {
			ID string `json:"id"`
		} `json:"api_keys"`
	}
	status, body, err := b.call(ctx, http.MethodGet, "/_security/api_key?active_only=true&name="+url.QueryEscape(name), nil)
	if err != nil {
		return "", nil, err
	}
	if status == http.StatusOK {
		if err := json.Unmarshal(body, &existing); err != nil {
			return "", nil, errors.New("dynsecret elasticsearch: unreadable API key listing")
		}
	} else if status != http.StatusNotFound {
		return "", nil, fmt.Errorf("dynsecret elasticsearch: list API keys: %s", elasticsearchFailure(status, body))
	}
	for _, key := range existing.APIKeys {
		if err := b.invalidate(ctx, key.ID); err != nil {
			return "", nil, fmt.Errorf("dynsecret elasticsearch: invalidate an interrupted key: %w", err)
		}
	}
	request, err := json.Marshal(map[string]any{
		"name":       name,
		"expiration": strconv.FormatInt(int64(b.maxLifetime/time.Second), 10) + "s",
		"role_descriptors": map[string]any{"trstctl_lease": map[string]any{
			"cluster": []string{},
			"indices": []map[string]any{{"names": grant.Names, "privileges": grant.Privileges}},
		}},
		"metadata": map[string]string{"trstctl_role": req.Role},
	})
	if err != nil {
		return "", nil, err
	}
	status, body, err = b.call(ctx, http.MethodPost, "/_security/api_key", request)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(body)
	if status != http.StatusOK {
		return "", nil, fmt.Errorf("dynsecret elasticsearch: create API key: %s", elasticsearchFailure(status, body))
	}
	var created struct {
		ID         string           `json:"id"`
		APIKey     secret.JSONBytes `json:"api_key"`
		Encoded    secret.JSONBytes `json:"encoded"`
		Expiration int64            `json:"expiration"`
	}
	if err := json.Unmarshal(body, &created); err != nil || !elasticsearchKeyID.MatchString(created.ID) || len(created.Encoded) == 0 {
		return "", nil, errors.New("dynsecret elasticsearch: the API key response carries no key")
	}
	defer secret.Wipe(created.APIKey)
	defer secret.Wipe(created.Encoded)
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		ID        string           `json:"id"`
		APIKey    secret.JSONBytes `json:"api_key"`
		Encoded   secret.JSONBytes `json:"encoded"`
		ExpiresAt time.Time        `json:"expires_at"`
	}{ID: created.ID, APIKey: created.APIKey, Encoded: created.Encoded, ExpiresAt: time.UnixMilli(created.Expiration).UTC()})
	if err != nil {
		return "", nil, err
	}
	return elasticsearchRefPrefix + created.ID, credential, nil
}

// Revoke implements Backend: the key is invalidated, so Elasticsearch refuses
// it (401). Invalidating an already invalidated or expired key succeeds.
func (b *ElasticsearchBackend) Revoke(ctx context.Context, ref string) error {
	id, ok := strings.CutPrefix(ref, elasticsearchRefPrefix)
	if !ok || !elasticsearchKeyID.MatchString(id) {
		return fmt.Errorf("dynsecret elasticsearch: %q is not an API key this provider issued", ref)
	}
	return b.invalidate(ctx, id)
}

func (b *ElasticsearchBackend) invalidate(ctx context.Context, id string) error {
	request, err := json.Marshal(map[string][]string{"ids": {id}})
	if err != nil {
		return err
	}
	status, body, err := b.call(ctx, http.MethodDelete, "/_security/api_key", request)
	if err != nil {
		return err
	}
	var result struct {
		ErrorCount int `json:"error_count"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &result) != nil || result.ErrorCount != 0 {
		return fmt.Errorf("dynsecret elasticsearch: invalidate API key: %s", elasticsearchFailure(status, body))
	}
	return nil
}

func (b *ElasticsearchBackend) call(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := b.adminPassword.Use(func(password []byte) error {
		req.SetBasicAuth(b.adminUser, string(password))
		return nil
	}); err != nil {
		return 0, nil, err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret elasticsearch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret elasticsearch: read the response: %w", err)
	}
	return resp.StatusCode, out, nil
}

// elasticsearchFailure names an error by its status and Elasticsearch's error
// type only.
func elasticsearchFailure(status int, body []byte) string {
	var e struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && elasticsearchPrivilege.MatchString(e.Error.Type) {
		return fmt.Sprintf("HTTP %d (%s)", status, e.Error.Type)
	}
	return fmt.Sprintf("HTTP %d", status)
}

// Close wipes the administrator password.
func (b *ElasticsearchBackend) Close() { b.adminPassword.Destroy() }
