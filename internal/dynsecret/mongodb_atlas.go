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
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

const atlasAccept = "application/vnd.atlas.2023-01-01+json"

var (
	atlasRole     = regexp.MustCompile(`^[A-Za-z]{1,64}$`)
	atlasDatabase = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	atlasGroupID  = regexp.MustCompile(`^[0-9a-f]{24}$`)
	atlasUser     = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
)

// AtlasRole is one built-in role on one database, as Atlas grants it.
type AtlasRole struct {
	RoleName     string `json:"roleName"`
	DatabaseName string `json:"databaseName"`
}

// ParseAtlasRoles reads a role binding: "<role> on <database>[,<database>]",
// for example "read on orders" or "readWrite on orders,inventory".
func ParseAtlasRoles(binding string) ([]AtlasRole, error) {
	role, databases, ok := strings.Cut(strings.TrimSpace(binding), " on ")
	role = strings.TrimSpace(role)
	if !ok || !atlasRole.MatchString(role) {
		return nil, errors.New(`expected "<role> on <databases>", for example "read on orders"`)
	}
	var roles []AtlasRole
	for _, db := range strings.Split(databases, ",") {
		db = strings.TrimSpace(db)
		if !atlasDatabase.MatchString(db) {
			return nil, fmt.Errorf("database %q is not a plain database name", db)
		}
		roles = append(roles, AtlasRole{RoleName: role, DatabaseName: db})
	}
	return roles, nil
}

// MongoDBAtlasConfig configures the MongoDB Atlas provider (A239): each lease is
// a database user of one Atlas project with a generated password and its role's
// built-in roles, which Atlas itself deletes after the provider's maximum
// lifetime (deleteAfterDate); revocation deletes it at once. The Admin API is
// called with a service account's OAuth token.
type MongoDBAtlasConfig struct {
	// Endpoint is https://cloud.mongodb.com by default.
	Endpoint              string
	GroupID               string
	ClientID              string
	ClientSecret          []byte
	RoleBindings          map[string]string
	UsernamePrefix        string
	MaxLifetime           time.Duration
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
	Now                   func() time.Time
}

// MongoDBAtlasBackend issues Atlas database users.
type MongoDBAtlasBackend struct {
	endpoint     string
	groupID      string
	clientID     string
	clientSecret *secret.Buffer
	roles        map[string][]AtlasRole
	prefix       string
	maxLifetime  time.Duration
	client       *http.Client
	now          func() time.Time
}

// NewMongoDBAtlasBackend validates cfg.
func NewMongoDBAtlasBackend(cfg MongoDBAtlasConfig) (*MongoDBAtlasBackend, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://cloud.mongodb.com"
	}
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret mongodb-atlas: endpoint: %w", err)
	}
	if !atlasGroupID.MatchString(cfg.GroupID) {
		return nil, errors.New("dynsecret mongodb-atlas: the project (group) ID must be Atlas's 24 hexadecimal characters")
	}
	if strings.TrimSpace(cfg.ClientID) == "" || len(cfg.ClientSecret) == 0 || cfg.HTTPClient == nil {
		return nil, errors.New("dynsecret mongodb-atlas: the service account and an HTTP client are required")
	}
	// Atlas deletes a user at most a week after the date it is given.
	if cfg.MaxLifetime < time.Minute || cfg.MaxLifetime > 7*24*time.Hour {
		return nil, errors.New("dynsecret mongodb-atlas: the maximum lifetime must be between 1 minute and 7 days")
	}
	b := &MongoDBAtlasBackend{endpoint: strings.TrimRight(endpoint, "/"), groupID: cfg.GroupID, clientID: cfg.ClientID,
		roles: map[string][]AtlasRole{}, prefix: cfg.UsernamePrefix, maxLifetime: cfg.MaxLifetime, client: cfg.HTTPClient, now: cfg.Now}
	if b.now == nil {
		b.now = time.Now
	}
	for role, binding := range cfg.RoleBindings {
		roles, err := ParseAtlasRoles(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret mongodb-atlas: role %q: %w", role, err)
		}
		b.roles[role] = roles
	}
	var err error
	if b.clientSecret, err = secret.NewFrom(cfg.ClientSecret); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend.
func (b *MongoDBAtlasBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The user's name derives from the
// lease: a retry after an uncertain attempt finds it (409) and updates its
// password and roles instead of adding a user.
func (b *MongoDBAtlasBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret mongodb-atlas: static credentials are not served")
	}
	roles, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret mongodb-atlas: role %q has no database roles", req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 64, "_")
	if err != nil {
		return "", nil, err
	}
	if !atlasUser.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret mongodb-atlas: generated user name %q is not plain", user)
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	deleteAfter := b.now().UTC().Add(b.maxLifetime).Truncate(time.Second)
	body, err := json.Marshal(struct { // #nosec G117 -- the new user's password goes to the Atlas Admin API over the guarded client and is not kept (CWE-200)
		DatabaseName    string           `json:"databaseName"`
		Username        string           `json:"username"`
		Password        secret.JSONBytes `json:"password"`
		Roles           []AtlasRole      `json:"roles"`
		DeleteAfterDate string           `json:"deleteAfterDate"`
		GroupID         string           `json:"groupId"`
	}{DatabaseName: "admin", Username: user, Password: password, Roles: roles,
		DeleteAfterDate: deleteAfter.Format(time.RFC3339), GroupID: b.groupID})
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(body)
	token, err := b.accessToken(ctx)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(token)
	users := "/api/atlas/v2/groups/" + b.groupID + "/databaseUsers"
	status, err := b.call(ctx, token, http.MethodPost, users, body)
	if err == nil && status == http.StatusConflict {
		status, err = b.call(ctx, token, http.MethodPatch, users+"/admin/"+url.PathEscape(user), body)
	}
	if err != nil {
		return "", nil, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", nil, fmt.Errorf("dynsecret mongodb-atlas: create database user: HTTP %d", status)
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username        string           `json:"username"`
		Password        secret.JSONBytes `json:"password"`
		DeleteAfterDate time.Time        `json:"delete_after_date"`
	}{Username: user, Password: password, DeleteAfterDate: deleteAfter})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// Revoke implements Backend: the user is deleted, so Atlas refuses its next
// login. Only users this provider names are deleted; one already gone (or
// already removed by its deleteAfterDate) counts as deleted.
func (b *MongoDBAtlasBackend) Revoke(ctx context.Context, ref string) error {
	if !atlasUser.MatchString(ref) || !issuedPrincipalName(b.prefix, ref) {
		return fmt.Errorf("dynsecret mongodb-atlas: refusing to delete %q, which this provider did not create", ref)
	}
	token, err := b.accessToken(ctx)
	if err != nil {
		return err
	}
	defer secret.Wipe(token)
	status, err := b.call(ctx, token, http.MethodDelete, "/api/atlas/v2/groups/"+b.groupID+"/databaseUsers/admin/"+url.PathEscape(ref), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusAccepted && status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("dynsecret mongodb-atlas: delete database user: HTTP %d", status)
	}
	return nil
}

// accessToken gets a service-account access token (client credentials grant,
// HTTP Basic client authentication) from Atlas's token endpoint.
func (b *MongoDBAtlasBackend) accessToken(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+"/api/oauth/token",
		strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if err := b.clientSecret.Use(func(clientSecret []byte) error {
		req.SetBasicAuth(url.QueryEscape(b.clientID), url.QueryEscape(string(clientSecret)))
		return nil
	}); err != nil {
		return nil, err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return nil, fmt.Errorf("dynsecret mongodb-atlas: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	defer secret.Wipe(body)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dynsecret mongodb-atlas: service account token: HTTP %d", resp.StatusCode)
	}
	var token struct {
		AccessToken secret.JSONBytes `json:"access_token"`
	}
	if err := json.Unmarshal(body, &token); err != nil || len(token.AccessToken) == 0 {
		return nil, errors.New("dynsecret mongodb-atlas: the token response carries no access_token")
	}
	return token.AccessToken, nil
}

func (b *MongoDBAtlasBackend) call(ctx context.Context, token []byte, method, path string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", atlasAccept)
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, fmt.Errorf("dynsecret mongodb-atlas: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// Close wipes the service account's secret.
func (b *MongoDBAtlasBackend) Close() { b.clientSecret.Destroy() }
