// SPDX-License-Identifier: BUSL-1.1

// Package infisical inventories the secrets of Infisical projects (OD-13):
// each project's environments, every folder below the chosen secret path,
// with each secret's key, version, type, tags and dates. A metadata-only run
// asks Infisical to leave values out (viewSecretValue=false); every response
// body is still wiped once it is decoded, because a server that ignores that
// parameter would return values. With content inspection the values are read
// once per environment, inspected and wiped. A machine identity signs in
// with Universal Auth (client ID and client secret) or brings an access
// token.
package infisical

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secretjson"
)

// ProviderName is the discovery provider identifier.
const ProviderName = "infisical"

const (
	defaultBaseURL = "https://app.infisical.com"
	projectPage    = 100
	maxProjects    = 1000
)

// Config configures one Infisical inventory. Project narrows it to one
// project ID (empty: every secret-manager project the identity can read),
// Environments to named environment slugs (empty: each project's
// environments) and SecretPath to a folder (empty: "/"); folders below it
// are always included.
type Config struct {
	BaseURL string
	// ClientID and ClientSecret are a machine identity's Universal Auth
	// credentials; the run signs in once. Token is an access token instead.
	ClientID       string
	ClientSecret   cloudcert.TokenProvider
	Token          cloudcert.TokenProvider
	Project        string
	Environments   []string
	SecretPath     string
	NamePrefix     string
	InspectContent bool
	HTTPClient     *http.Client
	Retry          cloudcert.RetryPolicy
}

// Enumerator is a read-only Infisical secret source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds an Infisical enumerator.
func New(cfg Config) (*Enumerator, error) {
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	switch {
	case cfg.Token != nil && (cfg.ClientID != "" || cfg.ClientSecret != nil):
		return nil, errors.New("infisical: use token_ref or client_id with client_secret_ref, not both")
	case cfg.Token == nil && (cfg.ClientID == "" || cfg.ClientSecret == nil):
		return nil, errors.New("infisical: client_id and client_secret_ref (Universal Auth) or token_ref are required")
	}
	cfg.Project = strings.TrimSpace(cfg.Project)
	if len(cfg.Environments) > 0 && cfg.Project == "" {
		return nil, errors.New("infisical: environments belong to a project; set project")
	}
	path, err := cleanSecretPath(cfg.SecretPath)
	if err != nil {
		return nil, err
	}
	cfg.SecretPath = path
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("infisical: bad endpoint %q", cfg.BaseURL)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.SafeClient(30 * time.Second)
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg, host: u.Host}, nil
}

// cleanSecretPath accepts "", "/" or an absolute folder path without dot
// segments, and returns it with one leading slash and no trailing one.
func cleanSecretPath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" || path == "/" {
		return "/", nil
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("infisical: path_prefix %q must start with /", raw)
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\x00\\?#") {
			return "", fmt.Errorf("infisical: path_prefix %q is not a clean folder path", raw)
		}
	}
	return "/" + strings.Join(parts, "/"), nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return ProviderName }

type environment struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type project struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Slug         string        `json:"slug"`
	Type         string        `json:"type"`
	Environments []environment `json:"environments"`
}

type tag struct {
	Slug string `json:"slug"`
}

type secretItem struct {
	ID          string                 `json:"id"`
	SecretKey   string                 `json:"secretKey"`
	SecretValue secretjson.StringBytes `json:"secretValue"`
	Version     int64                  `json:"version"`
	Type        string                 `json:"type"`
	Environment string                 `json:"environment"`
	SecretPath  string                 `json:"secretPath"`
	Tags        []tag                  `json:"tags"`
	CreatedAt   string                 `json:"createdAt"`
	UpdatedAt   string                 `json:"updatedAt"`
	Hidden      bool                   `json:"secretValueHidden"`
}

// Enumerate lists every secret in scope as a metadata finding and, with
// content inspection, inspects each value.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	token, err := e.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	projects, err := e.projects(ctx, token)
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	for _, p := range projects {
		envs := p.Environments
		if len(e.cfg.Environments) > 0 {
			envs = envs[:0:0]
			for _, slug := range e.cfg.Environments {
				envs = append(envs, environment{Slug: strings.TrimSpace(slug), Name: strings.TrimSpace(slug)})
			}
		}
		for _, env := range envs {
			found, err := e.enumerateEnvironment(ctx, token, p, env)
			if err != nil {
				return nil, err
			}
			out = append(out, found...)
		}
	}
	return out, nil
}

func (e *Enumerator) enumerateEnvironment(ctx context.Context, token string, p project, env environment) ([]cloudsecret.Found, error) {
	items, err := e.secrets(ctx, token, p.ID, env.Slug, e.cfg.InspectContent)
	defer func() {
		for _, item := range items {
			secret.Wipe(item.SecretValue)
		}
	}()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].SecretPath != items[j].SecretPath {
			return items[i].SecretPath < items[j].SecretPath
		}
		return items[i].SecretKey < items[j].SecretKey
	})
	var out []cloudsecret.Found
	for _, item := range items {
		if item.Type == "personal" || (e.cfg.NamePrefix != "" && !strings.HasPrefix(item.SecretKey, e.cfg.NamePrefix)) {
			continue
		}
		folder := item.SecretPath
		if folder == "" {
			folder = e.cfg.SecretPath
		}
		location := p.ID + "/" + env.Slug + folder
		resource := "infisical://" + e.host + "/projects/" + p.ID + "/" + env.Slug + strings.TrimRight(folder, "/") + "/" + item.SecretKey
		tags := make([]string, 0, len(item.Tags))
		for _, t := range item.Tags {
			tags = append(tags, t.Slug)
		}
		sort.Strings(tags)
		meta := map[string]string{
			"secret_name": item.SecretKey, "resource_id": resource, "project": p.ID, "project_name": p.Name,
			"environment": env.Slug, "secret_path": folder, "version": strconv.FormatInt(item.Version, 10),
			"secret_type": item.Type, "tags": strings.Join(tags, ","), "created_at": item.CreatedAt,
			"updated_at": item.UpdatedAt, "content_inspected": "false",
		}
		out = append(out, cloudsecret.MetadataFound(ProviderName, resource, item.SecretKey, location, resource, meta))
		if !e.cfg.InspectContent || item.Hidden || len(item.SecretValue) == 0 {
			continue
		}
		found, err := cloudsecret.InspectSecret(ProviderName, cloudsecret.Secret{
			Name: item.SecretKey, ResourceID: resource, Location: location, Provenance: resource,
			Value: item.SecretValue, Fields: []cloudsecret.SecretField{{Name: item.SecretKey, Value: item.SecretValue}},
			Metadata: map[string]string{
				"secret_name": item.SecretKey, "resource_id": resource, "project": p.ID,
				"environment": env.Slug, "secret_path": folder, "content_inspected": "true",
			},
		})
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

// secrets reads one environment's secrets below the configured path, with
// values only when withValues is set. References and imports are not
// expanded: a referenced secret is inventoried where it is stored.
func (e *Enumerator) secrets(ctx context.Context, token, projectID, env string, withValues bool) ([]secretItem, error) {
	q := url.Values{
		"projectId": {projectID}, "environment": {env}, "secretPath": {e.cfg.SecretPath}, "recursive": {"true"},
		"viewSecretValue": {strconv.FormatBool(withValues)}, "expandSecretReferences": {"false"},
		"includeImports": {"false"}, "includePersonalOverrides": {"false"},
	}
	raw, err := e.get(ctx, token, "/api/v4/secrets?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("infisical: secrets of %s/%s: %w", projectID, env, err)
	}
	var resp struct {
		Secrets []secretItem `json:"secrets"`
	}
	err = json.Unmarshal(raw, &resp)
	secret.Wipe(raw)
	if err != nil {
		for _, item := range resp.Secrets {
			secret.Wipe(item.SecretValue)
		}
		return nil, fmt.Errorf("infisical: parse secrets of %s/%s: %w", projectID, env, err)
	}
	if !withValues {
		// A metadata-only run never keeps a value, even from a server that
		// ignored viewSecretValue=false.
		for i := range resp.Secrets {
			secret.Wipe(resp.Secrets[i].SecretValue)
			resp.Secrets[i].SecretValue = nil
		}
	}
	return resp.Secrets, nil
}

func (e *Enumerator) projects(ctx context.Context, token string) ([]project, error) {
	if e.cfg.Project != "" {
		raw, err := e.get(ctx, token, "/api/v1/projects/"+url.PathEscape(e.cfg.Project))
		if err != nil {
			return nil, fmt.Errorf("infisical: project %s: %w", e.cfg.Project, err)
		}
		var resp struct {
			Project project `json:"project"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil || resp.Project.ID == "" {
			return nil, fmt.Errorf("infisical: parse project %s: %v", e.cfg.Project, err)
		}
		return []project{resp.Project}, nil
	}
	var out []project
	for offset := 0; offset < maxProjects; offset += projectPage {
		q := url.Values{"type": {"secret-manager"}, "limit": {strconv.Itoa(projectPage)}, "offset": {strconv.Itoa(offset)}}
		raw, err := e.get(ctx, token, "/api/v1/projects?"+q.Encode())
		if err != nil {
			return nil, fmt.Errorf("infisical: projects: %w", err)
		}
		var resp struct {
			Projects   []project `json:"projects"`
			TotalCount int       `json:"totalCount"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("infisical: parse projects: %w", err)
		}
		for _, p := range resp.Projects {
			if p.Type == "" || p.Type == "secret-manager" {
				out = append(out, p)
			}
		}
		// Infisical pages by limit and offset; totalCount is not always sent.
		if len(resp.Projects) < projectPage || (resp.TotalCount > 0 && offset+len(resp.Projects) >= resp.TotalCount) {
			sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
			return out, nil
		}
	}
	return nil, fmt.Errorf("infisical: more than %d projects; set project", maxProjects)
}

// accessToken signs in with Universal Auth, or returns the configured token.
func (e *Enumerator) accessToken(ctx context.Context) (string, error) {
	if e.cfg.Token != nil {
		tok, err := e.cfg.Token.Token(ctx)
		if err != nil {
			return "", fmt.Errorf("infisical: token: %w", err)
		}
		return tok, nil
	}
	clientSecret, err := e.cfg.ClientSecret.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("infisical: client secret: %w", err)
	}
	body := make([]byte, 0, 64+len(e.cfg.ClientID)+len(clientSecret))
	body = append(body, `{"clientId":`...)
	body = append(body, secretjson.QuoteBytes([]byte(e.cfg.ClientID))...)
	body = append(body, `,"clientSecret":`...)
	body = append(body, secretjson.QuoteBytes([]byte(clientSecret))...)
	body = append(body, '}')
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.BaseURL+"/api/v1/auth/universal-auth/login", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	raw, err := cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, body, e.cfg.Retry)
	if err != nil {
		return "", fmt.Errorf("infisical: universal auth sign-in: %w", statusOnly(err))
	}
	defer secret.Wipe(raw)
	var resp struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.AccessToken == "" {
		return "", errors.New("infisical: universal auth sign-in returned no access token")
	}
	return resp.AccessToken, nil
}

// statusOnly keeps a refused request's status but not its body, which
// could echo what was sent.
func statusOnly(err error) error {
	msg := err.Error()
	if strings.HasPrefix(msg, "cloudcert: status ") {
		if i := strings.Index(msg[len("cloudcert: status "):], ":"); i > 0 {
			return errors.New(msg[:len("cloudcert: status ")+i])
		}
	}
	return err
}

func (e *Enumerator) get(ctx context.Context, token, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfg.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	raw, err := cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, nil, e.cfg.Retry)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(raw), nil
}
