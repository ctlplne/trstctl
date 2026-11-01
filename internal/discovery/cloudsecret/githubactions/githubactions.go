// SPDX-License-Identifier: BUSL-1.1

// Package githubactions inventories GitHub Actions secrets (A173): a
// repository's secrets, its environments' secrets and an organization's
// secrets. GitHub's API returns names and timestamps only and never a value,
// so this provider is metadata-only by construction and refuses content
// inspection rather than pretend to perform it.
package githubactions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/netsec"
)

// ProviderName is the discovery provider identifier.
const ProviderName = "github-actions"

const (
	defaultBaseURL = "https://api.github.com"
	perPage        = 100
	// maxPages bounds one listing: 100 pages of 100 secrets.
	maxPages = 100
)

// ErrNoContentInspection reports a source that asked to inspect GitHub
// Actions secret values, which GitHub's API never returns.
var ErrNoContentInspection = errors.New("github-actions: GitHub never returns Actions secret values, so content inspection is not available; inventory is metadata only")

// Config configures one GitHub Actions secret inventory: a repository
// (Owner and Repo, optionally with Environments), an organization (Org), or
// both.
type Config struct {
	BaseURL        string
	Owner          string
	Repo           string
	Environments   []string
	Org            string
	Token          cloudcert.TokenProvider
	NamePrefix     string
	InspectContent bool
	HTTPClient     *http.Client
	Retry          cloudcert.RetryPolicy
}

// Enumerator is a read-only GitHub Actions secret source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds a GitHub Actions secret enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.InspectContent {
		return nil, ErrNoContentInspection
	}
	if cfg.Token == nil {
		return nil, errors.New("github-actions: token_ref is required")
	}
	cfg.Owner, cfg.Repo, cfg.Org = strings.TrimSpace(cfg.Owner), strings.TrimSpace(cfg.Repo), strings.TrimSpace(cfg.Org)
	if (cfg.Owner == "") != (cfg.Repo == "") {
		return nil, errors.New("github-actions: owner and repo go together")
	}
	if cfg.Repo == "" && cfg.Org == "" {
		return nil, errors.New("github-actions: name a repository (owner and repo) or an org")
	}
	if len(cfg.Environments) > 0 && cfg.Repo == "" {
		return nil, errors.New("github-actions: environments belong to a repository; set owner and repo")
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("github-actions: bad endpoint %q", cfg.BaseURL)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.SafeClient(30 * time.Second)
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg, host: u.Host}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return ProviderName }

type listedSecret struct {
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Visibility string `json:"visibility"`
}

// Enumerate lists every secret in scope as a metadata finding.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	var out []cloudsecret.Found
	if e.cfg.Repo != "" {
		repo := e.cfg.Owner + "/" + e.cfg.Repo
		base := "/repos/" + url.PathEscape(e.cfg.Owner) + "/" + url.PathEscape(e.cfg.Repo)
		secrets, err := e.list(ctx, base+"/actions/secrets")
		if err != nil {
			return nil, err
		}
		out = e.appendFound(out, secrets, "repository", repo, repo+"/actions/secrets/", map[string]string{"repository": repo})
		for _, env := range e.cfg.Environments {
			env = strings.TrimSpace(env)
			if env == "" {
				continue
			}
			secrets, err := e.list(ctx, base+"/environments/"+url.PathEscape(env)+"/secrets")
			if err != nil {
				return nil, err
			}
			out = e.appendFound(out, secrets, "environment", repo, repo+"/environments/"+env+"/secrets/",
				map[string]string{"repository": repo, "environment": env})
		}
	}
	if e.cfg.Org != "" {
		secrets, err := e.list(ctx, "/orgs/"+url.PathEscape(e.cfg.Org)+"/actions/secrets")
		if err != nil {
			return nil, err
		}
		out = e.appendFound(out, secrets, "organization", e.cfg.Org, e.cfg.Org+"/actions/secrets/", map[string]string{"org": e.cfg.Org})
	}
	return out, nil
}

func (e *Enumerator) appendFound(out []cloudsecret.Found, secrets []listedSecret, scope, location, prefix string, extra map[string]string) []cloudsecret.Found {
	for _, s := range secrets {
		if e.cfg.NamePrefix != "" && !strings.HasPrefix(s.Name, e.cfg.NamePrefix) {
			continue
		}
		resource := "github://" + e.host + "/" + prefix + s.Name
		meta := map[string]string{
			"secret_name": s.Name, "resource_id": resource, "scope": scope,
			"created_at": s.CreatedAt, "updated_at": s.UpdatedAt,
			"content_inspected": "false", "value_readable": "false",
		}
		if s.Visibility != "" {
			meta["visibility"] = s.Visibility
		}
		for k, v := range extra {
			meta[k] = v
		}
		out = append(out, cloudsecret.MetadataFound(ProviderName, resource, s.Name, location, resource, meta))
	}
	return out
}

func (e *Enumerator) list(ctx context.Context, path string) ([]listedSecret, error) {
	var out []listedSecret
	for page := 1; page <= maxPages; page++ {
		raw, err := e.get(ctx, e.cfg.BaseURL+path+"?per_page="+strconv.Itoa(perPage)+"&page="+strconv.Itoa(page))
		if err != nil {
			return nil, err
		}
		var resp struct {
			TotalCount int            `json:"total_count"`
			Secrets    []listedSecret `json:"secrets"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("github-actions: parse %s: %w", path, err)
		}
		out = append(out, resp.Secrets...)
		if len(resp.Secrets) < perPage || len(out) >= resp.TotalCount {
			return out, nil
		}
	}
	return nil, fmt.Errorf("github-actions: %s has more than %d secrets", path, perPage*maxPages)
}

func (e *Enumerator) get(ctx context.Context, target string) ([]byte, error) {
	tok, err := e.cfg.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("github-actions: token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, nil, e.cfg.Retry)
}
