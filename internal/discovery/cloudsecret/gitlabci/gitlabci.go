// SPDX-License-Identifier: BUSL-1.1

// Package gitlabci inventories GitLab CI/CD variables: a project's and a
// group's variables (A173) and the instance-level variables every project on
// a self-managed instance inherits (OD-2), with their type, protection,
// masking, visibility and environment scope. GitLab returns a variable's
// value in the list response unless the variable is hidden, so every
// response body is wiped after it is read; values are inspected only when
// content inspection was chosen, and a hidden variable is reported as not
// inspectable with the reason.
package gitlabci

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

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secretjson"
)

// ProviderName is the discovery provider identifier.
const ProviderName = "gitlab-ci"

const (
	defaultBaseURL = "https://gitlab.com"
	perPage        = 100
	maxPages       = 100
)

// Config configures one GitLab CI/CD variable inventory: a project, a group
// (each by numeric ID or full path), the instance, or any of them together.
type Config struct {
	BaseURL string
	Project string
	Group   string
	// Instance lists the instance-level variables too; GitLab serves them
	// to an administrator's token only.
	Instance       bool
	Token          cloudcert.TokenProvider
	NamePrefix     string
	InspectContent bool
	HTTPClient     *http.Client
	Retry          cloudcert.RetryPolicy
}

// Enumerator is a read-only GitLab CI/CD variable source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds a GitLab CI/CD variable enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.Token == nil {
		return nil, errors.New("gitlab-ci: token_ref is required")
	}
	cfg.Project, cfg.Group = strings.TrimSpace(cfg.Project), strings.TrimSpace(cfg.Group)
	if cfg.Project == "" && cfg.Group == "" && !cfg.Instance {
		return nil, errors.New("gitlab-ci: name a project, a group, or the instance")
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("gitlab-ci: bad endpoint %q", cfg.BaseURL)
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

type variable struct {
	Key              string `json:"key"`
	VariableType     string `json:"variable_type"`
	Protected        bool   `json:"protected"`
	Masked           bool   `json:"masked"`
	Hidden           bool   `json:"hidden"`
	Raw              bool   `json:"raw"`
	EnvironmentScope string `json:"environment_scope"`
	// Value is nil for a hidden variable, whose value GitLab returns as null.
	Value *secretjson.StringBytes `json:"value"`
}

func (v variable) value() []byte {
	if v.Value == nil {
		return nil
	}
	return *v.Value
}

// Enumerate lists every variable in scope as a metadata finding and, with
// content inspection, inspects each readable value.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	var out []cloudsecret.Found
	for _, scope := range []struct{ kind, id, segment string }{
		{"project", e.cfg.Project, "projects"}, {"group", e.cfg.Group, "groups"},
	} {
		if scope.id == "" {
			continue
		}
		found, err := e.enumerateScope(ctx, scope.kind, scope.id,
			"/api/v4/"+scope.segment+"/"+url.PathEscape(scope.id)+"/variables", scope.segment+"/"+scope.id+"/variables/")
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	if e.cfg.Instance {
		found, err := e.enumerateScope(ctx, "instance", e.host, "/api/v4/admin/ci/variables", "instance/variables/")
		if err != nil {
			return nil, fmt.Errorf("gitlab-ci: instance variables (GitLab lists them to an administrator's token only): %w", err)
		}
		out = append(out, found...)
	}
	return out, nil
}

// enumerateScope lists one scope's variables: kind is "project", "group" or
// "instance" and id that scope's ID (the project or group ID or path, or the
// instance's host).
func (e *Enumerator) enumerateScope(ctx context.Context, kind, id, path, resourcePrefix string) ([]cloudsecret.Found, error) {
	vars, err := e.list(ctx, path)
	defer func() {
		for _, v := range vars {
			secret.Wipe(v.value())
		}
	}()
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	for _, v := range vars {
		if e.cfg.NamePrefix != "" && !strings.HasPrefix(v.Key, e.cfg.NamePrefix) {
			continue
		}
		envScope := v.EnvironmentScope
		if envScope == "" {
			envScope = "*"
		}
		resource := "gitlab://" + e.host + "/" + resourcePrefix + v.Key
		if envScope != "*" {
			resource += "?environment_scope=" + url.QueryEscape(envScope)
		}
		location := kind + ":" + id
		if kind == "instance" {
			location = kind
		}
		meta := map[string]string{
			"secret_name": v.Key, "resource_id": resource, "scope": kind, kind: id,
			"variable_type": v.VariableType, "protected": strconv.FormatBool(v.Protected),
			"masked": strconv.FormatBool(v.Masked), "hidden": strconv.FormatBool(v.Hidden),
			"environment_scope": envScope, "content_inspected": "false",
		}
		if e.cfg.InspectContent && v.Hidden {
			meta["content_unavailable_reason"] = "hidden variable: GitLab never returns its value"
		}
		out = append(out, cloudsecret.MetadataFound(ProviderName, resource, v.Key, location, resource, meta))
		value := v.value()
		if !e.cfg.InspectContent || v.Hidden || len(value) == 0 {
			continue
		}
		inspectMeta := map[string]string{
			"secret_name": v.Key, "resource_id": resource, "scope": kind, kind: id,
			"environment_scope": envScope, "content_inspected": "true",
		}
		found, err := cloudsecret.InspectSecret(ProviderName, cloudsecret.Secret{
			Name: v.Key, ResourceID: resource, Location: location, Provenance: resource,
			Value: value, Fields: []cloudsecret.SecretField{{Name: v.Key, Value: value}}, Metadata: inspectMeta,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

// list reads every page of a variables listing. The response bodies carry
// values, so each is wiped as soon as it is decoded; the returned values are
// the caller's to wipe.
func (e *Enumerator) list(ctx context.Context, path string) ([]variable, error) {
	var out []variable
	for page := 1; page <= maxPages; page++ {
		raw, err := e.get(ctx, e.cfg.BaseURL+path+"?per_page="+strconv.Itoa(perPage)+"&page="+strconv.Itoa(page))
		if err != nil {
			return out, err
		}
		var vars []variable
		err = json.Unmarshal(raw, &vars)
		secret.Wipe(raw)
		if err != nil {
			return out, fmt.Errorf("gitlab-ci: parse %s: %w", path, err)
		}
		out = append(out, vars...)
		if len(vars) < perPage {
			return out, nil
		}
	}
	return out, fmt.Errorf("gitlab-ci: %s has more than %d variables", path, perPage*maxPages)
}

func (e *Enumerator) get(ctx context.Context, target string) ([]byte, error) {
	tok, err := e.cfg.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("gitlab-ci: token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", tok)
	req.Header.Set("Accept", "application/json")
	return cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, nil, e.cfg.Retry)
}
