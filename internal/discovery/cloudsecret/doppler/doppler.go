// SPDX-License-Identifier: BUSL-1.1

// Package doppler inventories secrets in Doppler projects and configs (A173,
// restored in OD-14).
// Names come from the names-only endpoint, so a metadata-only run never
// receives a value; with content inspection, each config's values are read
// once, inspected and wiped.
package doppler

import (
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
const ProviderName = "doppler"

const (
	defaultBaseURL = "https://api.doppler.com"
	perPage        = 100
	maxPages       = 100
)

// Config configures one Doppler inventory. Project narrows it to one project
// (empty: every project the token can read) and Configs to named configs of
// it (empty: every config).
type Config struct {
	BaseURL        string
	Project        string
	Configs        []string
	Token          cloudcert.TokenProvider
	NamePrefix     string
	InspectContent bool
	// GenericHighEntropy adds the opt-in generic high-entropy rule to
	// content inspection (A172-L4); it has no effect without
	// InspectContent.
	GenericHighEntropy bool
	HTTPClient         *http.Client
	Retry              cloudcert.RetryPolicy
}

// Enumerator is a read-only Doppler secret source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds a Doppler enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.Token == nil {
		return nil, errors.New("doppler: token_ref is required")
	}
	cfg.Project = strings.TrimSpace(cfg.Project)
	if len(cfg.Configs) > 0 && cfg.Project == "" {
		return nil, errors.New("doppler: configs belong to a project; set project")
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("doppler: bad endpoint %q", cfg.BaseURL)
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

type config struct {
	Name        string `json:"name"`
	Environment string `json:"environment"`
	Locked      bool   `json:"locked"`
}

// Enumerate lists every secret name in scope as a metadata finding and, with
// content inspection, inspects each value.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	projects, err := e.projects(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	for _, project := range projects {
		configs, err := e.configs(ctx, project)
		if err != nil {
			return nil, err
		}
		for _, c := range configs {
			found, err := e.enumerateConfig(ctx, project, c)
			if err != nil {
				return nil, err
			}
			out = append(out, found...)
		}
	}
	return out, nil
}

func (e *Enumerator) enumerateConfig(ctx context.Context, project string, c config) ([]cloudsecret.Found, error) {
	q := url.Values{"project": {project}, "config": {c.Name}}
	raw, err := e.get(ctx, "/v3/configs/config/secrets/names?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var names struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, fmt.Errorf("doppler: parse names of %s/%s: %w", project, c.Name, err)
	}
	sort.Strings(names.Names)
	location := project + "/" + c.Name
	var out []cloudsecret.Found
	var selected []string
	for _, name := range names.Names {
		if e.cfg.NamePrefix != "" && !strings.HasPrefix(name, e.cfg.NamePrefix) {
			continue
		}
		selected = append(selected, name)
		resource := "doppler://" + e.host + "/" + location + "/" + name
		out = append(out, cloudsecret.MetadataFound(ProviderName, resource, name, location, resource, map[string]string{
			"secret_name": name, "resource_id": resource, "project": project, "config": c.Name,
			"environment": c.Environment, "locked": strconv.FormatBool(c.Locked), "content_inspected": "false",
		}))
	}
	if !e.cfg.InspectContent || len(selected) == 0 {
		return out, nil
	}
	found, err := e.inspectConfig(ctx, project, c, location, selected)
	if err != nil {
		return nil, err
	}
	return append(out, found...), nil
}

// inspectConfig reads a config's values once. Doppler's raw value is the
// stored one; a reference to another secret is found at that secret's name.
func (e *Enumerator) inspectConfig(ctx context.Context, project string, c config, location string, names []string) ([]cloudsecret.Found, error) {
	q := url.Values{"project": {project}, "config": {c.Name}, "include_dynamic_secrets": {"false"}}
	raw, err := e.get(ctx, "/v3/configs/config/secrets?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		Secrets map[string]struct {
			Raw secretjson.StringBytes `json:"raw"`
		} `json:"secrets"`
	}
	err = json.Unmarshal(raw, &resp)
	secret.Wipe(raw)
	defer func() {
		for _, v := range resp.Secrets {
			secret.Wipe(v.Raw)
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("doppler: parse values of %s: %w", location, err)
	}
	var out []cloudsecret.Found
	for _, name := range names {
		value := resp.Secrets[name].Raw
		if len(value) == 0 {
			continue
		}
		resource := "doppler://" + e.host + "/" + location + "/" + name
		found, err := cloudsecret.InspectSecret(ProviderName, cloudsecret.Secret{
			GenericHighEntropy: e.cfg.GenericHighEntropy,
			Name:               name, ResourceID: resource, Location: location, Provenance: resource, Value: value,
			Fields: []cloudsecret.SecretField{{Name: name, Value: value}},
			Metadata: map[string]string{
				"secret_name": name, "resource_id": resource, "project": project, "config": c.Name, "content_inspected": "true",
			},
		})
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

func (e *Enumerator) projects(ctx context.Context) ([]string, error) {
	if e.cfg.Project != "" {
		return []string{e.cfg.Project}, nil
	}
	var out []string
	for page := 1; page <= maxPages; page++ {
		raw, err := e.get(ctx, "/v3/projects?page="+strconv.Itoa(page)+"&per_page="+strconv.Itoa(perPage))
		if err != nil {
			return nil, err
		}
		var resp struct {
			Projects []struct {
				Slug string `json:"slug"`
			} `json:"projects"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("doppler: parse projects: %w", err)
		}
		for _, p := range resp.Projects {
			out = append(out, p.Slug)
		}
		if len(resp.Projects) < perPage {
			return out, nil
		}
	}
	return nil, fmt.Errorf("doppler: more than %d projects", perPage*maxPages)
}

func (e *Enumerator) configs(ctx context.Context, project string) ([]config, error) {
	var listed []config
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"project": {project}, "page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(perPage)}}
		raw, err := e.get(ctx, "/v3/configs?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var resp struct {
			Configs []config `json:"configs"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("doppler: parse configs of %s: %w", project, err)
		}
		listed = append(listed, resp.Configs...)
		if len(resp.Configs) < perPage {
			break
		}
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].Name < listed[j].Name })
	if len(e.cfg.Configs) == 0 {
		return listed, nil
	}
	var out []config
	for _, want := range e.cfg.Configs {
		want = strings.TrimSpace(want)
		found := false
		for _, c := range listed {
			if c.Name == want {
				out = append(out, c)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("doppler: config %q is not in project %s or not visible to this token", want, project)
		}
	}
	return out, nil
}

func (e *Enumerator) get(ctx context.Context, path string) ([]byte, error) {
	tok, err := e.cfg.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("doppler: token: %w", err)
	}
	return cloudcert.GetSigned(ctx, e.cfg.HTTPClient, e.cfg.BaseURL+path, tok, e.cfg.Retry)
}
