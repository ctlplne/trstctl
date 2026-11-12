// SPDX-License-Identifier: BUSL-1.1

// Package akeyless inventories the static secrets of an Akeyless account
// (OD-13): each item's name, type, tags, version and dates under a folder
// path. The item listing never carries a value, so a metadata-only run never
// receives one; with content inspection the values are read in small batches,
// inspected and wiped. An API-key access ID and access key sign in for a
// short-lived token; the base URL may be a self-hosted gateway's API.
package akeyless

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
const ProviderName = "akeyless"

const (
	defaultBaseURL = "https://api.akeyless.io"
	maxPages       = 100
	valueBatch     = 25
)

// Config configures one Akeyless inventory. AccessID and AccessKey are an
// API-key auth method's credentials; PathPrefix is the folder to list (empty:
// "/"), with every folder below it.
type Config struct {
	BaseURL        string
	AccessID       string
	AccessKey      cloudcert.TokenProvider
	PathPrefix     string
	NamePrefix     string
	InspectContent bool
	HTTPClient     *http.Client
	Retry          cloudcert.RetryPolicy
}

// Enumerator is a read-only Akeyless secret source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds an Akeyless enumerator.
func New(cfg Config) (*Enumerator, error) {
	cfg.AccessID = strings.TrimSpace(cfg.AccessID)
	if cfg.AccessID == "" || cfg.AccessKey == nil {
		return nil, errors.New("akeyless: client_id (the access ID) and client_secret_ref (the access key) are required")
	}
	path := "/" + strings.Trim(strings.TrimSpace(cfg.PathPrefix), "/")
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if path != "/" && (part == "" || part == "." || part == "..") {
			return nil, fmt.Errorf("akeyless: path_prefix %q is not a clean folder path", cfg.PathPrefix)
		}
	}
	cfg.PathPrefix = path
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("akeyless: bad endpoint %q", cfg.BaseURL)
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

type item struct {
	Name             string   `json:"item_name"`
	Type             string   `json:"item_type"`
	ID               int64    `json:"item_id"`
	Tags             []string `json:"item_tags"`
	LastVersion      int64    `json:"last_version"`
	CreationDate     string   `json:"creation_date"`
	ModificationDate string   `json:"modification_date"`
}

// Enumerate lists every static secret in scope as a metadata finding and,
// with content inspection, inspects each value.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	token, err := e.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	items, err := e.items(ctx, token)
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	var selected []item
	for _, it := range items {
		if e.cfg.NamePrefix != "" && !strings.HasPrefix(lastSegment(it.Name), e.cfg.NamePrefix) {
			continue
		}
		selected = append(selected, it)
		resource := "akeyless://" + e.host + it.Name
		tags := append([]string(nil), it.Tags...)
		sort.Strings(tags)
		out = append(out, cloudsecret.MetadataFound(ProviderName, resource, it.Name, folder(it.Name), resource, map[string]string{
			"secret_name": it.Name, "resource_id": resource, "item_type": it.Type, "item_id": strconv.FormatInt(it.ID, 10),
			"tags": strings.Join(tags, ","), "version": strconv.FormatInt(it.LastVersion, 10),
			"created_at": it.CreationDate, "updated_at": it.ModificationDate, "content_inspected": "false",
		}))
	}
	if !e.cfg.InspectContent {
		return out, nil
	}
	for start := 0; start < len(selected); start += valueBatch {
		end := min(start+valueBatch, len(selected))
		found, err := e.inspect(ctx, token, selected[start:end])
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

func lastSegment(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

func folder(name string) string {
	if i := strings.LastIndexByte(name, '/'); i > 0 {
		return name[:i]
	}
	return "/"
}

// inspect reads a batch of values once, inspects each and wipes them.
func (e *Enumerator) inspect(ctx context.Context, token string, batch []item) ([]cloudsecret.Found, error) {
	names := make([]string, 0, len(batch))
	for _, it := range batch {
		names = append(names, it.Name)
	}
	request, err := json.Marshal(map[string]any{"names": names, "token": token})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(request)
	raw, err := e.post(ctx, "/get-secret-value", request)
	if err != nil {
		return nil, fmt.Errorf("akeyless: get-secret-value: %w", statusOnly(err))
	}
	values := map[string]secretjson.StringBytes{}
	err = json.Unmarshal(raw, &values)
	secret.Wipe(raw)
	defer func() {
		for _, v := range values {
			secret.Wipe(v)
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("akeyless: parse secret values: %w", err)
	}
	var out []cloudsecret.Found
	for _, it := range batch {
		value := values[it.Name]
		if len(value) == 0 {
			continue
		}
		resource := "akeyless://" + e.host + it.Name
		found, err := cloudsecret.InspectSecret(ProviderName, cloudsecret.Secret{
			Name: it.Name, ResourceID: resource, Location: folder(it.Name), Provenance: resource, Value: value,
			Fields:   []cloudsecret.SecretField{{Name: lastSegment(it.Name), Value: value}},
			Metadata: map[string]string{"secret_name": it.Name, "resource_id": resource, "content_inspected": "true"},
		})
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

// items lists the static secrets under the folder, following next_page.
func (e *Enumerator) items(ctx context.Context, token string) ([]item, error) {
	var out []item
	next := ""
	for page := 0; page < maxPages; page++ {
		body := map[string]any{"token": token, "path": e.cfg.PathPrefix, "type": []string{"static-secret"}}
		if next != "" {
			body["pagination-token"] = next
		}
		request, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		raw, err := e.post(ctx, "/list-items", request)
		secret.Wipe(request)
		if err != nil {
			return nil, fmt.Errorf("akeyless: list-items: %w", statusOnly(err))
		}
		var resp struct {
			Items    []item `json:"items"`
			NextPage string `json:"next_page"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("akeyless: parse list-items: %w", err)
		}
		for _, it := range resp.Items {
			if e.cfg.PathPrefix == "/" || it.Name == e.cfg.PathPrefix || strings.HasPrefix(it.Name, e.cfg.PathPrefix+"/") {
				out = append(out, it)
			}
		}
		if resp.NextPage == "" {
			sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
			return out, nil
		}
		next = resp.NextPage
	}
	return nil, fmt.Errorf("akeyless: more than %d pages of items; narrow path_prefix", maxPages)
}

// authenticate signs in with the API key for a short-lived token.
func (e *Enumerator) authenticate(ctx context.Context) (string, error) {
	key, err := e.cfg.AccessKey.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("akeyless: access key: %w", err)
	}
	request := make([]byte, 0, 96+len(e.cfg.AccessID)+len(key))
	request = append(request, `{"access-type":"access_key","access-id":`...)
	request = append(request, secretjson.QuoteBytes([]byte(e.cfg.AccessID))...)
	request = append(request, `,"access-key":`...)
	request = append(request, secretjson.QuoteBytes([]byte(key))...)
	request = append(request, '}')
	defer secret.Wipe(request)
	raw, err := e.post(ctx, "/auth", request)
	if err != nil {
		return "", fmt.Errorf("akeyless: auth: %w", statusOnly(err))
	}
	defer secret.Wipe(raw)
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Token == "" {
		return "", errors.New("akeyless: auth returned no token")
	}
	return resp.Token, nil
}

// statusOnly keeps a refused request's status but not its body.
func statusOnly(err error) error {
	msg := err.Error()
	if strings.HasPrefix(msg, "cloudcert: status ") {
		if i := strings.Index(msg[len("cloudcert: status "):], ":"); i > 0 {
			return errors.New(msg[:len("cloudcert: status ")+i])
		}
	}
	return err
}

func (e *Enumerator) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, body, e.cfg.Retry)
}
