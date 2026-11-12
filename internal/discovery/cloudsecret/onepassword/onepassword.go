// SPDX-License-Identifier: BUSL-1.1

// Package onepassword inventories items in a 1Password Connect server's
// vaults (A173, restored in OD-14). Listing vaults and items returns titles, categories, tags
// and timestamps only; an item's field values are read, one item at a time,
// only when content inspection was chosen, and are wiped after inspection.
package onepassword

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
const ProviderName = "1password-connect"

// Config configures one 1Password Connect inventory. BaseURL is the Connect
// server; Vaults narrows it to vaults by ID or name (empty: every vault the
// token can read).
type Config struct {
	BaseURL        string
	Vaults         []string
	Token          cloudcert.TokenProvider
	NamePrefix     string
	InspectContent bool
	HTTPClient     *http.Client
	Retry          cloudcert.RetryPolicy
}

// Enumerator is a read-only 1Password Connect item source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds a 1Password Connect enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.Token == nil {
		return nil, errors.New("1password-connect: token_ref is required")
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		return nil, errors.New("1password-connect: endpoint (the Connect server URL) is required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("1password-connect: bad endpoint %q", cfg.BaseURL)
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

type vault struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type item struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Category  string   `json:"category"`
	Tags      []string `json:"tags"`
	Version   int      `json:"version"`
	UpdatedAt string   `json:"updatedAt"`
}

// Enumerate lists every item in the selected vaults as a metadata finding
// and, with content inspection, inspects each item's fields.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	vaults, err := e.selectedVaults(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	for _, v := range vaults {
		raw, err := e.get(ctx, "/v1/vaults/"+url.PathEscape(v.ID)+"/items")
		if err != nil {
			return nil, err
		}
		var items []item
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("1password-connect: parse items of vault %s: %w", v.Name, err)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Title < items[j].Title })
		for _, it := range items {
			if e.cfg.NamePrefix != "" && !strings.HasPrefix(it.Title, e.cfg.NamePrefix) {
				continue
			}
			resource := "1password://" + e.host + "/vaults/" + v.ID + "/items/" + it.ID
			out = append(out, cloudsecret.MetadataFound(ProviderName, resource, it.Title, v.Name, resource, map[string]string{
				"secret_name": it.Title, "resource_id": resource, "vault": v.Name, "vault_id": v.ID, "item_id": it.ID,
				"category": it.Category, "tag_count": strconv.Itoa(len(it.Tags)), "version": strconv.Itoa(it.Version),
				"updated_at": it.UpdatedAt, "content_inspected": "false",
			}))
			if !e.cfg.InspectContent {
				continue
			}
			found, err := e.inspectItem(ctx, v, it, resource)
			if err != nil {
				return nil, err
			}
			out = append(out, found...)
		}
	}
	return out, nil
}

func (e *Enumerator) selectedVaults(ctx context.Context) ([]vault, error) {
	raw, err := e.get(ctx, "/v1/vaults")
	if err != nil {
		return nil, err
	}
	var vaults []vault
	if err := json.Unmarshal(raw, &vaults); err != nil {
		return nil, fmt.Errorf("1password-connect: parse vaults: %w", err)
	}
	sort.Slice(vaults, func(i, j int) bool { return vaults[i].Name < vaults[j].Name })
	if len(e.cfg.Vaults) == 0 {
		return vaults, nil
	}
	var out []vault
	for _, want := range e.cfg.Vaults {
		want = strings.TrimSpace(want)
		found := false
		for _, v := range vaults {
			if v.ID == want || v.Name == want {
				out = append(out, v)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("1password-connect: vault %q is not visible to this token", want)
		}
	}
	return out, nil
}

func (e *Enumerator) inspectItem(ctx context.Context, v vault, it item, resource string) ([]cloudsecret.Found, error) {
	raw, err := e.get(ctx, "/v1/vaults/"+url.PathEscape(v.ID)+"/items/"+url.PathEscape(it.ID))
	if err != nil {
		return nil, err
	}
	var detail struct {
		Fields []struct {
			ID    string                 `json:"id"`
			Label string                 `json:"label"`
			Value secretjson.StringBytes `json:"value"`
		} `json:"fields"`
	}
	err = json.Unmarshal(raw, &detail)
	secret.Wipe(raw)
	defer func() {
		for _, f := range detail.Fields {
			secret.Wipe(f.Value)
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("1password-connect: parse item %s: %w", it.Title, err)
	}
	fields := make([]cloudsecret.SecretField, 0, len(detail.Fields))
	size := 0
	for _, f := range detail.Fields {
		if len(f.Value) == 0 {
			continue
		}
		name := f.Label
		if name == "" {
			name = f.ID
		}
		fields = append(fields, cloudsecret.SecretField{Name: name, Value: f.Value})
		size += len(f.Value) + 1
	}
	joined := make([]byte, 0, size)
	for _, f := range fields {
		if len(joined) > 0 {
			joined = append(joined, '\n')
		}
		joined = append(joined, f.Value...)
	}
	defer secret.Wipe(joined)
	return cloudsecret.InspectSecret(ProviderName, cloudsecret.Secret{
		Name: it.Title, ResourceID: resource, Location: v.Name, Provenance: resource, Value: joined, Fields: fields,
		Metadata: map[string]string{
			"secret_name": it.Title, "resource_id": resource, "vault": v.Name, "vault_id": v.ID, "item_id": it.ID,
			"content_inspected": "true",
		},
	})
}

func (e *Enumerator) get(ctx context.Context, path string) ([]byte, error) {
	tok, err := e.cfg.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("1password-connect: token: %w", err)
	}
	return cloudcert.GetSigned(ctx, e.cfg.HTTPClient, e.cfg.BaseURL+path, tok, e.cfg.Retry)
}
