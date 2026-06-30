// Package vaultkv enumerates certificate material stored in HashiCorp Vault KV v2.
// It uses read-only LIST and GET requests, keeps returned secret payloads in
// byte-backed JSON fields, wipes them after inspection, and emits only
// cloudsecret metadata findings.
package vaultkv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secretjson"
)

// Config configures HashiCorp Vault KV v2 discovery.
type Config struct {
	VaultURL   string
	Mount      string
	PathPrefix string
	Token      cloudcert.TokenProvider
	TagKey     string
	TagValue   string
	NamePrefix string
	HTTPClient *http.Client
	Retry      cloudcert.RetryPolicy
}

// Enumerator is a read-only Vault KV v2 certificate-secret source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds a Vault KV v2 enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("vaultkv: vault URL required")
	}
	if cfg.Token == nil {
		return nil, fmt.Errorf("vaultkv: token provider required")
	}
	u, err := url.Parse(cfg.VaultURL)
	if err != nil {
		return nil, fmt.Errorf("vaultkv: bad vault URL: %w", err)
	}
	if cfg.Mount == "" {
		cfg.Mount = "secret"
	}
	cfg.VaultURL = strings.TrimRight(cfg.VaultURL, "/")
	cfg.Mount = cleanVaultPath(cfg.Mount)
	cfg.PathPrefix = cleanVaultPath(cfg.PathPrefix)
	cfg.NamePrefix = cleanVaultPath(cfg.NamePrefix)
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.SafeClient(30 * time.Second)
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	if cfg.TagKey == "" && cfg.TagValue == "" {
		cfg.TagKey, cfg.TagValue = "type", "certificate"
	}
	return &Enumerator{cfg: cfg, host: u.Host}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return "hashicorp-vault" }

// Enumerate recursively lists KV v2 metadata paths and returns only certificate
// material from matching secrets.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	paths, err := e.listRecursive(ctx, e.cfg.PathPrefix)
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	for _, path := range paths {
		if e.cfg.NamePrefix != "" && !strings.HasPrefix(path, e.cfg.NamePrefix) {
			continue
		}
		found, err := e.inspectSecret(ctx, path)
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

func (e *Enumerator) listRecursive(ctx context.Context, prefix string) ([]string, error) {
	keys, err := e.listKeys(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, key := range keys {
		if strings.HasSuffix(key, "/") {
			childPrefix := joinVaultPath(prefix, strings.TrimSuffix(key, "/"))
			child, err := e.listRecursive(ctx, childPrefix)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
			continue
		}
		out = append(out, joinVaultPath(prefix, key))
	}
	return out, nil
}

func (e *Enumerator) listKeys(ctx context.Context, prefix string) ([]string, error) {
	raw, err := e.do(ctx, "LIST", e.endpoint("metadata", prefix))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("vaultkv: parse list: %w", err)
	}
	return resp.Data.Keys, nil
}

func (e *Enumerator) inspectSecret(ctx context.Context, path string) ([]cloudsecret.Found, error) {
	value, customMeta, err := e.readSecret(ctx, path)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(value)
	if e.cfg.TagKey != "" && customMeta[e.cfg.TagKey] != e.cfg.TagValue {
		return nil, nil
	}
	resource := "vault://" + e.host + "/" + joinVaultPath(e.cfg.Mount, path)
	found, err := cloudsecret.InspectSecret(e.Name(), cloudsecret.Secret{
		Name:       path,
		ResourceID: resource,
		Location:   e.host,
		Provenance: resource,
		Value:      value,
		Metadata: map[string]string{
			"secret_name": path,
			"resource_id": resource,
			"vault":       e.host,
			"mount":       e.cfg.Mount,
		},
	})
	return found, err
}

func (e *Enumerator) readSecret(ctx context.Context, path string) ([]byte, map[string]string, error) {
	raw, err := e.do(ctx, http.MethodGet, e.endpoint("data", path))
	if err != nil {
		return nil, nil, err
	}
	var resp struct {
		Data struct {
			Data     map[string]secretjson.StringBytes `json:"data"`
			Metadata struct {
				CustomMetadata map[string]string `json:"custom_metadata"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, nil, fmt.Errorf("vaultkv: parse read: %w", err)
	}
	defer wipeSecretMap(resp.Data.Data)
	return concatenateSecretFields(resp.Data.Data), resp.Data.Metadata.CustomMetadata, nil
}

func (e *Enumerator) do(ctx context.Context, method, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	tok, err := e.cfg.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("vaultkv: token: %w", err)
	}
	if tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	return cloudcert.Fetch(ctx, e.cfg.HTTPClient, req, nil, e.cfg.Retry)
}

func (e *Enumerator) endpoint(kind, path string) string {
	parts := []string{"v1", e.cfg.Mount, kind}
	if path != "" {
		parts = append(parts, strings.Split(cleanVaultPath(path), "/")...)
	}
	escaped := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			escaped = append(escaped, url.PathEscape(part))
		}
	}
	return e.cfg.VaultURL + "/" + strings.Join(escaped, "/")
}

func concatenateSecretFields(fields map[string]secretjson.StringBytes) []byte {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	for _, key := range keys {
		value := fields[key]
		if len(value) == 0 {
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(value)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func wipeSecretMap(fields map[string]secretjson.StringBytes) {
	for key, value := range fields {
		secret.Wipe(value)
		delete(fields, key)
	}
}

func cleanVaultPath(path string) string {
	return strings.Trim(strings.TrimSpace(path), "/")
}

func joinVaultPath(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		if p := cleanVaultPath(part); p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return strings.Join(cleaned, "/")
}
