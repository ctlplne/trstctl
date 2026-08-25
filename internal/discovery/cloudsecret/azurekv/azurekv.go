// SPDX-License-Identifier: MPL-2.0

// Package azurekv enumerates certificate material stored in Azure Key Vault
// secrets. It uses read-only list/get secret calls, keeps values in []byte-backed
// JSON fields, wipes them after inspection, and emits metadata-only findings.
package azurekv

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

const defaultAPIVersion = "7.4"

// Config configures Azure Key Vault secret discovery.
type Config struct {
	VaultURL   string
	APIVersion string
	Token      cloudcert.TokenProvider
	TagKey     string
	TagValue   string
	NamePrefix string
	// InspectContent is the explicit opt-in to the value-returning secret GET.
	InspectContent bool
	HTTPClient     *http.Client
	Retry          cloudcert.RetryPolicy
}

// Enumerator is a read-only Azure Key Vault certificate-secret source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds an Azure Key Vault secret enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("azurekv: vault URL required")
	}
	if cfg.Token == nil {
		return nil, fmt.Errorf("azurekv: token provider required")
	}
	u, err := url.Parse(cfg.VaultURL)
	if err != nil {
		return nil, fmt.Errorf("azurekv: bad vault URL: %w", err)
	}
	cfg.VaultURL = strings.TrimRight(cfg.VaultURL, "/")
	cfg.APIVersion = strings.TrimSpace(cfg.APIVersion)
	if cfg.APIVersion == "" {
		cfg.APIVersion = defaultAPIVersion
	}
	cfg.NamePrefix = strings.TrimSpace(cfg.NamePrefix)
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.SafeClient(30 * time.Second)
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg, host: u.Host}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return "azure-key-vault" }

// Enumerate always returns list-response metadata. A value-returning GET occurs
// only when InspectContent was explicitly enabled.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudsecret.Found, error) {
	secrets, err := e.listSecrets(ctx)
	if err != nil {
		return nil, err
	}
	var out []cloudsecret.Found
	for _, s := range secrets {
		if !e.matches(s) {
			continue
		}
		resourceID := nonempty(s.ID, e.cfg.VaultURL+"/secrets/"+s.Name)
		provenance := "azure-kv://" + e.host + "/" + s.Name
		out = append(out, cloudsecret.MetadataFound(e.Name(), resourceID, s.Name, e.host, provenance, map[string]string{
			"secret_name": s.Name, "resource_id": resourceID, "vault": e.host,
			"enabled": strconv.FormatBool(s.Enabled), "created_at_unix": strconv.FormatInt(s.CreatedAt, 10),
			"updated_at_unix": strconv.FormatInt(s.UpdatedAt, 10), "content_type": s.ContentType,
			"tag_count": strconv.Itoa(len(s.Tags)), "content_inspected": "false",
		}))
		if !e.cfg.InspectContent {
			continue
		}
		found, err := e.inspectSecret(ctx, s)
		if err != nil {
			return nil, err
		}
		out = append(out, found...)
	}
	return out, nil
}

type secretSummary struct {
	ID          string
	Name        string
	Tags        map[string]string
	Enabled     bool
	CreatedAt   int64
	UpdatedAt   int64
	ContentType string
}

type secretValue struct {
	Value       []byte
	ContentType string
}

func (e *Enumerator) matches(s secretSummary) bool {
	if e.cfg.NamePrefix != "" && !strings.HasPrefix(s.Name, e.cfg.NamePrefix) {
		return false
	}
	if e.cfg.TagKey != "" && s.Tags[e.cfg.TagKey] != e.cfg.TagValue {
		return false
	}
	return true
}

func (e *Enumerator) listSecrets(ctx context.Context) ([]secretSummary, error) {
	next := e.withAPIVersion(e.cfg.VaultURL + "/secrets")
	var out []secretSummary
	for next != "" {
		raw, err := e.get(ctx, next)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Value []struct {
				ID          string            `json:"id"`
				Tags        map[string]string `json:"tags"`
				ContentType string            `json:"contentType"`
				Attributes  struct {
					Enabled bool  `json:"enabled"`
					Created int64 `json:"created"`
					Updated int64 `json:"updated"`
				} `json:"attributes"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("azurekv: parse list: %w", err)
		}
		for _, s := range resp.Value {
			out = append(out, secretSummary{
				ID: s.ID, Name: shortName(s.ID), Tags: s.Tags, Enabled: s.Attributes.Enabled,
				CreatedAt: s.Attributes.Created, UpdatedAt: s.Attributes.Updated, ContentType: s.ContentType,
			})
		}
		next = resp.NextLink
	}
	return out, nil
}

func (e *Enumerator) inspectSecret(ctx context.Context, s secretSummary) ([]cloudsecret.Found, error) {
	value, err := e.readSecret(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(value.Value)
	candidate := value.Value
	if strings.EqualFold(value.ContentType, "application/octet-stream;base64") {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value.Value)))
		n, err := base64.StdEncoding.Decode(decoded, value.Value)
		if err != nil {
			secret.Wipe(decoded)
			return nil, fmt.Errorf("azurekv: decode base64 secret value: %w", err)
		}
		defer secret.Wipe(decoded)
		candidate = decoded[:n]
	}
	resourceID := nonempty(s.ID, e.cfg.VaultURL+"/secrets/"+s.Name)
	return cloudsecret.InspectSecret(e.Name(), cloudsecret.Secret{
		Name:       s.Name,
		ResourceID: resourceID,
		Location:   e.host,
		Provenance: "azure-kv://" + e.host + "/" + s.Name,
		Value:      candidate,
		Metadata: map[string]string{
			"secret_name":       s.Name,
			"resource_id":       resourceID,
			"vault":             e.host,
			"content_inspected": "true",
		},
	})
}

func (e *Enumerator) readSecret(ctx context.Context, resource string) (secretValue, error) {
	raw, err := e.get(ctx, e.withAPIVersion(resource))
	if err != nil {
		return secretValue{}, err
	}
	var resp struct {
		Value       secretjson.StringBytes `json:"value"`
		ContentType string                 `json:"contentType"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return secretValue{}, fmt.Errorf("azurekv: parse secret: %w", err)
	}
	defer secret.Wipe(resp.Value)
	return secretValue{
		Value:       append([]byte(nil), resp.Value...),
		ContentType: strings.TrimSpace(resp.ContentType),
	}, nil
}

func (e *Enumerator) get(ctx context.Context, target string) ([]byte, error) {
	tok, err := e.cfg.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("azurekv: token: %w", err)
	}
	return cloudcert.GetSigned(ctx, e.cfg.HTTPClient, target, tok, e.cfg.Retry)
}

func (e *Enumerator) withAPIVersion(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	if q.Get("api-version") == "" {
		q.Set("api-version", e.cfg.APIVersion)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func shortName(resource string) string {
	parts := strings.Split(strings.Trim(resource, "/"), "/")
	if len(parts) == 0 {
		return resource
	}
	return parts[len(parts)-1]
}

func nonempty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
