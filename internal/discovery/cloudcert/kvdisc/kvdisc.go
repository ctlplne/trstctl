// Package kvdisc enumerates certificates from Azure Key Vault through its
// read-only list and get operations (F49). It authenticates with a bearer token
// and never mutates the vault; certificate bytes are parsed through the crypto
// boundary (AN-3).
package kvdisc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
)

const defaultAPIVersion = "7.4"

// Config configures the Key Vault enumerator.
type Config struct {
	VaultURL   string // e.g. https://myvault.vault.azure.net
	APIVersion string
	Token      cloudcert.TokenProvider
	HTTPClient *http.Client
	Retry      cloudcert.RetryPolicy
}

// Enumerator is a read-only Key Vault certificate source.
type Enumerator struct {
	cfg  Config
	host string
}

// New builds a Key Vault enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("kvdisc: vault URL required")
	}
	if cfg.Token == nil {
		return nil, fmt.Errorf("kvdisc: token provider required")
	}
	u, err := url.Parse(cfg.VaultURL)
	if err != nil {
		return nil, fmt.Errorf("kvdisc: bad vault URL: %w", err)
	}
	if cfg.APIVersion == "" {
		cfg.APIVersion = defaultAPIVersion
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg, host: u.Host}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return "azure-keyvault" }

// Enumerate lists every certificate in the vault and fetches each one's bytes.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudcert.Found, error) {
	next := e.cfg.VaultURL + "/certificates?api-version=" + e.cfg.APIVersion
	var ids []string
	for next != "" {
		raw, err := e.get(ctx, next)
		if err != nil {
			return nil, err
		}
		var page struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("kvdisc: parse list: %w", err)
		}
		for _, v := range page.Value {
			ids = append(ids, v.ID)
		}
		next = page.NextLink
	}

	out := make([]cloudcert.Found, 0, len(ids))
	for _, id := range ids {
		raw, err := e.get(ctx, id+"?api-version="+e.cfg.APIVersion)
		if err != nil {
			return nil, err
		}
		var detail struct {
			CER string `json:"cer"`
		}
		if err := json.Unmarshal(raw, &detail); err != nil {
			return nil, fmt.Errorf("kvdisc: parse certificate: %w", err)
		}
		der, err := base64.StdEncoding.DecodeString(detail.CER)
		if err != nil {
			return nil, fmt.Errorf("kvdisc: decode cer for %s: %w", id, err)
		}
		info, err := certinfo.Inspect(der)
		if err != nil {
			return nil, fmt.Errorf("kvdisc: inspect %s: %w", id, err)
		}
		out = append(out, cloudcert.Found{Provider: e.Name(), ResourceID: id, Location: e.host, Cert: info})
	}
	return out, nil
}

func (e *Enumerator) get(ctx context.Context, url string) ([]byte, error) {
	tok, err := e.cfg.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("kvdisc: token: %w", err)
	}
	return cloudcert.GetSigned(ctx, e.cfg.HTTPClient, url, tok, e.cfg.Retry)
}
