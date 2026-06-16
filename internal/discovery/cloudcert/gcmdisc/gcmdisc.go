// Package gcmdisc enumerates certificates from GCP Certificate Manager through
// its read-only certificates.list operation (F49). It authenticates with a
// bearer token and never mutates the project; certificate PEM is parsed through
// the crypto boundary (AN-3).
package gcmdisc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
)

const defaultEndpoint = "https://certificatemanager.googleapis.com"

// Config configures the GCP Certificate Manager enumerator.
type Config struct {
	Project    string
	Location   string // e.g. global, us-central1
	Endpoint   string // defaults to the public API
	Token      cloudcert.TokenProvider
	HTTPClient *http.Client
	Retry      cloudcert.RetryPolicy
}

// Enumerator is a read-only Certificate Manager source.
type Enumerator struct {
	cfg Config
}

// New builds a Certificate Manager enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.Project == "" || cfg.Location == "" {
		return nil, fmt.Errorf("gcmdisc: project and location required")
	}
	if cfg.Token == nil {
		return nil, fmt.Errorf("gcmdisc: token provider required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return "gcp-certmanager" }

// Enumerate lists every certificate in the project/location, parsing each
// resource's PEM.
func (e *Enumerator) Enumerate(ctx context.Context) ([]cloudcert.Found, error) {
	base := fmt.Sprintf("%s/v1/projects/%s/locations/%s/certificates", e.cfg.Endpoint, e.cfg.Project, e.cfg.Location)
	pageToken := ""
	var out []cloudcert.Found
	for {
		u := base
		if pageToken != "" {
			u += "?pageToken=" + url.QueryEscape(pageToken)
		}
		tok, err := e.cfg.Token.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("gcmdisc: token: %w", err)
		}
		raw, err := cloudcert.GetSigned(ctx, e.cfg.HTTPClient, u, tok, e.cfg.Retry)
		if err != nil {
			return nil, err
		}
		var page struct {
			Certificates []struct {
				Name           string `json:"name"`
				PemCertificate string `json:"pemCertificate"`
			} `json:"certificates"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("gcmdisc: parse list: %w", err)
		}
		for _, c := range page.Certificates {
			if c.PemCertificate == "" {
				continue
			}
			info, err := certinfo.Inspect([]byte(c.PemCertificate))
			if err != nil {
				return nil, fmt.Errorf("gcmdisc: inspect %s: %w", c.Name, err)
			}
			out = append(out, cloudcert.Found{Provider: e.Name(), ResourceID: c.Name, Location: e.cfg.Location, Cert: info})
		}
		if page.NextPageToken == "" {
			break
		}
		pageToken = page.NextPageToken
	}
	return out, nil
}
