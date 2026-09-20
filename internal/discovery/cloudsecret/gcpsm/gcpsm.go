// SPDX-License-Identifier: BUSL-1.1

// Package gcpsm enumerates certificate material stored in GCP Secret Manager.
// It uses read-only list/access GET calls and returns metadata-only cloudsecret
// findings; secret payload bytes are wiped after certificate inspection.
package gcpsm

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

const defaultEndpoint = "https://secretmanager.googleapis.com"

// Config configures GCP Secret Manager discovery.
type Config struct {
	Project    string
	Endpoint   string
	Token      cloudcert.TokenProvider
	LabelKey   string
	LabelValue string
	NamePrefix string
	// InspectContent is the explicit opt-in to versions/latest:access.
	InspectContent bool
	HTTPClient     *http.Client
	Retry          cloudcert.RetryPolicy
}

// Enumerator is a read-only GCP Secret Manager certificate-secret source.
type Enumerator struct {
	cfg Config
}

// New builds a GCP Secret Manager enumerator.
func New(cfg Config) (*Enumerator, error) {
	if cfg.Project == "" {
		return nil, fmt.Errorf("gcpsm: project required")
	}
	if cfg.Token == nil {
		return nil, fmt.Errorf("gcpsm: token provider required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = netsec.SafeClient(30 * time.Second)
	}
	if cfg.Retry.Max == 0 && cfg.Retry.Base == 0 {
		cfg.Retry = cloudcert.DefaultRetry()
	}
	return &Enumerator{cfg: cfg}, nil
}

// Name identifies the provider.
func (e *Enumerator) Name() string { return "gcp-secret-manager" }

// Enumerate always returns metadata for matching resources and accesses a value
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
		name := shortName(s.Name)
		provenance := "gcp-sm://" + e.cfg.Project + "/" + name
		out = append(out, cloudsecret.MetadataFound(e.Name(), s.Name, name, e.cfg.Project, provenance, map[string]string{
			"secret_name": name, "resource_id": s.Name, "project": e.cfg.Project,
			"created_at": s.CreatedAt, "expires_at": s.ExpiresAt,
			"label_count": strconv.Itoa(len(s.Labels)), "content_inspected": "false",
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

type secretEntry struct {
	Name      string
	Labels    map[string]string
	CreatedAt string
	ExpiresAt string
}

func (e *Enumerator) matches(s secretEntry) bool {
	short := shortName(s.Name)
	if e.cfg.NamePrefix != "" && !strings.HasPrefix(short, e.cfg.NamePrefix) {
		return false
	}
	if e.cfg.LabelKey != "" && s.Labels[e.cfg.LabelKey] != e.cfg.LabelValue {
		return false
	}
	return true
}

func (e *Enumerator) listSecrets(ctx context.Context) ([]secretEntry, error) {
	base := e.cfg.Endpoint + "/v1/projects/" + url.PathEscape(e.cfg.Project) + "/secrets"
	pageToken := ""
	var out []secretEntry
	for {
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		if e.cfg.LabelKey != "" && e.cfg.LabelValue != "" {
			q.Set("filter", "labels."+e.cfg.LabelKey+"="+e.cfg.LabelValue)
		}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		u.RawQuery = q.Encode()
		raw, err := e.get(ctx, u.String())
		if err != nil {
			return nil, err
		}
		var resp struct {
			Secrets []struct {
				Name       string            `json:"name"`
				Labels     map[string]string `json:"labels"`
				CreateTime string            `json:"createTime"`
				ExpireTime string            `json:"expireTime"`
			} `json:"secrets"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("gcpsm: parse list: %w", err)
		}
		for _, s := range resp.Secrets {
			out = append(out, secretEntry{Name: s.Name, Labels: s.Labels, CreatedAt: s.CreateTime, ExpiresAt: s.ExpireTime})
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return out, nil
}

func (e *Enumerator) inspectSecret(ctx context.Context, s secretEntry) ([]cloudsecret.Found, error) {
	value, err := e.accessSecret(ctx, s.Name)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(value)
	name := shortName(s.Name)
	return cloudsecret.InspectSecret(e.Name(), cloudsecret.Secret{
		Name:       name,
		ResourceID: s.Name,
		Location:   e.cfg.Project,
		Provenance: "gcp-sm://" + e.cfg.Project + "/" + name,
		Value:      value,
		Metadata: map[string]string{
			"secret_name":       name,
			"resource_id":       s.Name,
			"project":           e.cfg.Project,
			"content_inspected": "true",
		},
	})
}

func (e *Enumerator) accessSecret(ctx context.Context, resource string) ([]byte, error) {
	raw, err := e.get(ctx, e.cfg.Endpoint+"/v1/"+strings.TrimPrefix(resource, "/")+"/versions/latest:access")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Payload struct {
			Data secretjson.StringBytes `json:"data"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("gcpsm: parse access: %w", err)
	}
	defer secret.Wipe(resp.Payload.Data)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(resp.Payload.Data)))
	n, err := base64.StdEncoding.Decode(decoded, resp.Payload.Data)
	if err != nil {
		secret.Wipe(decoded)
		return nil, fmt.Errorf("gcpsm: decode payload: %w", err)
	}
	return decoded[:n], nil
}

func (e *Enumerator) get(ctx context.Context, u string) ([]byte, error) {
	tok, err := e.cfg.Token.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcpsm: token: %w", err)
	}
	return cloudcert.GetSigned(ctx, e.cfg.HTTPClient, u, tok, e.cfg.Retry)
}

func shortName(resource string) string {
	parts := strings.Split(strings.Trim(resource, "/"), "/")
	if len(parts) == 0 {
		return resource
	}
	return parts[len(parts)-1]
}
