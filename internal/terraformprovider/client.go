package terraformprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

type Client struct {
	endpoint string
	token    string
	tenant   string
	http     *http.Client
}

type ClientConfig struct {
	Endpoint   string
	Token      string
	Tenant     string
	HTTPClient *http.Client
}

type Error struct {
	StatusCode int
	Detail     string
}

func (e *Error) Error() string {
	return fmt.Sprintf("trstctl API returned %d: %s", e.StatusCode, e.Detail)
}

type Profile struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Version   int64           `json:"version"`
	Active    bool            `json:"active"`
	CreatedBy string          `json:"created_by"`
	Spec      json.RawMessage `json:"spec"`
}

type SecretMeta struct {
	Name      string    `json:"name"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SecretValue struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Version int64  `json:"version"`
}

type PKISecret struct {
	Serial      string `json:"serial"`
	CommonName  string `json:"common_name"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

func NewClient(cfg ClientConfig) (*Client, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}
	if _, err := url.ParseRequestURI(endpoint); err != nil {
		return nil, fmt.Errorf("endpoint must be an absolute URL: %w", err)
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		endpoint: endpoint,
		token:    strings.TrimSpace(cfg.Token),
		tenant:   strings.TrimSpace(cfg.Tenant),
		http:     httpClient,
	}, nil
}

func (c *Client) CreateProfile(ctx context.Context, name string, spec json.RawMessage, idempotencyKey string) (Profile, error) {
	var out Profile
	err := c.do(ctx, routeCreateProfileMethod, routeCreateProfilePath, map[string]any{
		"name": name,
		"spec": spec,
	}, idempotencyKey, &out)
	return out, err
}

func (c *Client) GetProfileVersion(ctx context.Context, name string, version int64) (Profile, error) {
	var out Profile
	err := c.do(ctx, routeGetProfileVersionMethod, profileVersionPath(name, version), nil, "", &out)
	return out, err
}

func (c *Client) IssuePKISecret(ctx context.Context, commonName string, ttlSeconds int64, idempotencyKey string) (PKISecret, error) {
	var out PKISecret
	err := c.do(ctx, routeIssuePKISecretMethod, routeIssuePKISecretPath, map[string]any{
		"common_name": commonName,
		"ttl_seconds": ttlSeconds,
	}, idempotencyKey, &out)
	return out, err
}

func (c *Client) CreateSecret(ctx context.Context, name, value, idempotencyKey string) (SecretMeta, error) {
	var out SecretMeta
	err := c.do(ctx, routeCreateSecretMethod, routeCreateSecretPath, map[string]any{
		"name":  name,
		"value": value,
	}, idempotencyKey, &out)
	return out, err
}

func (c *Client) GetSecret(ctx context.Context, name string) (SecretValue, error) {
	var out SecretValue
	err := c.do(ctx, routeGetSecretMethod, secretPath(routeGetSecretPath, name), nil, "", &out)
	return out, err
}

func (c *Client) RotateSecret(ctx context.Context, name, value, idempotencyKey string) (SecretMeta, error) {
	var out SecretMeta
	err := c.do(ctx, routeRotateSecretMethod, secretPath(routeRotateSecretPath, name), map[string]any{
		"value": value,
	}, idempotencyKey, &out)
	return out, err
}

func (c *Client) DeleteSecret(ctx context.Context, name, idempotencyKey string) error {
	return c.do(ctx, routeDeleteSecretMethod, secretPath(routeDeleteSecretPath, name), nil, idempotencyKey, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body any, idempotencyKey string, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.tenant != "" {
		req.Header.Set("X-Tenant-ID", c.tenant)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{StatusCode: resp.StatusCode, Detail: problemDetail(raw)}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode trstctl response: %w", err)
	}
	return nil
}

func profileVersionPath(name string, version int64) string {
	p := strings.Replace(routeGetProfileVersionPath, "{name}", url.PathEscape(name), 1)
	return strings.Replace(p, "{version}", strconv.FormatInt(version, 10), 1)
}

func secretPath(template, name string) string {
	return strings.Replace(template, "{name}", escapePathSegments(name), 1)
}

func escapePathSegments(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

func problemDetail(raw []byte) string {
	var p struct {
		Detail string `json:"detail"`
		Title  string `json:"title"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(raw, &p); err == nil {
		switch {
		case p.Detail != "":
			return p.Detail
		case p.Title != "":
			return p.Title
		case p.Error != "":
			return p.Error
		}
	}
	return strings.TrimSpace(string(raw))
}

func stableIdempotencyKey(parts ...string) string {
	return "tf-" + crypto.SHA256Hex([]byte(strings.Join(parts, "\x00")))[:32]
}
