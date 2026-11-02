// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

const tailscaleRefPrefix = "tailscale-key:"

var (
	tailscaleTag   = regexp.MustCompile(`^tag:[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	tailscaleKeyID = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
	tailscaleNet   = regexp.MustCompile(`^(-|[A-Za-z0-9.@_-]{1,253})$`)
)

// ParseTailscaleTags reads a role binding: the comma-separated ACL tags the
// role's auth keys give the devices they register, for example "tag:ci".
func ParseTailscaleTags(binding string) ([]string, error) {
	var tags []string
	for _, tag := range strings.Split(binding, ",") {
		tag = strings.TrimSpace(tag)
		if !tailscaleTag.MatchString(tag) {
			return nil, fmt.Errorf("%q is not a Tailscale ACL tag (tag:name)", tag)
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

// TailscaleConfig configures the Tailscale provider (A239): each lease is an
// auth key for one device registration: single-use, ephemeral, preauthorized,
// carrying the ACL tags its role is bound to and expiring with the provider's
// maximum lifetime; revocation deletes the key. Devices it already registered
// stay in the tailnet until removed (an ephemeral device when it goes offline).
type TailscaleConfig struct {
	// Endpoint is the API's base URL, https://api.tailscale.com by default.
	Endpoint string
	// Tailnet is the tailnet's name, or "-" for the API token's own tailnet.
	Tailnet               string
	APIToken              []byte
	RoleBindings          map[string]string
	MaxLifetime           time.Duration
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// TailscaleBackend issues Tailscale auth keys.
type TailscaleBackend struct {
	endpoint    string
	tailnet     string
	apiToken    *secret.Buffer
	tags        map[string][]string
	maxLifetime time.Duration
	client      *http.Client
}

// NewTailscaleBackend validates cfg.
func NewTailscaleBackend(cfg TailscaleConfig) (*TailscaleBackend, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.tailscale.com"
	}
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret tailscale: endpoint: %w", err)
	}
	tailnet := cfg.Tailnet
	if tailnet == "" {
		tailnet = "-"
	}
	if !tailscaleNet.MatchString(tailnet) {
		return nil, fmt.Errorf("dynsecret tailscale: tailnet %q is not a tailnet name", tailnet)
	}
	if len(cfg.APIToken) == 0 || cfg.HTTPClient == nil || cfg.MaxLifetime < time.Second {
		return nil, errors.New("dynsecret tailscale: the API token, an HTTP client and the maximum lifetime are required")
	}
	b := &TailscaleBackend{endpoint: strings.TrimRight(endpoint, "/"), tailnet: tailnet, tags: map[string][]string{},
		maxLifetime: cfg.MaxLifetime, client: cfg.HTTPClient}
	for role, binding := range cfg.RoleBindings {
		tags, err := ParseTailscaleTags(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret tailscale: role %q: %w", role, err)
		}
		b.tags[role] = tags
	}
	var err error
	if b.apiToken, err = secret.NewFrom(cfg.APIToken); err != nil {
		return nil, err
	}
	return b, nil
}

// TailscaleKeyDescription is the description a lease's auth key carries in the
// admin console (Tailscale limits descriptions to 50 characters).
func TailscaleKeyDescription(leaseID string) string {
	return "trstctl " + crypto.SHA256Hex([]byte(leaseID))[:24]
}

// Create implements Backend.
func (b *TailscaleBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend: one key-creation call. The API
// has no idempotency key, so the server runs it at most once per lease.
func (b *TailscaleBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret tailscale: static credentials are not served")
	}
	tags, ok := b.tags[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret tailscale: role %q has no tags", req.Role)
	}
	request, err := json.Marshal(map[string]any{
		"capabilities": map[string]any{"devices": map[string]any{"create": map[string]any{
			"reusable": false, "ephemeral": true, "preauthorized": true, "tags": tags,
		}}},
		"expirySeconds": int64(b.maxLifetime / time.Second),
		"description":   TailscaleKeyDescription(req.LeaseID),
	})
	if err != nil {
		return "", nil, err
	}
	status, body, err := b.call(ctx, http.MethodPost, "/api/v2/tailnet/"+url.PathEscape(b.tailnet)+"/keys", request)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(body)
	if status != http.StatusOK {
		return "", nil, fmt.Errorf("dynsecret tailscale: create auth key: HTTP %d", status)
	}
	var created struct {
		ID      string           `json:"id"`
		Key     secret.JSONBytes `json:"key"`
		Expires time.Time        `json:"expires"`
	}
	if err := json.Unmarshal(body, &created); err != nil || !tailscaleKeyID.MatchString(created.ID) || len(created.Key) == 0 {
		return "", nil, errors.New("dynsecret tailscale: the response carries no auth key")
	}
	defer secret.Wipe(created.Key)
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		ID        string           `json:"id"`
		Key       secret.JSONBytes `json:"key"`
		ExpiresAt time.Time        `json:"expires_at"`
		Tags      []string         `json:"tags"`
	}{ID: created.ID, Key: created.Key, ExpiresAt: created.Expires.UTC(), Tags: tags})
	if err != nil {
		return "", nil, err
	}
	return tailscaleRefPrefix + created.ID, credential, nil
}

// Revoke implements Backend: the key is deleted, so Tailscale refuses it for any
// further registration. A key already gone counts as deleted.
func (b *TailscaleBackend) Revoke(ctx context.Context, ref string) error {
	id, ok := strings.CutPrefix(ref, tailscaleRefPrefix)
	if !ok || !tailscaleKeyID.MatchString(id) {
		return fmt.Errorf("dynsecret tailscale: %q is not an auth key this provider issued", ref)
	}
	status, body, err := b.call(ctx, http.MethodDelete, "/api/v2/tailnet/"+url.PathEscape(b.tailnet)+"/keys/"+id, nil)
	secret.Wipe(body)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("dynsecret tailscale: delete auth key: HTTP %d", status)
	}
	return nil
}

func (b *TailscaleBackend) call(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := b.apiToken.Use(func(token []byte) error {
		req.Header.Set("Authorization", "Bearer "+string(token))
		return nil
	}); err != nil {
		return 0, nil, err
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret tailscale: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret tailscale: read the response: %w", err)
	}
	return resp.StatusCode, out, nil
}

// Close wipes the API token.
func (b *TailscaleBackend) Close() { b.apiToken.Destroy() }
