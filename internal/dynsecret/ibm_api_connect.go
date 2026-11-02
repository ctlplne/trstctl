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

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

var apiConnectName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)

// ParseAPIConnectApp reads a role binding: the consumer app whose credentials
// a lease is, "<org>/<catalog>/<consumer-org>/<app>". The app's subscriptions
// (plans and products) are the credential's authority.
func ParseAPIConnectApp(binding string) (string, error) {
	parts := strings.Split(strings.TrimSpace(binding), "/")
	if len(parts) != 4 {
		return "", errors.New(`expected "<org>/<catalog>/<consumer-org>/<app>"`)
	}
	for _, part := range parts {
		if !apiConnectName.MatchString(part) {
			return "", fmt.Errorf("%q is not an API Connect name", part)
		}
	}
	return strings.Join(parts, "/"), nil
}

// APIConnectConfig configures the IBM API Connect provider (A239): each lease
// is a credential (client ID and secret) of the consumer app its role is bound
// to, created through the platform REST API; revocation deletes the
// credential, after which the gateway refuses its client ID.
type APIConnectConfig struct {
	// Endpoint is the platform API, https://<platform-api-host>.
	Endpoint string
	// ClientID, ClientSecret and APIKey authenticate the administrator (the
	// api_key grant).
	ClientID              string
	ClientSecret          []byte
	APIKey                []byte
	RoleBindings          map[string]string
	UsernamePrefix        string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// APIConnectBackend issues API Connect app credentials.
type APIConnectBackend struct {
	endpoint     string
	clientID     string
	clientSecret *secret.Buffer
	apiKey       *secret.Buffer
	apps         map[string]string
	prefix       string
	client       *http.Client
}

// NewAPIConnectBackend validates cfg.
func NewAPIConnectBackend(cfg APIConnectConfig) (*APIConnectBackend, error) {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(cfg.Endpoint, cfg.AllowInsecureLoopback); err != nil {
		return nil, fmt.Errorf("dynsecret ibm-api-connect: endpoint: %w", err)
	}
	if strings.TrimSpace(cfg.ClientID) == "" || len(cfg.ClientSecret) == 0 || len(cfg.APIKey) == 0 || cfg.HTTPClient == nil {
		return nil, errors.New("dynsecret ibm-api-connect: the platform client ID and secret, an API key and an HTTP client are required")
	}
	b := &APIConnectBackend{endpoint: strings.TrimRight(cfg.Endpoint, "/"), clientID: cfg.ClientID, apps: map[string]string{},
		prefix: cfg.UsernamePrefix, client: cfg.HTTPClient}
	for role, binding := range cfg.RoleBindings {
		app, err := ParseAPIConnectApp(binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret ibm-api-connect: role %q: %w", role, err)
		}
		b.apps[role] = app
	}
	if len(b.apps) == 0 {
		return nil, errors.New("dynsecret ibm-api-connect: every allowed role needs a consumer app in role_bindings")
	}
	var err error
	if b.clientSecret, err = secret.NewFrom(cfg.ClientSecret); err != nil {
		return nil, err
	}
	if b.apiKey, err = secret.NewFrom(cfg.APIKey); err != nil {
		b.clientSecret.Destroy()
		return nil, err
	}
	return b, nil
}

// Create implements Backend.
func (b *APIConnectBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The credential's name derives
// from the lease. API Connect generates the secret and never shows it again,
// so a retry that finds the name taken (409) deletes that credential and
// creates it anew rather than adding a second one.
func (b *APIConnectBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret ibm-api-connect: static credentials are not served")
	}
	app, ok := b.apps[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret ibm-api-connect: role %q has no consumer app", req.Role)
	}
	name, err := scopedNameForRequest(b.prefix, req, 64, "-")
	if err != nil {
		return "", nil, err
	}
	if !apiConnectName.MatchString(name) {
		return "", nil, fmt.Errorf("dynsecret ibm-api-connect: generated credential name %q is not plain", name)
	}
	token, err := b.accessToken(ctx)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(token)
	body, _ := json.Marshal(map[string]string{"name": name, "title": name, "summary": "trstctl dynamic secret"})
	collection := "/api/apps/" + app + "/credentials"
	status, response, err := b.call(ctx, token, http.MethodPost, collection, body)
	if err == nil && status == http.StatusConflict {
		secret.Wipe(response)
		if status, _, err = b.call(ctx, token, http.MethodDelete, collection+"/"+url.PathEscape(name), nil); err == nil && status/100 == 2 {
			status, response, err = b.call(ctx, token, http.MethodPost, collection, body)
		}
	}
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(response)
	if status != http.StatusCreated && status != http.StatusOK {
		return "", nil, fmt.Errorf("dynsecret ibm-api-connect: create credential: HTTP %d", status)
	}
	var created struct {
		ClientID     string           `json:"client_id"`
		ClientSecret secret.JSONBytes `json:"client_secret"`
	}
	if err := json.Unmarshal(response, &created); err != nil || created.ClientID == "" || len(created.ClientSecret) == 0 {
		return "", nil, errors.New("dynsecret ibm-api-connect: the credential response carries no client ID and secret")
	}
	defer secret.Wipe(created.ClientSecret)
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		ClientID     string           `json:"client_id"`
		ClientSecret secret.JSONBytes `json:"client_secret"`
		App          string           `json:"app"`
	}{ClientID: created.ClientID, ClientSecret: created.ClientSecret, App: app})
	if err != nil {
		return "", nil, err
	}
	return app + "/" + name, credential, nil
}

// Revoke implements Backend: the credential is deleted, and the gateway refuses
// its client ID. Only credentials this provider names, on apps its roles are
// bound to, are deleted; one already gone counts as revoked.
func (b *APIConnectBackend) Revoke(ctx context.Context, ref string) error {
	cut := strings.LastIndex(ref, "/")
	if cut < 0 {
		return fmt.Errorf("dynsecret ibm-api-connect: refusing to delete %q, which this provider did not create", ref)
	}
	app, name := ref[:cut], ref[cut+1:]
	bound := false
	for _, configured := range b.apps {
		bound = bound || configured == app
	}
	if !bound || !apiConnectName.MatchString(name) || !issuedPrincipalNameWith(b.prefix, name, '-') {
		return fmt.Errorf("dynsecret ibm-api-connect: refusing to delete %q, which this provider did not create", ref)
	}
	token, err := b.accessToken(ctx)
	if err != nil {
		return err
	}
	defer secret.Wipe(token)
	status, response, err := b.call(ctx, token, http.MethodDelete, "/api/apps/"+app+"/credentials/"+url.PathEscape(name), nil)
	secret.Wipe(response)
	if err != nil {
		return err
	}
	if status/100 != 2 && status != http.StatusNotFound {
		return fmt.Errorf("dynsecret ibm-api-connect: delete credential: HTTP %d", status)
	}
	return nil
}

// accessToken exchanges the API key for a platform access token (the api_key
// grant of POST /api/token).
func (b *APIConnectBackend) accessToken(ctx context.Context) ([]byte, error) {
	var body []byte
	err := b.apiKey.Use(func(apiKey []byte) error {
		return b.clientSecret.Use(func(clientSecret []byte) error {
			var err error
			body, err = json.Marshal(struct { // #nosec G117 -- the platform credentials go to the token endpoint over the guarded client and are not kept (CWE-200)
				APIKey       secret.JSONBytes `json:"api_key"`
				ClientID     string           `json:"client_id"`
				ClientSecret secret.JSONBytes `json:"client_secret"`
				GrantType    string           `json:"grant_type"`
			}{APIKey: apiKey, ClientID: b.clientID, ClientSecret: clientSecret, GrantType: "api_key"})
			return err
		})
	})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(body)
	status, response, err := b.call(ctx, nil, http.MethodPost, "/api/token", body)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(response)
	var token struct {
		AccessToken secret.JSONBytes `json:"access_token"`
	}
	if status != http.StatusOK || json.Unmarshal(response, &token) != nil || len(token.AccessToken) == 0 {
		return nil, fmt.Errorf("dynsecret ibm-api-connect: platform token: HTTP %d", status)
	}
	return token.AccessToken, nil
}

func (b *APIConnectBackend) call(ctx context.Context, token []byte, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != nil {
		req.Header.Set("Authorization", "Bearer "+string(token))
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the endpoint is operator configuration, sent through the SSRF-guarded client (CWE-918)
	if err != nil {
		return 0, nil, fmt.Errorf("dynsecret ibm-api-connect: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	response, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		secret.Wipe(response)
		return 0, nil, fmt.Errorf("dynsecret ibm-api-connect: read the response: %w", err)
	}
	return resp.StatusCode, response, nil
}

// Close wipes the platform credentials.
func (b *APIConnectBackend) Close() {
	b.clientSecret.Destroy()
	b.apiKey.Destroy()
}
