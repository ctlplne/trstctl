// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

var auth0ClientID = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)

// Auth0Config configures the Auth0 client-secret rotator (A240): each allowed
// role is bound to one application's client ID, and a static rotation asks the
// Management API to rotate that application's client secret. Auth0 invalidates
// the current secret the moment it issues the next, so the rotation is single
// phase: consumers fail until they read the new version. It issues no leases.
type Auth0Config struct {
	// Endpoint is the tenant's domain, https://<tenant>.<region>.auth0.com.
	Endpoint string
	// ClientID and ClientSecret are a machine-to-machine application allowed
	// the Management API's update:client_keys scope.
	ClientID              string
	ClientSecret          []byte
	RoleBindings          map[string]string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// Auth0Backend rotates Auth0 application client secrets.
type Auth0Backend struct {
	api          hostedAPI
	clientID     string
	clientSecret *secret.Buffer
	clients      map[string]string
}

// NewAuth0Backend validates cfg.
func NewAuth0Backend(cfg Auth0Config) (*Auth0Backend, error) {
	api, err := newHostedAPI("auth0", cfg.Endpoint, cfg.AllowInsecureLoopback, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	if !auth0ClientID.MatchString(cfg.ClientID) || len(cfg.ClientSecret) == 0 {
		return nil, errors.New("dynsecret auth0: the management client ID and secret are required")
	}
	b := &Auth0Backend{api: api, clientID: cfg.ClientID, clients: map[string]string{}}
	for role, clientID := range cfg.RoleBindings {
		if !auth0ClientID.MatchString(strings.TrimSpace(clientID)) {
			return nil, fmt.Errorf("dynsecret auth0: role %q is not bound to an application client ID", role)
		}
		b.clients[role] = strings.TrimSpace(clientID)
	}
	if len(b.clients) == 0 {
		return nil, errors.New("dynsecret auth0: every allowed role needs the application client ID it rotates in role_bindings")
	}
	if b.clientSecret, err = secret.NewFrom(cfg.ClientSecret); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend: Auth0 issues no leases.
func (b *Auth0Backend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for a static rotation: the bound
// application's client secret is rotated, and the response's new secret is the
// credential. The reference names the application and the rotation, never
// anything derived from the secret.
func (b *Auth0Backend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, errors.New("dynsecret auth0: an application's client secret is rotated, not leased; use a static rotation")
	}
	clientID, ok := b.clients[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret auth0: role %q has no application", req.Role)
	}
	token, err := b.managementToken(ctx)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(token)
	status, response, err := b.api.call(ctx, http.MethodPost, "/api/v2/clients/"+url.PathEscape(clientID)+"/rotate-secret", nil, bearerValue(token))
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(response)
	if status != http.StatusOK {
		return "", nil, fmt.Errorf("dynsecret auth0: rotate the client secret: HTTP %d", status)
	}
	var rotated struct {
		ClientID     string           `json:"client_id"`
		ClientSecret secret.JSONBytes `json:"client_secret"`
	}
	if err := json.Unmarshal(response, &rotated); err != nil || rotated.ClientID != clientID || len(rotated.ClientSecret) == 0 {
		return "", nil, errors.New("dynsecret auth0: the rotation response carries no client secret for the application")
	}
	defer secret.Wipe(rotated.ClientSecret)
	credential, err := json.Marshal(struct { // #nosec G117 -- the rotated client secret is this provider's output: the outbox seals it and only the secret's readers open it (CWE-200)
		ClientID     string           `json:"client_id"`
		ClientSecret secret.JSONBytes `json:"client_secret"`
		Domain       string           `json:"domain"`
	}{ClientID: clientID, ClientSecret: rotated.ClientSecret, Domain: b.api.endpoint})
	if err != nil {
		return "", nil, err
	}
	ref := clientID
	if req.LeaseID != "" {
		ref += "/" + req.LeaseID
	}
	return ref, credential, nil
}

// Revoke implements Backend. A single-phase rotation invalidated the previous
// secret when it issued the next, so retiring it has nothing left to do; only
// references to a bound application are accepted.
func (b *Auth0Backend) Revoke(_ context.Context, ref string) error {
	clientID, _, _ := strings.Cut(ref, "/")
	for _, bound := range b.clients {
		if bound == clientID {
			return nil
		}
	}
	return fmt.Errorf("dynsecret auth0: refusing %q, which names no application this provider rotates", ref)
}

// VerifyCredential proves a rotated secret authenticates its application at
// the token endpoint: a token, or a refusal that only an authenticated client
// gets (the application is not authorized for the Management API), passes;
// invalid_client fails.
func (b *Auth0Backend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		ClientID     string           `json:"client_id"`
		ClientSecret secret.JSONBytes `json:"client_secret"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.ClientID == "" || len(parsed.ClientSecret) == 0 {
		return errors.New("dynsecret auth0: the credential carries no client ID and secret")
	}
	defer secret.Wipe(parsed.ClientSecret)
	status, response, err := b.tokenRequest(ctx, parsed.ClientID, parsed.ClientSecret)
	if err != nil {
		return err
	}
	defer secret.Wipe(response)
	var refusal struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(response, &refusal)
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusForbidden && (refusal.Error == "access_denied" || refusal.Error == "unauthorized_client"):
		return nil
	default:
		return fmt.Errorf("dynsecret auth0: the rotated secret does not authenticate its application: HTTP %d %s", status, refusal.Error)
	}
}

// managementToken obtains a Management API token for the configured client.
func (b *Auth0Backend) managementToken(ctx context.Context) ([]byte, error) {
	var status int
	var response []byte
	err := b.clientSecret.Use(func(clientSecret []byte) error {
		var err error
		status, response, err = b.tokenRequest(ctx, b.clientID, clientSecret)
		return err
	})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(response)
	var token struct {
		AccessToken secret.JSONBytes `json:"access_token"`
	}
	if status != http.StatusOK || json.Unmarshal(response, &token) != nil || len(token.AccessToken) == 0 {
		return nil, fmt.Errorf("dynsecret auth0: management token: HTTP %d", status)
	}
	return token.AccessToken, nil
}

// tokenRequest runs the client-credentials grant for the Management API's
// audience.
func (b *Auth0Backend) tokenRequest(ctx context.Context, clientID string, clientSecret []byte) (int, []byte, error) {
	body, err := json.Marshal(struct { // #nosec G117 -- client credentials go to the tenant's token endpoint over the guarded client and are not kept (CWE-200)
		GrantType    string           `json:"grant_type"`
		ClientID     string           `json:"client_id"`
		ClientSecret secret.JSONBytes `json:"client_secret"`
		Audience     string           `json:"audience"`
	}{GrantType: "client_credentials", ClientID: clientID, ClientSecret: clientSecret, Audience: b.api.endpoint + "/api/v2/"})
	if err != nil {
		return 0, nil, err
	}
	defer secret.Wipe(body)
	return b.api.call(ctx, http.MethodPost, "/oauth/token", body, nil)
}

// Close wipes the management client secret.
func (b *Auth0Backend) Close() { b.clientSecret.Destroy() }
