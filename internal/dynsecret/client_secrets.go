// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/hostedkey"
)

// clientSecretID is a vendor's ID for one secret of a client.
var clientSecretID = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)

// clientSecretVendor is one hosted service's API for the secrets of an
// existing client (A240): a rotation adds a secret beside the one consumers
// use, and retirement removes the old one. These secrets carry no name, so
// the bound client is the boundary: only secrets of a bound client are ever
// removed, and every one of them is a version of the credential being
// rotated.
type clientSecretVendor interface {
	// add creates a secret of the client the binding names and returns its
	// ID and the credential document a consumer reads.
	add(ctx context.Context, api hostedAPI, binding string) (id string, credential []byte, err error)
	// present reports whether the client still has the secret.
	present(ctx context.Context, api hostedAPI, binding, id string) (bool, error)
	// remove deletes the secret; one already gone is not an error.
	remove(ctx context.Context, api hostedAPI, binding, id string) error
	// verify proves a credential document authenticates as its client.
	verify(ctx context.Context, api hostedAPI, credential []byte) error
}

// clientSecretVendors are the vendors by provider type.
var clientSecretVendors = map[string]func(admin *secret.Buffer, clientID string) clientSecretVendor{
	"okta": func(admin *secret.Buffer, _ string) clientSecretVendor { return oktaVendor{token: admin} },
	"databricks": func(admin *secret.Buffer, clientID string) clientSecretVendor {
		return &databricksVendor{secret: admin, clientID: clientID}
	},
}

// ClientSecretConfig configures a client secret rotator (A240). It rotates
// only: a role names one client, whose secrets are few (Okta allows two,
// Databricks five), so it issues no leases.
type ClientSecretConfig struct {
	Endpoint string
	// AdminKey authenticates the management calls: an Okta API token, or a
	// Databricks account admin service principal's OAuth secret.
	AdminKey []byte
	// AdminClientID is that service principal's application ID (Databricks).
	AdminClientID         string
	RoleBindings          map[string]string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
}

// ClientSecretBackend rotates one vendor's client secrets.
type ClientSecretBackend struct {
	provider string
	vendor   clientSecretVendor
	api      hostedAPI
	admin    *secret.Buffer
	bindings map[string]string
}

// NewClientSecretBackend validates cfg for provider.
func NewClientSecretBackend(provider string, cfg ClientSecretConfig) (*ClientSecretBackend, error) {
	open, ok := clientSecretVendors[provider]
	if !ok {
		return nil, fmt.Errorf("dynsecret: %q is not a client secret rotator", provider)
	}
	api, err := newHostedAPI(provider, cfg.Endpoint, cfg.AllowInsecureLoopback, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	if len(cfg.AdminKey) == 0 {
		return nil, fmt.Errorf("dynsecret %s: the administrator's credential is required", provider)
	}
	b := &ClientSecretBackend{provider: provider, api: api, bindings: map[string]string{}}
	for role, binding := range cfg.RoleBindings {
		canonical, err := hostedkey.ParseBinding(provider, binding)
		if err != nil {
			return nil, fmt.Errorf("dynsecret %s: role %q: %w", provider, role, err)
		}
		b.bindings[role] = canonical
	}
	if len(b.bindings) == 0 {
		return nil, fmt.Errorf("dynsecret %s: every allowed role needs a binding in role_bindings", provider)
	}
	if b.admin, err = secret.NewFrom(cfg.AdminKey); err != nil {
		return nil, err
	}
	b.vendor = open(b.admin, cfg.AdminClientID)
	return b, nil
}

// Create implements Backend; a client secret rotator issues no leases.
func (b *ClientSecretBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for static rotation only: the
// successor is a new secret of the role's client.
func (b *ClientSecretBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, fmt.Errorf("dynsecret %s: rotates client secrets only; it issues no leases", b.provider)
	}
	binding, ok := b.bindings[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret %s: role %q has no binding", b.provider, req.Role)
	}
	id, credential, err := b.vendor.add(ctx, b.api, binding)
	if err != nil {
		return "", nil, err
	}
	if !clientSecretID.MatchString(id) {
		secret.Wipe(credential)
		return "", nil, fmt.Errorf("dynsecret %s: the vendor returned an unusable secret ID", b.provider)
	}
	return binding + "/" + id, credential, nil
}

// Revoke implements Backend: a secret of a bound client is removed; one
// already gone counts as revoked, and a reference to anything else is
// refused.
func (b *ClientSecretBackend) Revoke(ctx context.Context, ref string) error {
	cut := strings.LastIndex(ref, "/")
	refused := fmt.Errorf("dynsecret %s: refusing %q, which names no secret of a bound client", b.provider, ref)
	if cut <= 0 {
		return refused
	}
	binding, id := ref[:cut], ref[cut+1:]
	if !clientSecretID.MatchString(id) || !b.bound(binding) {
		return refused
	}
	present, err := b.vendor.present(ctx, b.api, binding, id)
	if err != nil || !present {
		return err
	}
	return b.vendor.remove(ctx, b.api, binding, id)
}

func (b *ClientSecretBackend) bound(binding string) bool {
	for _, candidate := range b.bindings {
		if candidate == binding {
			return true
		}
	}
	return false
}

// VerifyCredential proves a secret with the vendor's client authentication.
func (b *ClientSecretBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	return b.vendor.verify(ctx, b.api, credential)
}

// Close wipes the administrator's credential.
func (b *ClientSecretBackend) Close() { b.admin.Destroy() }

// basicFrom authenticates as HTTP Basic with a client ID and a secret the
// caller holds, encoded without a string of the secret.
func basicFrom(clientID string, clientSecret []byte) func(http.Header) error {
	return func(header http.Header) error {
		raw := append(append([]byte(url.QueryEscape(clientID)), ':'), appendQueryEscaped(nil, clientSecret)...)
		defer secret.Wipe(raw)
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
		base64.StdEncoding.Encode(encoded, raw)
		defer secret.Wipe(encoded)
		header.Set("Authorization", "Basic "+string(encoded))
		return nil
	}
}

// clientSecretDocument is the credential a client secret rotator hands out.
func clientSecretDocument(fields map[string]any) ([]byte, error) {
	return json.Marshal(fields) // #nosec G117 -- the new secret is this provider's output: the outbox seals it and only its readers open it (CWE-200)
}

// --- Okta -----------------------------------------------------------------

// oktaVendor rotates an Okta app's client secrets with an API token (SSWS):
// a new secret is ACTIVE at once, the old one keeps working until retirement
// deactivates and deletes it (Okta deletes only inactive secrets, and refuses
// to deactivate the last one). Okta allows two secrets per app, so a
// rotation needs the app to hold only the one consumers use.
type oktaVendor struct {
	token *secret.Buffer
}

func (o oktaVendor) authenticate(header http.Header) error {
	return o.token.Use(func(value []byte) error {
		header.Set("Authorization", "SSWS "+string(value))
		return nil
	})
}

func oktaSecrets(app string) string {
	return "/api/v1/apps/" + url.PathEscape(app) + "/credentials/secrets"
}

func (o oktaVendor) add(ctx context.Context, api hostedAPI, app string) (string, []byte, error) {
	var current struct {
		Credentials struct {
			OAuthClient struct {
				ClientID string `json:"client_id"`
			} `json:"oauthClient"`
		} `json:"credentials"`
	}
	if _, err := hostedJSON(ctx, api, http.MethodGet, "/api/v1/apps/"+url.PathEscape(app), nil, o.authenticate, &current); err != nil {
		return "", nil, fmt.Errorf("dynsecret okta: read the app: %w", err)
	}
	clientID := current.Credentials.OAuthClient.ClientID
	if clientID == "" {
		return "", nil, errors.New("dynsecret okta: the app has no OAuth client")
	}
	var created struct {
		ID           string           `json:"id"`
		ClientSecret secret.JSONBytes `json:"client_secret"`
		Status       string           `json:"status"`
	}
	if _, err := hostedJSON(ctx, api, http.MethodPost, oktaSecrets(app), map[string]any{}, o.authenticate, &created, http.StatusCreated); err != nil {
		return "", nil, fmt.Errorf("dynsecret okta: add a secret (an app holds at most two): %w", err)
	}
	defer secret.Wipe(created.ClientSecret)
	if created.ID == "" || len(created.ClientSecret) == 0 || created.Status != "ACTIVE" {
		return "", nil, errors.New("dynsecret okta: the create response carries no active secret")
	}
	credential, err := clientSecretDocument(map[string]any{"client_id": clientID, "client_secret": created.ClientSecret, "secret_id": created.ID})
	return created.ID, credential, err
}

func (o oktaVendor) present(ctx context.Context, api hostedAPI, app, id string) (bool, error) {
	status, err := hostedJSON(ctx, api, http.MethodGet, oktaSecrets(app)+"/"+url.PathEscape(id), nil, o.authenticate, nil, http.StatusNotFound)
	return err == nil && status == http.StatusOK, err
}

func (o oktaVendor) remove(ctx context.Context, api hostedAPI, app, id string) error {
	path := oktaSecrets(app) + "/" + url.PathEscape(id)
	if _, err := hostedJSON(ctx, api, http.MethodPost, path+"/lifecycle/deactivate", nil, o.authenticate, nil, http.StatusNotFound); err != nil {
		return fmt.Errorf("dynsecret okta: deactivate the old secret: %w", err)
	}
	_, err := hostedJSON(ctx, api, http.MethodDelete, path, nil, o.authenticate, nil, http.StatusNoContent, http.StatusNotFound)
	return err
}

// verify authenticates as the client at the org authorization server's
// introspection endpoint: Okta checks the client before the token, so a live
// secret is answered (active false for the dummy token) and a dead one 401.
func (oktaVendor) verify(ctx context.Context, api hostedAPI, credential []byte) error {
	var parsed struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.ClientID == "" {
		return errors.New("dynsecret okta: the credential names no client")
	}
	clientSecret, err := credentialField("okta", credential, "client_secret")
	if err != nil {
		return err
	}
	defer secret.Wipe(clientSecret)
	status, response, err := api.callForm(ctx, "/oauth2/v1/introspect", []byte("token=trstctl-client-check&token_type_hint=access_token"), basicFrom(parsed.ClientID, clientSecret))
	secret.Wipe(response)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("dynsecret okta: the secret did not authenticate its client (HTTP %d)", status)
	}
	return nil
}

// --- Databricks ---------------------------------------------------------------

// databricksVendor rotates a Databricks service principal's OAuth secrets at
// the account API ("<account-id>:<service-principal-id>"), authenticating as
// an account admin service principal with OAuth client credentials. A
// principal holds at most five secrets.
type databricksVendor struct {
	secret   *secret.Buffer
	clientID string
}

// authenticate gets an account-level OAuth token for the admin principal.
func (d *databricksVendor) authenticate(ctx context.Context, api hostedAPI, account string) (func(http.Header) error, error) {
	var token struct {
		AccessToken secret.JSONBytes `json:"access_token"`
	}
	var status int
	var response []byte
	err := d.secret.Use(func(value []byte) error {
		var err error
		status, response, err = api.callForm(ctx, "/oidc/accounts/"+account+"/v1/token", []byte("grant_type=client_credentials&scope=all-apis"), basicFrom(d.clientID, value))
		return err
	})
	defer secret.Wipe(response)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || json.Unmarshal(response, &token) != nil || len(token.AccessToken) == 0 {
		secret.Wipe(token.AccessToken)
		return nil, fmt.Errorf("dynsecret databricks: the admin service principal got no token (HTTP %d)", status)
	}
	return func(header http.Header) error {
		header.Set("Authorization", "Bearer "+string(token.AccessToken))
		secret.Wipe(token.AccessToken)
		return nil
	}, nil
}

func databricksSecrets(binding string) (account, path string) {
	account, principal, _ := strings.Cut(binding, ":")
	return account, "/api/2.0/accounts/" + account + "/servicePrincipals/" + principal + "/credentials/secrets"
}

func (d *databricksVendor) add(ctx context.Context, api hostedAPI, binding string) (string, []byte, error) {
	account, path := databricksSecrets(binding)
	auth, err := d.authenticate(ctx, api, account)
	if err != nil {
		return "", nil, err
	}
	var principal struct {
		ApplicationID string `json:"applicationId"`
	}
	_, principalID, _ := strings.Cut(binding, ":")
	if _, err := hostedJSON(ctx, api, http.MethodGet, "/api/2.0/accounts/"+account+"/scim/v2/ServicePrincipals/"+principalID, nil, auth, &principal); err != nil {
		return "", nil, fmt.Errorf("dynsecret databricks: read the service principal: %w", err)
	}
	if auth, err = d.authenticate(ctx, api, account); err != nil {
		return "", nil, err
	}
	var created struct {
		ID     string           `json:"id"`
		Secret secret.JSONBytes `json:"secret"`
	}
	if _, err := hostedJSON(ctx, api, http.MethodPost, path, map[string]any{}, auth, &created, http.StatusCreated); err != nil {
		return "", nil, fmt.Errorf("dynsecret databricks: add a secret (a principal holds at most five): %w", err)
	}
	defer secret.Wipe(created.Secret)
	if created.ID == "" || len(created.Secret) == 0 || principal.ApplicationID == "" {
		return "", nil, errors.New("dynsecret databricks: the create response carries no secret")
	}
	credential, err := clientSecretDocument(map[string]any{
		"client_id": principal.ApplicationID, "client_secret": created.Secret, "secret_id": created.ID, "account_id": account,
	})
	return created.ID, credential, err
}

func (d *databricksVendor) present(ctx context.Context, api hostedAPI, binding, id string) (bool, error) {
	account, path := databricksSecrets(binding)
	auth, err := d.authenticate(ctx, api, account)
	if err != nil {
		return false, err
	}
	var listed struct {
		Secrets []struct {
			ID string `json:"id"`
		} `json:"secrets"`
	}
	if _, err := hostedJSON(ctx, api, http.MethodGet, path, nil, auth, &listed); err != nil {
		return false, err
	}
	for _, candidate := range listed.Secrets {
		if candidate.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func (d *databricksVendor) remove(ctx context.Context, api hostedAPI, binding, id string) error {
	account, path := databricksSecrets(binding)
	auth, err := d.authenticate(ctx, api, account)
	if err != nil {
		return err
	}
	_, err = hostedJSON(ctx, api, http.MethodDelete, path+"/"+url.PathEscape(id), nil, auth, nil, http.StatusNotFound)
	return err
}

// verify gets an account-level OAuth token with the new secret itself.
func (d *databricksVendor) verify(ctx context.Context, api hostedAPI, credential []byte) error {
	var parsed struct {
		ClientID  string `json:"client_id"`
		AccountID string `json:"account_id"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.ClientID == "" || !hostedkey.DatabricksAccount(parsed.AccountID) {
		return errors.New("dynsecret databricks: the credential names no client and account")
	}
	clientSecret, err := credentialField("databricks", credential, "client_secret")
	if err != nil {
		return err
	}
	defer secret.Wipe(clientSecret)
	status, response, err := api.callForm(ctx, "/oidc/accounts/"+parsed.AccountID+"/v1/token", []byte("grant_type=client_credentials&scope=all-apis"), basicFrom(parsed.ClientID, clientSecret))
	secret.Wipe(response)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("dynsecret databricks: the secret got no token (HTTP %d)", status)
	}
	return nil
}
