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
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A272: identity provider administrator accounts — the break-glass super
// administrators of Okta, Microsoft Entra ID and Google Workspace. Each
// provider sets the bound account's password through the identity provider's
// own administration API and proves it with one non-interactive sign-in where
// the provider has one:
//
//   - okta-user: an API token (SSWS) sets the user's password with a partial
//     update (POST /api/v1/users/{id} credentials.password); the Authentication
//     API (POST /api/v1/authn) proves it — SUCCESS, or an MFA step, means the
//     password was right, and a pending transaction is cancelled.
//   - entra-user: an application's client-credentials token PATCHes the
//     user's passwordProfile through Microsoft Graph; one resource-owner
//     password sign-in proves it, read by its error code: 50126 is a wrong
//     password, an MFA or conditional-access step after a right password
//     (50076, 50079, 50072, 50074, 50158) is a right one, and a blocked
//     account or a tenant that refuses the flow cannot be proved.
//   - google-workspace-user: a service account with domain-wide delegation,
//     impersonating a super administrator, PATCHes the user's password through
//     the Admin SDK Directory API. Google offers no non-interactive password
//     check, so the change is not proved there.
//
// A wrong password is never retried by a proof: each counts toward the
// account's lockout.

// IdPAdminConfig configures one identity provider.
type IdPAdminConfig struct {
	// Vendor is "okta-user", "entra-user" or "google-workspace-user".
	Vendor string
	// Endpoint is the administration API: the Okta org, Microsoft Graph or
	// the Admin SDK (https://admin.googleapis.com).
	Endpoint string
	// AuthorityHost is Entra's sign-in host (https://login.microsoftonline.com)
	// or Google's token endpoint (https://oauth2.googleapis.com/token).
	AuthorityHost         string
	AllowInsecureLoopback bool
	HTTPClient            *http.Client
	// APIToken is Okta's SSWS token.
	APIToken []byte
	// ClientID, ClientSecret and AzureTenant are Entra's application.
	ClientID     string
	ClientSecret []byte
	AzureTenant  string
	// ServiceAccountEmail and ServiceAccountKeyPEM sign Google's assertion;
	// Subject is the super administrator it impersonates.
	ServiceAccountEmail  string
	ServiceAccountKeyPEM []byte
	Subject              string
	// RoleAccounts binds each role to the account it rotates: an Okta login,
	// an Entra user principal name or a Google primary email.
	RoleAccounts map[string]string
}

var (
	idpAccount  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	entraTenant = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$`)
)

// IdPAdminBackend rotates one identity provider's administrator accounts.
type IdPAdminBackend struct {
	vendor     string
	api        hostedAPI
	authority  hostedAPI
	credential *secret.Buffer // Okta token, Entra client secret, or Google key
	clientID   string
	tenant     string
	saEmail    string
	subject    string
	accounts   map[string]string
	now        func() time.Time
}

// NewIdPAdminBackend validates cfg.
func NewIdPAdminBackend(cfg IdPAdminConfig) (*IdPAdminBackend, error) {
	b := &IdPAdminBackend{vendor: cfg.Vendor, clientID: cfg.ClientID, tenant: cfg.AzureTenant, saEmail: cfg.ServiceAccountEmail,
		subject: cfg.Subject, accounts: map[string]string{}, now: time.Now}
	var err error
	if b.api, err = newHostedAPI(cfg.Vendor, cfg.Endpoint, cfg.AllowInsecureLoopback, cfg.HTTPClient); err != nil {
		return nil, err
	}
	var credential []byte
	switch cfg.Vendor {
	case "okta-user":
		credential = cfg.APIToken
	case "entra-user":
		if !entraTenant.MatchString(cfg.AzureTenant) || cfg.ClientID == "" {
			return nil, errors.New("dynsecret entra-user: the directory (tenant) ID and the application's client ID are required")
		}
		credential = cfg.ClientSecret
		if b.authority, err = newHostedAPI(cfg.Vendor, cfg.AuthorityHost, cfg.AllowInsecureLoopback, cfg.HTTPClient); err != nil {
			return nil, err
		}
	case "google-workspace-user":
		if !idpAccount.MatchString(cfg.ServiceAccountEmail) || !idpAccount.MatchString(cfg.Subject) {
			return nil, errors.New("dynsecret google-workspace-user: the service account and the super administrator it impersonates are required")
		}
		credential = cfg.ServiceAccountKeyPEM
		if b.authority, err = newHostedAPI(cfg.Vendor, cfg.AuthorityHost, cfg.AllowInsecureLoopback, cfg.HTTPClient); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("dynsecret: unknown identity provider %q", cfg.Vendor)
	}
	if len(credential) == 0 {
		return nil, fmt.Errorf("dynsecret %s: the administration credential is required", cfg.Vendor)
	}
	seen := map[string]bool{}
	for role, account := range cfg.RoleAccounts {
		account = strings.TrimSpace(account)
		switch {
		case !idpAccount.MatchString(account):
			return nil, fmt.Errorf("dynsecret %s: role %q names %q, which is not a sign-in name (user@domain)", cfg.Vendor, role, account)
		case strings.EqualFold(account, cfg.Subject):
			return nil, fmt.Errorf("dynsecret %s: role %q names the administrator the provider acts as", cfg.Vendor, role)
		case seen[strings.ToLower(account)]:
			return nil, fmt.Errorf("dynsecret %s: account %q serves two roles", cfg.Vendor, account)
		}
		seen[strings.ToLower(account)] = true
		b.accounts[role] = account
	}
	if len(b.accounts) == 0 {
		return nil, fmt.Errorf("dynsecret %s: every allowed role needs its account in role_bindings", cfg.Vendor)
	}
	if b.credential, err = secret.NewFrom(credential); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend: administrator accounts are rotated, not leased.
func (b *IdPAdminBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for a static rotation.
func (b *IdPAdminBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, fmt.Errorf("dynsecret %s: an administrator account is rotated, not leased; use a static rotation", b.vendor)
	}
	account, ok := b.accounts[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret %s: role %q has no account", b.vendor, req.Role)
	}
	// Identity providers' complexity rules want a symbol as well.
	password, err := randomPolicyPassword(31)
	if err != nil {
		return "", nil, err
	}
	password = append(password, '!')
	defer secret.Wipe(password)
	if err := b.set(ctx, account, password); err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the rotated administrator credential; the rotation seals it before storage (CWE-200)
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Username: account, Password: password})
	if err != nil {
		return "", nil, err
	}
	return account + "/" + req.LeaseID, credential, nil
}

// bearer turns a token into an Authorization header value.
func bearerHeader(token []byte) func(http.Header) error {
	return func(h http.Header) error {
		h.Set("Authorization", "Bearer "+string(token))
		return nil
	}
}

// accessToken gets the administration token (Entra client credentials,
// Google's signed assertion). The caller wipes it.
func (b *IdPAdminBackend) accessToken(ctx context.Context) ([]byte, error) {
	var form []byte
	path := ""
	err := b.credential.Use(func(credential []byte) error {
		switch b.vendor {
		case "entra-user":
			path = "/" + b.tenant + "/oauth2/v2.0/token"
			form = append([]byte("grant_type=client_credentials&client_id="+url.QueryEscape(b.clientID)+"&scope="+
				url.QueryEscape("https://graph.microsoft.com/.default")+"&client_secret="), queryEscapeBytes(credential)...)
		case "google-workspace-user":
			now := b.now().UTC()
			assertion, err := crypto.SignJWTWithPEMKeyBytes(credential, "", map[string]any{"iss": b.saEmail, "sub": b.subject,
				"scope": "https://www.googleapis.com/auth/admin.directory.user", "aud": b.authority.endpoint, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
			if err != nil {
				return err
			}
			form = append([]byte("grant_type="+url.QueryEscape("urn:ietf:params:oauth:grant-type:jwt-bearer")+"&assertion="), assertion...)
			secret.Wipe(assertion)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(form)
	status, raw, err := b.authority.send(ctx, http.MethodPost, path, form, "application/x-www-form-urlencoded", nil)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	var token struct {
		AccessToken secret.JSONBytes `json:"access_token"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &token) != nil || len(token.AccessToken) == 0 {
		secret.Wipe(token.AccessToken)
		return nil, fmt.Errorf("dynsecret %s: the identity provider refused the administration token (HTTP %d)", b.vendor, status)
	}
	return token.AccessToken, nil
}

// set changes account's password through the administration API.
func (b *IdPAdminBackend) set(ctx context.Context, account string, password []byte) error {
	value, err := secret.JSONBytes(password).MarshalJSON()
	if err != nil {
		return err
	}
	defer secret.Wipe(value)
	var method, path string
	var body []byte
	switch b.vendor {
	case "okta-user":
		method, path = http.MethodPost, "/api/v1/users/"+url.PathEscape(account)
		body = append(append([]byte(`{"credentials":{"password":{"value":`), value...), "}}}"...)
	case "entra-user":
		method, path = http.MethodPatch, "/v1.0/users/"+url.PathEscape(account)
		body = append(append([]byte(`{"passwordProfile":{"password":`), value...), `,"forceChangePasswordNextSignIn":false}}`...)
	case "google-workspace-user":
		method, path = http.MethodPatch, "/admin/directory/v1/users/"+url.PathEscape(account)
		body = append(append([]byte(`{"password":`), value...), `,"changePasswordAtNextLogin":false}`...)
	}
	defer secret.Wipe(body)
	var status int
	var raw []byte
	if b.vendor == "okta-user" {
		err = b.credential.Use(func(token []byte) error {
			status, raw, err = b.api.call(ctx, method, path, body, func(h http.Header) error { h.Set("Authorization", "SSWS "+string(token)); return nil })
			return err
		})
	} else {
		token, terr := b.accessToken(ctx)
		if terr != nil {
			return terr
		}
		status, raw, err = b.api.call(ctx, method, path, body, bearerHeader(token))
		secret.Wipe(token)
	}
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("dynsecret %s: the identity provider refused the password change (HTTP %d)", b.vendor, status)
	}
	return nil
}

// entraProven are the sign-in error codes that follow a right password: an
// MFA or conditional-access step the account must complete interactively.
var entraProven = map[int]bool{50076: true, 50079: true, 50072: true, 50074: true, 50158: true}

// VerifyCredential makes one non-interactive sign-in with the credential.
// Google has none (ErrNoSelfProof).
func (b *IdPAdminBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return fmt.Errorf("dynsecret %s: the credential carries no account and password", b.vendor)
	}
	defer secret.Wipe(parsed.Password)
	password, err := secret.JSONBytes(parsed.Password).MarshalJSON()
	if err != nil {
		return err
	}
	defer secret.Wipe(password)
	name, _ := json.Marshal(parsed.Username)
	switch b.vendor {
	case "okta-user":
		body := append(append(append(append([]byte(`{"username":`), name...), `,"password":`...), password...), '}')
		defer secret.Wipe(body)
		status, raw, err := b.api.call(ctx, http.MethodPost, "/api/v1/authn", body, nil)
		if err != nil {
			return err
		}
		defer secret.Wipe(raw)
		var answer struct {
			Status     string           `json:"status"`
			StateToken secret.JSONBytes `json:"stateToken"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &answer) != nil {
			return fmt.Errorf("dynsecret okta-user: the sign-in was refused (HTTP %d)", status)
		}
		defer secret.Wipe(answer.StateToken)
		if len(answer.StateToken) > 0 {
			// An MFA step is pending: end the transaction so it never waits.
			token, _ := answer.StateToken.MarshalJSON()
			cancel := append(append([]byte(`{"stateToken":`), token...), '}')
			_, out, _ := b.api.call(ctx, http.MethodPost, "/api/v1/authn/cancel", cancel, nil)
			secret.Wipe(cancel)
			secret.Wipe(token)
			secret.Wipe(out)
		}
		switch answer.Status {
		case "SUCCESS", "MFA_REQUIRED", "MFA_ENROLL", "MFA_CHALLENGE":
			return nil
		case "LOCKED_OUT":
			return errors.New("dynsecret okta-user: the account is locked out")
		}
		return fmt.Errorf("dynsecret okta-user: the sign-in ended in %s", answer.Status)
	case "entra-user":
		var form []byte
		err := b.credential.Use(func(clientSecret []byte) error {
			form = append([]byte("grant_type=password&client_id="+url.QueryEscape(b.clientID)+"&scope="+url.QueryEscape("https://graph.microsoft.com/.default")+
				"&username="+url.QueryEscape(parsed.Username)+"&password="), queryEscapeBytes(parsed.Password)...)
			form = append(append(form, "&client_secret="...), queryEscapeBytes(clientSecret)...)
			return nil
		})
		if err != nil {
			return err
		}
		defer secret.Wipe(form)
		status, raw, err := b.authority.send(ctx, http.MethodPost, "/"+b.tenant+"/oauth2/v2.0/token", form, "application/x-www-form-urlencoded", nil)
		if err != nil {
			return err
		}
		defer secret.Wipe(raw)
		if status == http.StatusOK {
			return nil
		}
		var refusal struct {
			ErrorCodes []int `json:"error_codes"`
		}
		_ = json.Unmarshal(raw, &refusal)
		for _, code := range refusal.ErrorCodes {
			switch {
			case entraProven[code]:
				return nil
			case code == 50126:
				return errors.New("dynsecret entra-user: the identity provider refused the password")
			case code == 50053:
				return errors.New("dynsecret entra-user: the account is locked out")
			}
		}
		// The tenant refuses the flow (conditional access, a disabled
		// account, a confidential-client restriction): no proof either way.
		return ErrNoSelfProof
	}
	return ErrNoSelfProof
}

// RestoreStaticCredential puts role's predecessor back and proves it where
// the provider can (the rollback of a failed rotation).
func (b *IdPAdminBackend) RestoreStaticCredential(ctx context.Context, role, _ string, credential []byte) error {
	account, ok := b.accounts[role]
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || !ok || !strings.EqualFold(parsed.Username, account) || len(parsed.Password) == 0 {
		return fmt.Errorf("dynsecret %s: the predecessor is not this role's account credential", b.vendor)
	}
	defer secret.Wipe(parsed.Password)
	if err := b.set(ctx, account, parsed.Password); err != nil {
		return err
	}
	if err := b.VerifyCredential(ctx, credential); err != nil && !errors.Is(err, ErrNoSelfProof) {
		return err
	}
	return nil
}

// Revoke implements Backend: the predecessor stopped working when the next
// password was set.
func (b *IdPAdminBackend) Revoke(_ context.Context, ref string) error {
	account, _, _ := strings.Cut(ref, "/")
	for _, bound := range b.accounts {
		if strings.EqualFold(account, bound) {
			return nil
		}
	}
	return fmt.Errorf("dynsecret %s: refusing %q, which names no account this provider rotates", b.vendor, ref)
}

// Close wipes the administration credential.
func (b *IdPAdminBackend) Close() { b.credential.Destroy() }
