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
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

// A271: server management controller accounts through Redfish's
// AccountService (HPE iLO first, then any conforming controller). The
// administrator opens a Redfish session, finds the bound account's
// ManagerAccount by UserName and PATCHes its Password; the change is proved
// by opening a new session with the new password, and a change the
// controller does not prove is put back. Each role is one account, changed in
// place (single-phase); the administrator is never one of them.

// RedfishConfig configures one controller.
type RedfishConfig struct {
	// Endpoint is the controller's https://host[:port]; HTTPClient pins its
	// certificate.
	Endpoint      string
	HTTPClient    *http.Client
	AdminUser     string
	AdminPassword []byte
	// RoleAccounts binds each role to the UserName it rotates.
	RoleAccounts map[string]string
}

// RedfishBackend rotates and discovers one controller's accounts.
type RedfishBackend struct {
	endpoint string
	client   *http.Client
	admin    string
	password *secret.Buffer
	accounts map[string]string
}

// NewRedfishBackend validates cfg.
func NewRedfishBackend(cfg RedfishConfig) (*RedfishBackend, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" {
		return nil, errors.New("dynsecret redfish: endpoint must be the controller's https://host[:port]")
	}
	if cfg.HTTPClient == nil || !networkAPIAccount.MatchString(cfg.AdminUser) || len(cfg.AdminPassword) == 0 {
		return nil, errors.New("dynsecret redfish: the pinned client, admin_user and its password are required")
	}
	b := &RedfishBackend{endpoint: "https://" + parsed.Host, client: cfg.HTTPClient, admin: cfg.AdminUser, accounts: map[string]string{}}
	seen := map[string]bool{}
	for role, account := range cfg.RoleAccounts {
		account = strings.TrimSpace(account)
		switch {
		case !networkAPIAccount.MatchString(account):
			return nil, fmt.Errorf("dynsecret redfish: role %q names %q, which is not an account name", role, account)
		case account == cfg.AdminUser:
			return nil, fmt.Errorf("dynsecret redfish: role %q names the administrator that makes the change", role)
		case seen[account]:
			return nil, fmt.Errorf("dynsecret redfish: account %q serves two roles", account)
		}
		seen[account] = true
		b.accounts[role] = account
	}
	if len(b.accounts) == 0 {
		return nil, errors.New("dynsecret redfish: every allowed role needs its account in role_bindings")
	}
	if b.password, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend: controller accounts are rotated, not leased.
func (b *RedfishBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for a static rotation.
func (b *RedfishBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, errors.New("dynsecret redfish: a controller account is rotated, not leased; use a static rotation")
	}
	account, ok := b.accounts[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret redfish: role %q has no account", req.Role)
	}
	password, err := randomPolicyPassword(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if err := b.set(ctx, account, password); err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the rotated controller credential; the rotation seals it before storage (CWE-200)
		Host     string           `json:"host"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Host: strings.TrimPrefix(b.endpoint, "https://"), Username: account, Password: password})
	if err != nil {
		return "", nil, err
	}
	return account + "/" + req.LeaseID, credential, nil
}

// do sends one request; the caller wipes the response.
func (b *RedfishBackend) do(ctx context.Context, method, path, token string, header http.Header, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Auth-Token", token)
	}
	resp, err := b.client.Do(req) // #nosec G704 -- the operator's configured controller through the pinned, egress-guarded client (CWE-918)
	if err != nil {
		// A dial, TLS handshake or deadline reads as unreachable (DEV-D1).
		return 0, nil, nil, withSignInClass(classifyNetwork(err), errors.New("dynsecret redfish: the controller did not answer"))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, networkAPIMaxBody+1))
	if err != nil || len(raw) > networkAPIMaxBody {
		secret.Wipe(raw)
		return 0, nil, nil, errors.New("dynsecret redfish: the controller's answer was unreadable or too large")
	}
	return resp.StatusCode, resp.Header, raw, nil
}

// session opens a Redfish session as user and returns its token and URI.
// The token is a header string, as net/http requires; it is deleted with the
// session.
func (b *RedfishBackend) session(ctx context.Context, user string, password []byte) (string, string, error) {
	value, err := secret.JSONBytes(password).MarshalJSON()
	if err != nil {
		return "", "", err
	}
	name, _ := json.Marshal(user)
	body := append(append(append(append([]byte(`{"UserName":`), name...), `,"Password":`...), value...), '}')
	secret.Wipe(value)
	defer secret.Wipe(body)
	status, header, raw, err := b.do(ctx, http.MethodPost, "/redfish/v1/SessionService/Sessions", "", nil, body)
	secret.Wipe(raw)
	if err != nil {
		return "", "", err
	}
	// DSP0266 has a service answer a new session with 201 Created, but the
	// token is what a session needs: DMTF's reference client accepts any
	// success that carries one, and DMTF's reference mockup answers 204.
	token, location := header.Get("X-Auth-Token"), header.Get("Location")
	if status == http.StatusUnauthorized {
		// DSP0266: a session refused for its credentials is 401, the rejected
		// class (DEV-D1).
		return "", "", fmt.Errorf("%w: dynsecret redfish: the controller refused %s's session (HTTP %d)", ErrSignInRejected, user, status)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices || token == "" {
		return "", "", fmt.Errorf("dynsecret redfish: the controller refused %s's session (HTTP %d)", user, status)
	}
	if u, err := url.Parse(location); err == nil && u.Path != "" {
		location = u.Path
	}
	if !strings.HasPrefix(location, "/redfish/v1/SessionService/Sessions/") {
		location = ""
	}
	return token, location, nil
}

func (b *RedfishBackend) endSession(ctx context.Context, token, location string) {
	if location == "" {
		return
	}
	_, _, raw, _ := b.do(ctx, http.MethodDelete, location, token, nil, nil)
	secret.Wipe(raw)
}

// adminSession runs fn in an administrator session and ends it.
func (b *RedfishBackend) adminSession(ctx context.Context, fn func(token string) error) error {
	return b.password.Use(func(admin []byte) error {
		token, location, err := b.session(ctx, b.admin, admin)
		if err != nil {
			return err
		}
		defer b.endSession(context.WithoutCancel(ctx), token, location)
		return fn(token)
	})
}

type redfishAccount struct {
	URI      string
	UserName string `json:"UserName"`
	RoleID   string `json:"RoleId"`
	Enabled  bool   `json:"Enabled"`
	ETag     string
}

// listAccounts reads every ManagerAccount (never a password: Redfish answers
// Password as null).
func (b *RedfishBackend) listAccounts(ctx context.Context, token string) ([]redfishAccount, error) {
	status, _, raw, err := b.do(ctx, http.MethodGet, "/redfish/v1/AccountService/Accounts", token, nil, nil)
	if err != nil {
		return nil, err
	}
	var collection struct {
		Members []struct {
			ID string `json:"@odata.id"`
		} `json:"Members"`
	}
	err = json.Unmarshal(raw, &collection)
	secret.Wipe(raw)
	if status != http.StatusOK || err != nil {
		return nil, fmt.Errorf("dynsecret redfish: the account collection was unreadable (HTTP %d)", status)
	}
	if len(collection.Members) > pamdiscovery.MaxAccounts {
		return nil, errors.New("dynsecret redfish: more accounts than one discovery holds")
	}
	var out []redfishAccount
	for _, m := range collection.Members {
		if !strings.HasPrefix(m.ID, "/redfish/v1/AccountService/Accounts/") {
			continue
		}
		status, header, raw, err := b.do(ctx, http.MethodGet, m.ID, token, nil, nil)
		if err != nil {
			return nil, err
		}
		var a redfishAccount
		err = json.Unmarshal(raw, &a)
		secret.Wipe(raw)
		if status != http.StatusOK || err != nil {
			return nil, fmt.Errorf("dynsecret redfish: an account was unreadable (HTTP %d)", status)
		}
		a.URI, a.ETag = m.ID, header.Get("ETag")
		out = append(out, a)
	}
	return out, nil
}

// set changes account's password.
func (b *RedfishBackend) set(ctx context.Context, account string, password []byte) error {
	value, err := secret.JSONBytes(password).MarshalJSON()
	if err != nil {
		return err
	}
	body := append(append([]byte(`{"Password":`), value...), '}')
	secret.Wipe(value)
	defer secret.Wipe(body)
	return b.adminSession(ctx, func(token string) error {
		accounts, err := b.listAccounts(ctx, token)
		if err != nil {
			return err
		}
		for _, a := range accounts {
			if a.UserName != account {
				continue
			}
			header := http.Header{}
			if a.ETag != "" {
				header.Set("If-Match", a.ETag)
			}
			status, _, raw, err := b.do(ctx, http.MethodPatch, a.URI, token, header, body)
			secret.Wipe(raw)
			if err != nil {
				return err
			}
			if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusAccepted {
				return fmt.Errorf("dynsecret redfish: the controller refused the change (HTTP %d)", status)
			}
			return nil
		}
		return fmt.Errorf("dynsecret redfish: account %q is not on the controller", account)
	})
}

// VerifyCredential proves the credential opens a new session.
func (b *RedfishBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret redfish: the credential carries no account and password")
	}
	defer secret.Wipe(parsed.Password)
	token, location, err := b.session(ctx, parsed.Username, parsed.Password)
	if err != nil {
		return err
	}
	b.endSession(ctx, token, location)
	return nil
}

// RestoreStaticCredential puts role's predecessor back and proves it opens a
// session again (the rollback of a failed rotation).
func (b *RedfishBackend) RestoreStaticCredential(ctx context.Context, role, _ string, credential []byte) error {
	account, ok := b.accounts[role]
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || !ok || parsed.Username != account || len(parsed.Password) == 0 {
		return errors.New("dynsecret redfish: the predecessor is not this role's account credential")
	}
	defer secret.Wipe(parsed.Password)
	if err := b.set(ctx, account, parsed.Password); err != nil {
		return err
	}
	return b.VerifyCredential(ctx, credential)
}

// Revoke implements Backend: the predecessor stopped working when the next
// password was set.
func (b *RedfishBackend) Revoke(_ context.Context, ref string) error {
	account, _, _ := strings.Cut(ref, "/")
	for _, bound := range b.accounts {
		if account == bound {
			return nil
		}
	}
	return fmt.Errorf("dynsecret redfish: refusing %q, which names no account this provider rotates", ref)
}

// DiscoverPrivilegedAccounts lists the controller's accounts with their
// RoleId; disabled accounts are marked so.
func (b *RedfishBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	var out []pamdiscovery.Account
	err := b.adminSession(ctx, func(token string) error {
		accounts, err := b.listAccounts(ctx, token)
		if err != nil {
			return err
		}
		for _, a := range accounts {
			if a.UserName == "" {
				continue // an empty account slot (iLO and many controllers list them)
			}
			out = append(out, pamdiscovery.Account{Key: "user:" + a.UserName, Name: a.UserName, Kind: "local_user",
				Privileges: []string{"role " + a.RoleID}, Disabled: !a.Enabled, Details: map[string]string{"controller": "redfish"}})
		}
		return nil
	})
	return out, err
}

// Close wipes the administrator's password.
func (b *RedfishBackend) Close() { b.password.Destroy() }
