// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

// A271: vCenter Server's local single sign-on users. vCenter offers no
// public API that sets another SSO user's password, so the change is made the
// documented way: SSH to the appliance as root (with a key, root's login
// shell set to bash) and run dir-cli password reset as the SSO administrator,
// whose password is typed at dir-cli's prompt and never on a command line.
// The new password is dir-cli's --new argument (its documented form),
// single-quoted, with the shell's history off. The change is proved by
// opening a vSphere Automation API session (POST /api/session) as the user
// with the new password; a change the appliance does not prove is put back.
// Discovery lists the SSO Administrators group.

// VCenterSSOConfig configures one appliance.
type VCenterSSOConfig struct {
	// Endpoint is the appliance's https://host[:port] for the REST proof;
	// HTTPClient pins its certificate.
	Endpoint   string
	HTTPClient *http.Client
	// SSHAddress and HostKeyFingerprint are the appliance's SSH, where
	// RootUser signs in with RootKeyPKCS8.
	SSHAddress, HostKeyFingerprint string
	RootUser                       string
	RootKeyPKCS8                   []byte
	// SSOAdmin is the SSO administrator's user@domain; SSOAdminPassword its
	// password.
	SSOAdmin         string
	SSOAdminPassword []byte
	// RoleAccounts binds each role to the SSO user name (no domain) it
	// rotates.
	RoleAccounts map[string]string
}

var ssoUPN = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// VCenterSSOBackend rotates and discovers one appliance's SSO users.
type VCenterSSOBackend struct {
	endpoint string
	client   *http.Client
	target   crypto.SSHAccountTarget
	rootKey  *secret.Buffer
	admin    string
	domain   string
	password *secret.Buffer
	accounts map[string]string
}

// NewVCenterSSOBackend validates cfg.
func NewVCenterSSOBackend(cfg VCenterSSOConfig) (*VCenterSSOBackend, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" {
		return nil, errors.New("dynsecret vcenter-sso: endpoint must be the appliance's https://host[:port]")
	}
	if host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.SSHAddress)); err != nil || host == "" || port == "" || !strings.HasPrefix(cfg.HostKeyFingerprint, "SHA256:") {
		return nil, errors.New("dynsecret vcenter-sso: the appliance's SSH host:port and pinned host key are required")
	}
	if cfg.HTTPClient == nil || !crypto.ValidSSHAccountName(cfg.RootUser) || len(cfg.RootKeyPKCS8) == 0 || !ssoUPN.MatchString(cfg.SSOAdmin) || len(cfg.SSOAdminPassword) == 0 {
		return nil, errors.New("dynsecret vcenter-sso: the pinned client, the root key, and the SSO administrator (user@domain) with its password are required")
	}
	admin, domain, _ := strings.Cut(cfg.SSOAdmin, "@")
	b := &VCenterSSOBackend{endpoint: "https://" + parsed.Host, client: cfg.HTTPClient, admin: admin, domain: domain, accounts: map[string]string{},
		target: crypto.SSHAccountTarget{Address: strings.TrimSpace(cfg.SSHAddress), AdminUser: cfg.RootUser, HostKeyFingerprint: cfg.HostKeyFingerprint}}
	seen := map[string]bool{}
	for role, account := range cfg.RoleAccounts {
		account = strings.TrimSpace(account)
		switch {
		case !networkAPIAccount.MatchString(account):
			return nil, fmt.Errorf("dynsecret vcenter-sso: role %q names %q, which is not an SSO user name (no domain)", role, account)
		case strings.EqualFold(account, admin):
			return nil, fmt.Errorf("dynsecret vcenter-sso: role %q names the SSO administrator that makes the change", role)
		case seen[account]:
			return nil, fmt.Errorf("dynsecret vcenter-sso: account %q serves two roles", account)
		}
		seen[account] = true
		b.accounts[role] = account
	}
	if len(b.accounts) == 0 {
		return nil, errors.New("dynsecret vcenter-sso: every allowed role needs its account in role_bindings")
	}
	if b.rootKey, err = secret.NewFrom(cfg.RootKeyPKCS8); err != nil {
		return nil, err
	}
	if b.password, err = secret.NewFrom(cfg.SSOAdminPassword); err != nil {
		b.rootKey.Destroy()
		return nil, err
	}
	return b, nil
}

// Create implements Backend: SSO users are rotated, not leased.
func (b *VCenterSSOBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for a static rotation.
func (b *VCenterSSOBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, errors.New("dynsecret vcenter-sso: an SSO user is rotated, not leased; use a static rotation")
	}
	account, ok := b.accounts[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret vcenter-sso: role %q has no account", req.Role)
	}
	password, err := randomPolicyPassword(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if err := b.set(ctx, account, password); err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the rotated SSO credential; the rotation seals it before storage (CWE-200)
		Host     string           `json:"host"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Host: strings.TrimPrefix(b.endpoint, "https://"), Username: account + "@" + b.domain, Password: password})
	if err != nil {
		return "", nil, err
	}
	return account + "/" + req.LeaseID, credential, nil
}

const dirCLIPath = "/usr/lib/vmware-vmafd/bin/dir-cli"

// dirCLI runs one dir-cli command in the appliance's root shell, answering
// its administrator password prompt, and returns its output.
func (b *VCenterSSOBackend) dirCLI(ctx context.Context, command []byte) ([]byte, error) {
	var out []byte
	err := b.rootKey.Use(func(key []byte) error {
		return b.password.Use(func(admin []byte) error {
			var err error
			out, err = crypto.RunSSHKeyCLI(ctx, b.target, key, "#", []crypto.CLIStep{
				{Line: []byte(" unset HISTFILE"), Prompt: "#"},
				{Line: command, Prompt: ":"},
				{Line: admin, Prompt: "#"},
			})
			return err
		})
	})
	if err != nil {
		return nil, fmt.Errorf("dynsecret vcenter-sso: %w", err)
	}
	if bytes.Contains(out, []byte("dir-cli failed")) {
		secret.Wipe(out)
		return nil, errors.New("dynsecret vcenter-sso: dir-cli refused the command")
	}
	return out, nil
}

// set resets account's password with dir-cli.
func (b *VCenterSSOBackend) set(ctx context.Context, account string, password []byte) error {
	if err := cliPassword(password); err != nil {
		return err
	}
	if bytes.ContainsRune(password, '\'') {
		return errors.New("dynsecret vcenter-sso: the password has a single quote, which the appliance shell cannot take quoted")
	}
	command := append([]byte(" "+dirCLIPath+" password reset --account "+account+" --new '"), password...)
	command = append(command, "' --login "+b.admin+"@"+b.domain...)
	defer secret.Wipe(command)
	out, err := b.dirCLI(ctx, command)
	if err != nil {
		return err
	}
	defer secret.Wipe(out)
	if !bytes.Contains(out, []byte("reset successfully")) {
		return errors.New("dynsecret vcenter-sso: dir-cli did not confirm the reset")
	}
	return nil
}

// VerifyCredential proves the credential opens a vSphere Automation API
// session, then ends it.
func (b *VCenterSSOBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret vcenter-sso: the credential carries no account and password")
	}
	defer secret.Wipe(parsed.Password)
	raw := append([]byte(parsed.Username+":"), parsed.Password...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	secret.Wipe(raw)
	authorization := "Basic " + string(encoded)
	secret.Wipe(encoded)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+"/api/session", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authorization)
	resp, err := b.client.Do(req) // #nosec G704 -- the operator's configured appliance through the pinned, egress-guarded client (CWE-918)
	if err != nil {
		return errors.New("dynsecret vcenter-sso: the appliance did not answer")
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("dynsecret vcenter-sso: the appliance refused %s's session (HTTP %d)", parsed.Username, resp.StatusCode)
	}
	var session string
	if json.Unmarshal(body, &session) == nil && session != "" {
		end, err := http.NewRequestWithContext(ctx, http.MethodDelete, b.endpoint+"/api/session", nil)
		if err == nil {
			end.Header.Set("vmware-api-session-id", session)
			if out, err := b.client.Do(end); err == nil { // #nosec G704 -- same configured appliance (CWE-918)
				_ = out.Body.Close()
			}
		}
	}
	return nil
}

// RestoreStaticCredential puts role's predecessor back and proves it opens a
// session again (the rollback of a failed rotation).
func (b *VCenterSSOBackend) RestoreStaticCredential(ctx context.Context, role, _ string, credential []byte) error {
	account, ok := b.accounts[role]
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || !ok || !strings.EqualFold(parsed.Username, account+"@"+b.domain) || len(parsed.Password) == 0 {
		return errors.New("dynsecret vcenter-sso: the predecessor is not this role's account credential")
	}
	defer secret.Wipe(parsed.Password)
	if err := b.set(ctx, account, parsed.Password); err != nil {
		return err
	}
	return b.VerifyCredential(ctx, credential)
}

// Revoke implements Backend: the predecessor stopped working when the next
// password was set.
func (b *VCenterSSOBackend) Revoke(_ context.Context, ref string) error {
	account, _, _ := strings.Cut(ref, "/")
	for _, bound := range b.accounts {
		if account == bound {
			return nil
		}
	}
	return fmt.Errorf("dynsecret vcenter-sso: refusing %q, which names no account this provider rotates", ref)
}

var ssoMember = regexp.MustCompile(`(?m)^CN=([^,\r\n]+),CN=Users,`)

// DiscoverPrivilegedAccounts lists the members of the SSO Administrators
// group.
func (b *VCenterSSOBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	out, err := b.dirCLI(ctx, []byte(" "+dirCLIPath+" group list --name Administrators --login "+b.admin+"@"+b.domain))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(out)
	var accounts []pamdiscovery.Account
	for _, m := range ssoMember.FindAllSubmatch(out, -1) {
		name := string(m[1])
		accounts = append(accounts, pamdiscovery.Account{Key: "user:" + name, Name: name, Kind: "sso_user",
			Privileges: []string{"group Administrators"}, Details: map[string]string{"domain": b.domain}})
	}
	if len(accounts) > pamdiscovery.MaxAccounts {
		return nil, errors.New("dynsecret vcenter-sso: more accounts than one discovery holds")
	}
	return accounts, nil
}

// Close wipes the root key and the administrator's password.
func (b *VCenterSSOBackend) Close() {
	b.rootKey.Destroy()
	b.password.Destroy()
}
