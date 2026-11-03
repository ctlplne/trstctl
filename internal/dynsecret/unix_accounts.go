// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// UnixAccountsConfig configures the local-account rotator (A240). The host is
// reached over SSH as an administrator authenticating with a key, its host key
// pinned, and the only command run is chpasswd with the change on stdin. A
// role with RotationAccounts alternates between two local accounts its owner
// provisioned (two-phase); any other allowed role is bound to one account,
// whose password changes in place, so its rotation is single-phase. It rotates
// only; it issues no leases.
type UnixAccountsConfig struct {
	// Address is the host's SSH endpoint, host:port.
	Address string
	// AdminUser is root, or an account allowed `sudo -n /usr/sbin/chpasswd`
	// (Sudo); AdminKey is its private key, PKCS#8 PEM.
	AdminUser          string
	AdminKey           []byte
	HostKeyFingerprint string
	Sudo               bool
	RoleAccounts       map[string]string
	RotationAccounts   map[string][2]string
	// Windows rotates a Windows host's local accounts instead (A240): the
	// host serves OpenSSH, AdminUser is in Administrators, and the profile is
	// Set-LocalUser with the password on stdin. Its passwords mix upper and
	// lower case letters and digits, which Windows' complexity rule needs.
	Windows bool
}

// UnixAccountsBackend changes local account passwords over SSH.
type UnixAccountsBackend struct {
	provider string
	target   crypto.SSHAccountTarget
	adminKey *secret.Buffer
	accounts map[string]string
	pairs    map[string][2]string
}

// NewUnixAccountsBackend validates cfg.
func NewUnixAccountsBackend(cfg UnixAccountsConfig) (*UnixAccountsBackend, error) {
	if host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.Address)); err != nil || host == "" || port == "" {
		return nil, errors.New("dynsecret unix: addr must be the host's SSH host:port")
	}
	if !crypto.ValidSSHAccountName(cfg.AdminUser) || !strings.HasPrefix(cfg.HostKeyFingerprint, "SHA256:") || len(cfg.AdminKey) == 0 {
		return nil, errors.New("dynsecret unix: admin_user, its private key and the pinned host_key_fingerprint are required")
	}
	if cfg.Windows && cfg.Sudo {
		return nil, errors.New("dynsecret windows: sudo is a Unix setting")
	}
	b := &UnixAccountsBackend{
		provider: "unix",
		target: crypto.SSHAccountTarget{Address: strings.TrimSpace(cfg.Address), AdminUser: cfg.AdminUser,
			HostKeyFingerprint: cfg.HostKeyFingerprint, Sudo: cfg.Sudo, Windows: cfg.Windows},
		accounts: map[string]string{}, pairs: map[string][2]string{},
	}
	if cfg.Windows {
		b.provider = "windows"
	}
	owner := map[string]string{}
	claim := func(role, account string) error {
		if !crypto.ValidSSHAccountName(account) {
			return fmt.Errorf("dynsecret unix: role %q names %q, which is not a local account name", role, account)
		}
		if other, taken := owner[account]; taken && other != role {
			return fmt.Errorf("dynsecret unix: account %q serves roles %q and %q", account, other, role)
		}
		owner[account] = role
		return nil
	}
	for role, pair := range cfg.RotationAccounts {
		if pair[0] == pair[1] {
			return nil, fmt.Errorf("dynsecret unix: role %q needs two distinct rotation accounts", role)
		}
		for _, account := range pair {
			if err := claim(role, account); err != nil {
				return nil, err
			}
		}
		b.pairs[role] = pair
	}
	for role, account := range cfg.RoleAccounts {
		if _, paired := b.pairs[role]; paired {
			continue
		}
		account = strings.TrimSpace(account)
		if err := claim(role, account); err != nil {
			return nil, err
		}
		b.accounts[role] = account
	}
	if len(b.accounts) == 0 && len(b.pairs) == 0 {
		return nil, errors.New("dynsecret unix: every allowed role needs its account in role_bindings, or two in rotation_accounts")
	}
	var err error
	if b.adminKey, err = secret.NewFrom(cfg.AdminKey); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend: local accounts are rotated, not leased.
func (b *UnixAccountsBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for a static rotation. A
// two-user role stages the account its consumers are not using and the
// reference names that account; a single-account role changes the bound
// account's password in place and the reference names the account and the
// rotation, so retiring the predecessor has nothing left to do.
func (b *UnixAccountsBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, errors.New("dynsecret unix: a local account is rotated, not leased; use a static rotation")
	}
	account, ref := "", ""
	if next, ok := TwoUserAccount(b.pairs, req.Role, req.Predecessor); ok {
		account, ref = next, next
	} else if bound, ok := b.accounts[req.Role]; ok {
		account, ref = bound, bound+"/"+req.LeaseID
	} else {
		return "", nil, fmt.Errorf("dynsecret unix: role %q has no account", req.Role)
	}
	password, err := b.newPassword(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if err := b.setPassword(ctx, account, password); err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the rotated local-account credential; the rotation seals it before storage (CWE-200)
		Host     string           `json:"host"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Host: b.target.Address, Username: account, Password: password})
	if err != nil {
		return "", nil, err
	}
	return ref, credential, nil
}

func (b *UnixAccountsBackend) setPassword(ctx context.Context, account string, password []byte) error {
	return b.adminKey.Use(func(adminKey []byte) error {
		if err := crypto.SetSSHAccountPassword(ctx, b.target, adminKey, account, password); err != nil {
			return fmt.Errorf("dynsecret %s: %w", b.provider, err)
		}
		return nil
	})
}

// newPassword returns n characters a host accepts: hex on Unix; on Windows,
// whose complexity rule wants three character classes, upper and lower case
// letters and digits.
func (b *UnixAccountsBackend) newPassword(n int) ([]byte, error) {
	if b.target.Windows {
		return randomPolicyPassword(n)
	}
	return randomSecretHex(n)
}

// Revoke implements Backend. A two-user account is retired by setting a
// password nobody holds; its groups and files stay. A single-account
// rotation's predecessor stopped working when the next password was set, so
// retiring it has nothing left to do. Anything else is refused.
func (b *UnixAccountsBackend) Revoke(ctx context.Context, ref string) error {
	for _, pair := range b.pairs {
		if ref == pair[0] || ref == pair[1] {
			scrambled, err := b.newPassword(32)
			if err != nil {
				return err
			}
			defer secret.Wipe(scrambled)
			return b.setPassword(ctx, ref, scrambled)
		}
	}
	account, _, _ := strings.Cut(ref, "/")
	for _, bound := range b.accounts {
		if account == bound {
			return nil
		}
	}
	return fmt.Errorf("dynsecret %s: refusing %q, which names no account this provider rotates", b.provider, ref)
}

// VerifyCredential proves the credential logs in at the host (password
// authentication; no command runs).
func (b *UnixAccountsBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret unix: the credential carries no account and password")
	}
	defer secret.Wipe(parsed.Password)
	if err := crypto.VerifySSHAccountPassword(ctx, b.target, parsed.Username, parsed.Password); err != nil {
		return fmt.Errorf("dynsecret %s: %w", b.provider, err)
	}
	return nil
}

// Close wipes the administrator key.
func (b *UnixAccountsBackend) Close() { b.adminKey.Destroy() }
