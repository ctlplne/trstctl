// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

// A270: local account passwords on network devices, changed through the
// device's own command line over SSH: Cisco IOS-XE and Juniper Junos. Each
// allowed role is bound to one account whose password changes in place
// (single-phase); on IOS-XE the account "enable" is the privileged-mode
// secret. The administrator that signs in to make the change is never one of
// the rotated accounts.

// NetworkDeviceConfig configures one device.
type NetworkDeviceConfig struct {
	// Vendor is "iosxe" or "junos".
	Vendor string
	// Address is the device's SSH host:port, pinned by HostKeyFingerprint.
	Address, HostKeyFingerprint string
	// AdminUser signs in with AdminPassword to change the bound accounts.
	AdminUser     string
	AdminPassword []byte
	// RoleAccounts binds each role to the account it rotates.
	RoleAccounts map[string]string
}

// NetworkEnableAccount is the IOS-XE privileged-mode secret as a bound account.
const NetworkEnableAccount = "enable"

// networkDevicePrompts are the prompts an administrator lands at.
var networkDevicePrompts = map[string]string{"iosxe": "#", "junos": ">"}

// NetworkDeviceBackend rotates and discovers one device's local accounts.
type NetworkDeviceBackend struct {
	vendor   string
	target   crypto.SSHAccountTarget
	admin    string
	password *secret.Buffer
	accounts map[string]string
}

// NewNetworkDeviceBackend validates cfg.
func NewNetworkDeviceBackend(cfg NetworkDeviceConfig) (*NetworkDeviceBackend, error) {
	if _, ok := networkDevicePrompts[cfg.Vendor]; !ok {
		return nil, fmt.Errorf("dynsecret network: unknown device type %q", cfg.Vendor)
	}
	if host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.Address)); err != nil || host == "" || port == "" {
		return nil, errors.New("dynsecret network: addr must be the device's SSH host:port")
	}
	if !crypto.ValidSSHAccountName(cfg.AdminUser) || len(cfg.AdminPassword) == 0 || !strings.HasPrefix(cfg.HostKeyFingerprint, "SHA256:") {
		return nil, errors.New("dynsecret network: admin_user, its password and the pinned host_key_fingerprint are required")
	}
	b := &NetworkDeviceBackend{vendor: cfg.Vendor, admin: cfg.AdminUser, accounts: map[string]string{},
		target: crypto.SSHAccountTarget{Address: strings.TrimSpace(cfg.Address), AdminUser: cfg.AdminUser, HostKeyFingerprint: cfg.HostKeyFingerprint}}
	seen := map[string]bool{}
	for role, account := range cfg.RoleAccounts {
		account = strings.TrimSpace(account)
		switch {
		case account == NetworkEnableAccount && cfg.Vendor != "iosxe":
			return nil, fmt.Errorf("dynsecret network: role %q names the enable secret, which only IOS-XE has", role)
		case account != NetworkEnableAccount && !crypto.ValidSSHAccountName(account):
			return nil, fmt.Errorf("dynsecret network: role %q names %q, which is not a device account name", role, account)
		case account == cfg.AdminUser:
			return nil, fmt.Errorf("dynsecret network: role %q names the administrator that makes the change", role)
		case seen[account]:
			return nil, fmt.Errorf("dynsecret network: account %q serves two roles", account)
		}
		seen[account] = true
		b.accounts[role] = account
	}
	if len(b.accounts) == 0 {
		return nil, errors.New("dynsecret network: every allowed role needs its account in role_bindings")
	}
	var err error
	if b.password, err = secret.NewFrom(cfg.AdminPassword); err != nil {
		return nil, err
	}
	return b, nil
}

// Create implements Backend: device accounts are rotated, not leased.
func (b *NetworkDeviceBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend for a static rotation: the bound
// account's password (or the enable secret) changes in place.
func (b *NetworkDeviceBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, errors.New("dynsecret network: a device account is rotated, not leased; use a static rotation")
	}
	account, ok := b.accounts[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret network: role %q has no account", req.Role)
	}
	password, err := randomPolicyPassword(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if err := b.set(ctx, account, password); err != nil {
		return "", nil, err
	}
	credential, err := b.credential(account, password)
	if err != nil {
		return "", nil, err
	}
	return account + "/" + req.LeaseID, credential, nil
}

func (b *NetworkDeviceBackend) credential(account string, password []byte) ([]byte, error) {
	return json.Marshal(struct { // #nosec G117 -- the rotated device credential; the rotation seals it before storage (CWE-200)
		Host     string           `json:"host"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{Host: b.target.Address, Username: account, Password: password})
}

// run signs in as the administrator and runs steps, returning the transcript.
func (b *NetworkDeviceBackend) run(ctx context.Context, steps []crypto.CLIStep) ([]byte, error) {
	var out []byte
	err := b.password.Use(func(admin []byte) error {
		var err error
		out, err = crypto.RunNetworkDeviceCLI(ctx, b.target, b.admin, admin, networkDevicePrompts[b.vendor], steps)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("dynsecret %s: %w", b.vendor, err)
	}
	return out, nil
}

var iosxeUsername = regexp.MustCompile(`(?m)^username (\S+)(?: privilege (\d+))?`)

// iosxePrivilege reads an account's current privilege level: IOS replaces the
// whole username line, so a change that omitted it would reset the account
// to privilege 1.
func (b *NetworkDeviceBackend) iosxePrivilege(ctx context.Context, account string) (string, error) {
	out, err := b.run(ctx, []crypto.CLIStep{{Line: []byte("terminal length 0"), Prompt: "#"}, {Line: []byte("show running-config | include ^username"), Prompt: "#"}})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(out)
	for _, m := range iosxeUsername.FindAllSubmatch(out, -1) {
		if string(m[1]) == account {
			if len(m[2]) == 0 {
				return "1", nil
			}
			return string(m[2]), nil
		}
	}
	return "", fmt.Errorf("dynsecret iosxe: account %q is not on the device", account)
}

func line(parts ...[]byte) []byte { return bytes.Join(parts, []byte(" ")) }

// set changes account's password (or the enable secret) and saves the
// configuration.
func (b *NetworkDeviceBackend) set(ctx context.Context, account string, password []byte) error {
	var steps []crypto.CLIStep
	switch b.vendor {
	case "iosxe":
		change := line([]byte("enable secret 0"), password)
		if account != NetworkEnableAccount {
			privilege, err := b.iosxePrivilege(ctx, account)
			if err != nil {
				return err
			}
			change = line([]byte("username "+account+" privilege "+privilege+" secret 0"), password)
		}
		defer secret.Wipe(change)
		steps = []crypto.CLIStep{{Line: []byte("terminal length 0"), Prompt: "#"}, {Line: []byte("configure terminal"), Prompt: "(config)#"},
			{Line: change, Prompt: "(config)#"}, {Line: []byte("end"), Prompt: "#"}, {Line: []byte("write memory"), Prompt: "#"}}
	case "junos":
		steps = []crypto.CLIStep{{Line: []byte("set cli screen-length 0"), Prompt: ">"}, {Line: []byte("configure private"), Prompt: "#"},
			{Line: []byte("set system login user " + account + " authentication plain-text-password"), Prompt: "New password:"},
			{Line: password, Prompt: "Retype new password:"}, {Line: password, Prompt: "#"}, {Line: []byte("commit and-quit"), Prompt: ">"}}
	}
	out, err := b.run(ctx, steps)
	secret.Wipe(out)
	return err
}

// VerifyCredential proves the credential signs in at the device; the enable
// secret is proved by entering privileged mode with it.
func (b *NetworkDeviceBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.Username == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret network: the credential carries no account and password")
	}
	defer secret.Wipe(parsed.Password)
	if parsed.Username == NetworkEnableAccount && b.vendor == "iosxe" {
		out, err := b.run(ctx, []crypto.CLIStep{{Line: []byte("disable"), Prompt: ">"}, {Line: []byte("enable"), Prompt: "Password:"},
			{Line: parsed.Password, Prompt: "#"}})
		secret.Wipe(out)
		return err
	}
	if err := crypto.VerifySSHAccountPassword(ctx, b.target, parsed.Username, parsed.Password); err != nil {
		return fmt.Errorf("dynsecret %s: %w", b.vendor, err)
	}
	return nil
}

// RestoreStaticCredential puts role's predecessor credential back on the
// device and proves it signs in again (the rollback of a failed rotation).
func (b *NetworkDeviceBackend) RestoreStaticCredential(ctx context.Context, role, _ string, credential []byte) error {
	account, ok := b.accounts[role]
	var parsed struct {
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || !ok || parsed.Username != account || len(parsed.Password) == 0 {
		return errors.New("dynsecret network: the predecessor is not this role's account credential")
	}
	defer secret.Wipe(parsed.Password)
	if err := b.set(ctx, account, parsed.Password); err != nil {
		return err
	}
	return b.VerifyCredential(ctx, credential)
}

// Revoke implements Backend: the predecessor stopped working when the next
// password was set, so retiring it has nothing left to do.
func (b *NetworkDeviceBackend) Revoke(_ context.Context, ref string) error {
	account, _, _ := strings.Cut(ref, "/")
	for _, bound := range b.accounts {
		if account == bound {
			return nil
		}
	}
	return fmt.Errorf("dynsecret %s: refusing %q, which names no account this provider rotates", b.vendor, ref)
}

var junosClass = regexp.MustCompile(`(?m)^set system login user (\S+) class (\S+)`)

// DiscoverPrivilegedAccounts lists the device's local accounts with their
// privilege level (IOS-XE) or login class (Junos); password hashes are never
// read into the result.
func (b *NetworkDeviceBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	var steps []crypto.CLIStep
	var pattern *regexp.Regexp
	fact := ""
	switch b.vendor {
	case "iosxe":
		steps = []crypto.CLIStep{{Line: []byte("terminal length 0"), Prompt: "#"}, {Line: []byte("show running-config | include ^username"), Prompt: "#"}}
		pattern, fact = iosxeUsername, "privilege "
	case "junos":
		steps = []crypto.CLIStep{{Line: []byte("set cli screen-length 0"), Prompt: ">"}, {Line: []byte("show configuration system login | display set"), Prompt: ">"}}
		pattern, fact = junosClass, "class "
	}
	out, err := b.run(ctx, steps)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(out)
	var accounts []pamdiscovery.Account
	for _, m := range pattern.FindAllSubmatch(out, -1) {
		level := string(m[2])
		if level == "" {
			level = "1"
		}
		name := string(m[1])
		accounts = append(accounts, pamdiscovery.Account{Key: "user:" + name, Name: name, Kind: "local_user",
			Privileges: []string{fact + level}, Details: map[string]string{"device": b.vendor}})
	}
	if len(accounts) > pamdiscovery.MaxAccounts {
		return nil, errors.New("dynsecret network: more accounts than one discovery holds")
	}
	return accounts, nil
}

// Close wipes the administrator's password.
func (b *NetworkDeviceBackend) Close() { b.password.Destroy() }
