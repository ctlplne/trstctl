// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// LDAPConfig configures the LDAP directory-account backend (A239). Each lease is
// an inetOrgPerson entry under UsersDN whose password the directory sets and
// hashes itself (the Password Modify extended operation), added to the groups
// its role is bound to; revocation removes it from those groups and deletes
// it, after which the directory refuses its bind.
type LDAPConfig struct {
	ADReconcile *ADReconcileAuthority
	// DirectoryMode is empty for generic LDAP, active_directory for existing AD accounts.
	DirectoryMode string `json:"directory_mode"`
	// Addr is the directory's host:port: its LDAPS listener, or, with
	// AllowPlaintext, plain LDAP at a literal loopback or private IP.
	Addr string
	// TLSServerName is the certificate name LDAPS verifies; Addr's host when
	// that is a name. TLSCAPEM pins a private CA; system roots when empty.
	TLSServerName  string
	TLSCAPEM       []byte
	AllowPlaintext bool
	BindDN         string
	BindPassword   []byte
	// UsersDN is the container leased entries are created in.
	UsersDN string
	// RoleGroups maps each allowed role to the DN of the group
	// (groupOfNames) whose members get that role's authority. In active_directory
	// mode each value instead names one existing AD account under UsersDN.
	RoleGroups     map[string]string
	UsernamePrefix string
	// RotationAccounts maps a two-user role to two existing entries under
	// UsersDN (A240): a static rotation sets a new password on the one its
	// consumers are not using and retires the other by setting one nobody
	// holds; both keep their group memberships.
	RotationAccounts map[string][2]string
}

// The active_directory mode instead rotates existing named AD user accounts
// over verified LDAPS; it never creates inetOrgPerson entries as AD users.

// ldapConn is the part of a directory connection the backend uses.
type ldapConn interface {
	Bind(username, password string) error
	Add(*ldap.AddRequest) error
	Del(*ldap.DelRequest) error
	Modify(*ldap.ModifyRequest) error
	PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	Close() error
}

// LDAPBackend creates and deletes leased directory accounts.
type LDAPBackend struct {
	reconcile        *ADReconcileAuthority
	activeDirectory  bool
	url              string
	addr             string
	tls              bool
	serverName       string
	caPEM            []byte
	bindDN           string
	bindPassword     *secret.Buffer
	usersDN          string
	roleGroups       map[string]string
	usernamePrefix   string
	rotationAccounts map[string][2]string
	dial             func(ctx context.Context) (ldapConn, error)
}

// NewLDAPBackend validates cfg and builds the backend.
func NewLDAPBackend(cfg LDAPConfig) (*LDAPBackend, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(cfg.Addr))
	if err != nil || host == "" || port == "" {
		return nil, errors.New("dynsecret ldap: addr must be host:port")
	}
	b := &LDAPBackend{addr: net.JoinHostPort(host, port), tls: !cfg.AllowPlaintext,
		serverName: cfg.TLSServerName, caPEM: append([]byte(nil), cfg.TLSCAPEM...), bindDN: strings.TrimSpace(cfg.BindDN),
		usersDN: strings.TrimSpace(cfg.UsersDN), roleGroups: map[string]string{}, usernamePrefix: cfg.UsernamePrefix}
	if cfg.DirectoryMode != "" && cfg.DirectoryMode != "active_directory" {
		return nil, errors.New("dynsecret ldap: unknown directory_mode")
	}
	b.activeDirectory = cfg.DirectoryMode == "active_directory"
	if b.activeDirectory && cfg.AllowPlaintext {
		return nil, errors.New("dynsecret AD: verified LDAPS is required")
	}
	address := net.ParseIP(host)
	switch {
	case cfg.AllowPlaintext:
		if address == nil || (!address.IsLoopback() && !address.IsPrivate()) || cfg.TLSServerName != "" || len(cfg.TLSCAPEM) > 0 {
			return nil, errors.New("dynsecret ldap: plaintext LDAP is allowed only to a literal loopback or private IP, with no TLS settings")
		}
		b.url = "ldap://" + b.addr
	case b.serverName == "" && address != nil:
		return nil, errors.New("dynsecret ldap: tls_server_name is required when addr is an IP address")
	default:
		if b.serverName == "" {
			b.serverName = host
		}
		b.url = "ldaps://" + b.addr
	}
	if _, err := ldap.ParseDN(b.bindDN); err != nil || b.bindDN == "" {
		return nil, errors.New("dynsecret ldap: bind_dn must be a distinguished name")
	}
	if _, err := ldap.ParseDN(b.usersDN); err != nil || b.usersDN == "" {
		return nil, errors.New("dynsecret ldap: users_dn must be a distinguished name")
	}
	if len(cfg.BindPassword) == 0 {
		return nil, errors.New("dynsecret ldap: a bind password is required")
	}
	for role, group := range cfg.RoleGroups {
		group = strings.TrimSpace(group)
		if _, err := ldap.ParseDN(group); err != nil || group == "" {
			return nil, fmt.Errorf("dynsecret ldap: role_bindings[%q] must be a group DN", role)
		}
		if b.activeDirectory && !b.insideADContainer(group) {
			return nil, errors.New("dynsecret AD: each role names an existing account under users_dn")
		}
		b.roleGroups[role] = group
	}
	if len(b.roleGroups) == 0 {
		return nil, errors.New("dynsecret ldap: every allowed role needs a group in role_bindings")
	}
	b.rotationAccounts = map[string][2]string{}
	owner := map[string]string{}
	for role, pair := range cfg.RotationAccounts {
		for _, dn := range pair {
			if !b.underUsersDN(dn) {
				return nil, fmt.Errorf("dynsecret ldap: rotation account %q of role %q is not an entry under users_dn", dn, role)
			}
			if other, taken := owner[strings.ToLower(dn)]; taken {
				return nil, fmt.Errorf("dynsecret ldap: rotation account %q serves roles %q and %q", dn, other, role)
			}
			owner[strings.ToLower(dn)] = role
		}
		if strings.EqualFold(pair[0], pair[1]) {
			return nil, fmt.Errorf("dynsecret ldap: role %q needs two distinct rotation accounts", role)
		}
		b.rotationAccounts[role] = pair
	}
	if b.activeDirectory {
		if err := b.validateADBindings(); err != nil {
			return nil, err
		}
	}
	if err := b.configureADReconcile(cfg.ADReconcile); err != nil {
		return nil, err
	}
	password, err := secret.NewFrom(cfg.BindPassword)
	if err != nil {
		return nil, err
	}
	b.bindPassword = password
	b.dial = b.dialDirectory
	return b, nil
}

// underUsersDN reports whether dn is a distinguished name inside users_dn.
func (b *LDAPBackend) underUsersDN(dn string) bool {
	_, err := ldap.ParseDN(dn)
	return err == nil && strings.HasSuffix(strings.ToLower(dn), ","+strings.ToLower(b.usersDN))
}

// isRotationAccount reports whether dn is one entry of a two-user pair.
func (b *LDAPBackend) isRotationAccount(dn string) bool {
	for _, pair := range b.rotationAccounts {
		if strings.EqualFold(dn, pair[0]) || strings.EqualFold(dn, pair[1]) {
			return true
		}
	}
	return false
}

// dialDirectory connects (verified TLS through the crypto boundary, or the
// allowed plaintext) and binds as the administrator.
func (b *LDAPBackend) dialDirectory(ctx context.Context) (ldapConn, error) {
	var raw net.Conn
	var err error
	if b.tls {
		raw, err = mtls.DialVerifiedTCP(ctx, b.addr, b.serverName, b.caPEM)
	} else {
		raw, err = (&net.Dialer{}).DialContext(ctx, "tcp", b.addr)
	}
	if err != nil {
		return nil, errors.New("dynsecret ldap: connect failed")
	}
	conn := ldap.NewConn(raw, b.tls)
	conn.Start()
	return conn, nil
}

func (b *LDAPBackend) connect(ctx context.Context) (ldapConn, error) {
	conn, err := b.dial(ctx)
	if err != nil {
		return nil, err
	}
	// go-ldap takes the bind password as a string; it is converted at the call
	// and not kept.
	if err := b.bindPassword.Use(func(password []byte) error {
		return conn.Bind(b.bindDN, secrettext.String(password))
	}); err != nil {
		_ = conn.Close()
		return nil, errors.New("dynsecret ldap: administrator bind failed")
	}
	return conn, nil
}

// Create implements Backend.
func (b *LDAPBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend: a lease id makes the entry's
// name stable, so a retry after an uncertain issue replaces that one entry.
func (b *LDAPBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if b.reconcile != nil {
		return "", nil, errors.New("dynsecret AD: designated reset authority requires its exact sealed preparation")
	}
	if b.activeDirectory {
		return b.createADCredential(ctx, req)
	}
	if req.Static {
		account, ok := TwoUserAccount(b.rotationAccounts, req.Role, req.Predecessor)
		if !ok {
			return "", nil, fmt.Errorf("dynsecret ldap: role %q rotates only between two rotation_accounts", req.Role)
		}
		return b.stageTwoUser(ctx, account)
	}
	group, ok := b.roleGroups[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret ldap: role %q has no group", req.Role)
	}
	name, err := scopedNameForRequest(b.usernamePrefix, req, 64, "-")
	if err != nil {
		return "", nil, err
	}
	dn := "uid=" + ldap.EscapeDN(name) + "," + b.usersDN
	conn, err := b.connect(ctx)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = conn.Close() }()
	if req.LeaseID != "" {
		// An interrupted issue left this entry (or part of it); its password was
		// never delivered, so replace it.
		if err := b.remove(conn, dn); err != nil {
			return "", nil, err
		}
	}
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	add.Attribute("uid", []string{name})
	add.Attribute("cn", []string{name})
	add.Attribute("sn", []string{name})
	add.Attribute("description", []string{"trstctl dynamic lease"})
	if err := conn.Add(add); err != nil {
		return "", nil, errors.New("dynsecret ldap: create the entry failed")
	}
	password, err := randomSecretHex(24)
	if err != nil {
		_ = b.remove(conn, dn)
		return "", nil, err
	}
	defer secret.Wipe(password)
	// The directory hashes the password itself (RFC 3062); go-ldap takes it as a
	// string, converted at the call.
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", secrettext.String(password))); err != nil {
		_ = b.remove(conn, dn)
		return "", nil, errors.New("dynsecret ldap: set the password failed")
	}
	modify := ldap.NewModifyRequest(group, nil)
	modify.Add("member", []string{dn})
	if err := conn.Modify(modify); err != nil {
		_ = b.remove(conn, dn)
		return "", nil, fmt.Errorf("dynsecret ldap: add the entry to %s failed", group)
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the reveal-once LDAP lease credential; the caller seals it before storage (CWE-200)
		URL      string           `json:"url"`
		BindDN   string           `json:"bind_dn"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{URL: b.url, BindDN: dn, Username: name, Password: password})
	if err != nil {
		_ = b.remove(conn, dn)
		return "", nil, err
	}
	return dn, credential, nil
}

// stageTwoUser sets a new password on the role's inactive entry and returns
// its credential (A240). A retry sets the same entry's password again, so an
// uncertain attempt leaves no second credential; the predecessor is untouched.
func (b *LDAPBackend) stageTwoUser(ctx context.Context, dn string) (string, []byte, error) {
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	if err := b.setPassword(ctx, dn, password); err != nil {
		return "", nil, err
	}
	username := dn
	if parsed, err := ldap.ParseDN(dn); err == nil && len(parsed.RDNs) > 0 && len(parsed.RDNs[0].Attributes) > 0 {
		username = parsed.RDNs[0].Attributes[0].Value
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the staged two-user credential; the rotation seals it before storage (CWE-200)
		URL      string           `json:"url"`
		BindDN   string           `json:"bind_dn"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{URL: b.url, BindDN: dn, Username: username, Password: password})
	if err != nil {
		return "", nil, err
	}
	return dn, credential, nil
}

// retireTwoUser retires one entry of a pair without touching its group
// memberships: its password becomes one nobody holds, so the next bind with
// the old one is refused, and the next rotation that stages it sets one again.
func (b *LDAPBackend) retireTwoUser(ctx context.Context, dn string) error {
	scrambled, err := randomSecretHex(32)
	if err != nil {
		return err
	}
	defer secret.Wipe(scrambled)
	return b.setPassword(ctx, dn, scrambled)
}

// setPassword has the directory hash and store a new password for dn (RFC 3062).
func (b *LDAPBackend) setPassword(ctx context.Context, dn string, password []byte) error {
	conn, err := b.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	// go-ldap takes the password as a string, converted at the call.
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", secrettext.String(password))); err != nil {
		return fmt.Errorf("dynsecret ldap: set the password of %s failed", dn)
	}
	return nil
}

// VerifyCredential proves a credential binds: a fresh connection binds as its
// entry with its password.
func (b *LDAPBackend) VerifyCredential(ctx context.Context, credential []byte) error {
	if b.activeDirectory {
		return b.verifyADCredential(ctx, credential)
	}
	var parsed struct {
		BindDN   string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}
	if err := json.Unmarshal(credential, &parsed); err != nil || parsed.BindDN == "" || len(parsed.Password) == 0 {
		return errors.New("dynsecret ldap: the credential carries no bind DN and password")
	}
	defer secret.Wipe(parsed.Password)
	conn, err := b.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind(parsed.BindDN, secrettext.String(parsed.Password)); err != nil {
		return errors.New("dynsecret ldap: the credential does not bind")
	}
	return nil
}

// Revoke implements Backend: removing a gone entry succeeds; a two-user entry
// is retired, never removed.
func (b *LDAPBackend) Revoke(ctx context.Context, ref string) error {
	if b.reconcile != nil {
		return errors.New("dynsecret AD: designated reset authority requires its exact sealed preparation")
	}
	if b.activeDirectory {
		return b.retireADAccount(ctx, ref)
	}
	if b.isRotationAccount(ref) {
		return b.retireTwoUser(ctx, ref)
	}
	if _, err := ldap.ParseDN(ref); err != nil || !strings.HasSuffix(strings.ToLower(ref), ","+strings.ToLower(b.usersDN)) {
		return errors.New("dynsecret ldap: the lease reference is not an entry this provider created")
	}
	conn, err := b.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return b.remove(conn, ref)
}

// remove takes dn out of every role group and deletes it.
func (b *LDAPBackend) remove(conn ldapConn, dn string) error {
	for _, group := range b.roleGroups {
		modify := ldap.NewModifyRequest(group, nil)
		modify.Delete("member", []string{dn})
		if err := conn.Modify(modify); err != nil && !ldap.IsErrorAnyOf(err, ldap.LDAPResultNoSuchAttribute, ldap.LDAPResultNoSuchObject) {
			return fmt.Errorf("dynsecret ldap: remove the entry from %s failed", group)
		}
	}
	if err := conn.Del(ldap.NewDelRequest(dn, nil)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return errors.New("dynsecret ldap: delete the entry failed")
	}
	return nil
}

// Close wipes the administrator password.
func (b *LDAPBackend) Close() { b.bindPassword.Destroy() }
