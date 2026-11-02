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
	// (groupOfNames) whose members get that role's authority.
	RoleGroups     map[string]string
	UsernamePrefix string
}

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
	url            string
	addr           string
	tls            bool
	serverName     string
	caPEM          []byte
	bindDN         string
	bindPassword   *secret.Buffer
	usersDN        string
	roleGroups     map[string]string
	usernamePrefix string
	dial           func(ctx context.Context) (ldapConn, error)
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
		b.roleGroups[role] = group
	}
	if len(b.roleGroups) == 0 {
		return nil, errors.New("dynsecret ldap: every allowed role needs a group in role_bindings")
	}
	password, err := secret.NewFrom(cfg.BindPassword)
	if err != nil {
		return nil, err
	}
	b.bindPassword = password
	b.dial = b.dialDirectory
	return b, nil
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
	if req.Static {
		return "", nil, errors.New("dynsecret ldap: static credentials are not served")
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

// Revoke implements Backend: removing a gone entry succeeds.
func (b *LDAPBackend) Revoke(ctx context.Context, ref string) error {
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
