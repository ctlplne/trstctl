// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func (b *LDAPBackend) adRoute() ldapbind.PinnedTLS {
	return ldapbind.PinnedTLS{Address: b.addr, ServerName: b.serverName, CAPEM: b.caPEM}
}
func (b *LDAPBackend) insideADContainer(dn string) bool {
	parsed, err := ldap.ParseDN(dn)
	base, e := ldap.ParseDN(b.usersDN)
	return err == nil && e == nil && base.AncestorOfFold(parsed)
}

func (b *LDAPBackend) ownsADAccount(dn string) bool {
	if !b.insideADContainer(dn) {
		return false
	}
	for _, known := range b.roleGroups {
		if strings.EqualFold(known, dn) {
			return true
		}
	}
	return b.isRotationAccount(dn)
}

// inspectADAccount never tries the target's password. Fail closed on incomplete
// state and any previous bad password; one DC's observation cannot prevent races.
type adNativeIdentity struct{ Name, GUID, SID, PasswordSetAt string }

func (b *LDAPBackend) inspectADAccount(ctx context.Context, dn string, forBind bool) (string, error) {
	value, err := b.inspectADIdentity(ctx, dn, forBind, false)
	return value.Name, err
}
func (b *LDAPBackend) inspectADIdentity(ctx context.Context, dn string, forBind, requireIdentity bool) (adNativeIdentity, error) {
	if !b.ownsADAccount(dn) {
		return adNativeIdentity{}, errors.New("dynsecret AD: account is outside the configured role bindings")
	}
	var identity adNativeIdentity
	err := b.bindPassword.Use(func(admin []byte) error {
		raw, err := ldapbind.DialPinned(ctx, b.adRoute(), b.bindDN, admin)
		if err != nil {
			return err
		}
		conn := ldap.NewConn(raw, true)
		conn.SetTimeout(5 * time.Second)
		conn.Start()
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		defer stop()
		result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(&(objectClass=user)(!(objectClass=computer)))", []string{"sAMAccountName", "userAccountControl", "msDS-User-Account-Control-Computed", "badPwdCount", "pwdLastSet", "accountExpires", "objectGUID", "objectSid"}, nil))
		if err != nil || len(result.Entries) != 1 {
			return errors.New("dynsecret AD: cannot read the exact account state")
		}
		entry := result.Entries[0]
		identity.Name, err = validateADAccountState(entry, forBind, time.Now())
		if err != nil {
			return err
		}
		identity.PasswordSetAt = entry.GetAttributeValue("pwdLastSet")
		guid, sid := entry.GetRawAttributeValue("objectGUID"), entry.GetRawAttributeValue("objectSid")
		if requireIdentity && (len(guid) != 16 || len(sid) < 8 || len(sid) > 68) {
			return errors.New("dynsecret AD: native account GUID/SID is unavailable")
		}
		identity.GUID = hex.EncodeToString(guid)
		identity.SID = hex.EncodeToString(sid)
		return err
	})
	return identity, err
}
func (b *LDAPBackend) createADCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if !req.Static {
		return "", nil, errors.New("dynsecret AD: only existing vaulted accounts can be rotated")
	}
	dn, ok := b.roleGroups[req.Role]
	if !ok {
		return "", nil, errors.New("dynsecret AD: role is not configured")
	}
	if _, paired := b.rotationAccounts[req.Role]; paired {
		dn, ok = TwoUserAccount(b.rotationAccounts, req.Role, req.Predecessor)
		if !ok {
			return "", nil, errors.New("dynsecret AD: invalid predecessor account")
		}
	} else if req.Predecessor != "" && !strings.EqualFold(req.Predecessor, dn) {
		return "", nil, errors.New("dynsecret AD: predecessor changed the bound account")
	}
	name, err := b.inspectADAccount(ctx, dn, false)
	if err != nil {
		return "", nil, err
	}
	random, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(random)
	password, err := secret.New(4 + len(random))
	if err != nil {
		return "", nil, err
	}
	defer password.Destroy()
	copy(password.Bytes(), []byte("Tr5!"))
	copy(password.Bytes()[4:], random)
	if err = b.resetADPassword(ctx, dn, password.Bytes()); err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(struct {
		URL      string           `json:"url"`
		BindDN   string           `json:"bind_dn"`
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
	}{URL: b.url, BindDN: dn, Username: name, Password: password.Bytes()}) // #nosec G117 -- byte-backed rotated credential is sealed by the existing outbox rotation worker (CWE-200)
	return dn, raw, err
}
func (b *LDAPBackend) verifyADCredential(ctx context.Context, raw []byte) error {
	var c struct {
		BindDN   string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}
	defer func() { secret.Wipe(c.Password) }()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &c) != nil || len(c.Password) == 0 || len(c.Password) > 1024 {
		return errors.New("dynsecret AD: invalid credential")
	}
	if _, err := b.inspectADAccount(ctx, c.BindDN, true); err != nil {
		return err
	}
	conn, err := ldapbind.DialPinned(ctx, b.adRoute(), c.BindDN, c.Password)
	if err != nil {
		return err
	}
	return conn.Close()
}
func (b *LDAPBackend) retireADAccount(ctx context.Context, dn string) error {
	// A single-account predecessor was already replaced during the in-place
	// rotation. Resetting that same principal here would destroy the successor.
	if !b.isRotationAccount(dn) {
		if !b.ownsADAccount(dn) {
			return errors.New("dynsecret AD: refusing retirement of an unbound account")
		}
		return nil
	}

	if _, err := b.inspectADAccount(ctx, dn, false); err != nil {
		return err
	}
	random, err := randomSecretHex(32)
	if err != nil {
		return err
	}
	defer secret.Wipe(random)
	password, err := secret.New(4 + len(random))
	if err != nil {
		return err
	}
	defer password.Destroy()
	copy(password.Bytes(), []byte("Tr5!"))
	copy(password.Bytes()[4:], random)
	return b.resetADPassword(ctx, dn, password.Bytes())
}

// AD may accept the immediately preceding password during its native grace
// period. Make that predecessor an undisclosed random credential, then install
// the final credential. Both writes are part of the existing rotation operation;
// an uncertain reset is an error, never a claim that the old password still works.
func (b *LDAPBackend) resetADPassword(ctx context.Context, dn string, final []byte) error {
	random, err := randomSecretHex(32)
	if err != nil {
		return err
	}
	defer secret.Wipe(random)
	intermediate, err := secret.New(4 + len(random))
	if err != nil {
		return err
	}
	defer intermediate.Destroy()
	copy(intermediate.Bytes(), []byte("Tr5!"))
	copy(intermediate.Bytes()[4:], random)
	return b.bindPassword.Use(func(admin []byte) error {
		if err := ldapbind.ResetADPassword(ctx, b.adRoute(), b.bindDN, admin, dn, intermediate.Bytes()); err != nil {
			return err
		}
		return ldapbind.ResetADPassword(ctx, b.adRoute(), b.bindDN, admin, dn, final)
	})
}

func validateADAccountState(entry *ldap.Entry, forBind bool, now time.Time) (string, error) {
	name := entry.GetAttributeValue("sAMAccountName")
	if len(name) == 0 || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return "", errors.New("dynsecret AD: invalid logon name")
	}
	number := func(attribute string, missing bool) (uint64, error) {
		v := entry.GetAttributeValues(attribute)
		if len(v) == 0 && missing {
			return 0, nil
		}
		if len(v) != 1 {
			return 0, errors.New("missing account state")
		}
		return strconv.ParseUint(v[0], 10, 64)
	}
	uac, e := number("userAccountControl", false)
	computed, ce := number("msDS-User-Account-Control-Computed", false)
	bad, be := number("badPwdCount", false)
	pwd, pe := number("pwdLastSet", false)
	expiry, ee := number("accountExpires", true)
	if e != nil || ce != nil || be != nil || pe != nil || ee != nil || uac&2 != 0 || computed&16 != 0 || bad != 0 {
		return "", errors.New("dynsecret AD: account state is unsafe for a password operation; no user bind attempted")
	}
	// accountExpires is Windows FILETIME; zero and max int64 mean no expiry.
	const epoch = uint64(116444736000000000)
	unix := now.Unix()
	if unix < 0 || unix > 253402300799 {
		return "", errors.New("dynsecret AD: invalid observation time")
	}
	at := uint64(unix)*10000000 + epoch
	if expiry > 9223372036854775807 || (expiry != 0 && expiry != 9223372036854775807 && expiry <= at) {
		return "", errors.New("dynsecret AD: account expired")
	}
	if forBind && (pwd == 0 || computed&8388608 != 0) {
		return "", errors.New("dynsecret AD: password expired; no user bind attempted")
	}
	return name, nil
}

// validateADBindings prevents one role's rotation from changing another role's
// live principal, including a pair's inactive member and equivalent DN spellings.
func (b *LDAPBackend) validateADBindings() error {
	if len(b.roleGroups) > 256 || len(b.rotationAccounts) > 256 {
		return errors.New("dynsecret AD: account binding count exceeds 256 roles")
	}
	type owned struct{ dn *ldap.DN }
	var accounts []owned
	for role, binding := range b.roleGroups {
		names := []string{binding}
		if pair, ok := b.rotationAccounts[role]; ok {
			bound, e := ldap.ParseDN(binding)
			first, fe := ldap.ParseDN(pair[0])
			second, se := ldap.ParseDN(pair[1])
			if e != nil || fe != nil || se != nil || (!bound.EqualFold(first) && !bound.EqualFold(second)) {
				return errors.New("dynsecret AD: role binding must name one of its two rotation accounts")
			}
			names = []string{pair[0], pair[1]}
		}
		for _, dn := range names {
			parsed, e := ldap.ParseDN(dn)
			if e != nil || len(dn) > 4096 || !b.insideADContainer(dn) {
				return errors.New("dynsecret AD: invalid bound account DN")
			}
			for _, previous := range accounts {
				if parsed.EqualFold(previous.dn) {
					return errors.New("dynsecret AD: an account serves more than one role or pair slot")
				}
			}
			accounts = append(accounts, owned{dn: parsed})
		}
	}
	return nil
}
