// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/crypto/ldapbind"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A258-L1: a vaulted Active Directory account's credential check that never
// signs in when a refused password would lock the account.
//
// The provider's administrator reads, at one domain controller, the account's
// state and its failed sign-ins (badPwdCount, which domain controllers keep
// each for themselves) and the lockout threshold that applies to it: the
// msDS-LockoutThreshold of the password settings object its
// msDS-ResultantPSO names, else the domain's lockoutThreshold (0 is no
// lockout). A disabled, locked or expired account is classified from that
// state alone. Otherwise the check signs in with the vaulted password, at the
// same domain controller, only when a refusal would leave the account below
// its threshold; one short of it reads lockout_risk and nothing is sent. The
// rotation's proof uses the same DC-pinned threshold check. An administrator
// can reset a password regardless of the counter, but a proof bind may occur
// only when one more failed bind would still leave a safety margin.

// adSignInState is what the check reads before it signs in.
type adSignInState struct {
	uac, computed, bad, pwdLastSet, expires, threshold uint64
}

// CheckADAccountSignIn checks the vaulted credential of an account the
// provider rotates (its bind DN and password, as the rotation vaults them).
func (b *LDAPBackend) CheckADAccountSignIn(ctx context.Context, credential []byte) error {
	if !b.activeDirectory {
		return errors.New("dynsecret ldap: only an Active Directory provider checks its accounts' sign-in")
	}
	var c struct {
		BindDN   string           `json:"bind_dn"`
		Password secret.JSONBytes `json:"password"`
	}
	defer func() { secret.Wipe(c.Password) }()
	if len(credential) > 64<<10 || json.Unmarshal(credential, &c) != nil || c.BindDN == "" || len(c.Password) == 0 || len(c.Password) > 1024 {
		return errors.New("dynsecret AD: the vaulted credential carries no bind DN and password")
	}
	if !b.ownsADAccount(c.BindDN) {
		return errors.New("dynsecret AD: the vaulted account is outside the configured role bindings")
	}
	route, err := b.adSignInRoute(ctx)
	if err != nil {
		return err
	}
	return b.proveADPassword(ctx, route, c.BindDN, c.Password)
}

func (b *LDAPBackend) proveADPassword(ctx context.Context, route ldapbind.PinnedTLS, dn string, password []byte) error {
	if !b.ownsADAccount(dn) {
		return errors.New("dynsecret AD: the vaulted account is outside the configured role bindings")
	}
	state, err := b.readADSignInState(ctx, route, dn)
	if err != nil {
		return err
	}
	if err := state.refusal(time.Now()); err != nil {
		return err
	}
	conn, err := ldapbind.DialPinned(ctx, route, dn, password)
	if err != nil {
		return classifyADSignIn(err)
	}
	return conn.Close()
}

// adSignInRoute pins one domain controller: a name is resolved once, so the
// state read and the sign-in reach the same one, whose count the read saw.
func (b *LDAPBackend) adSignInRoute(ctx context.Context) (ldapbind.PinnedTLS, error) {
	route := b.adRoute()
	host, port, err := net.SplitHostPort(route.Address)
	if err != nil {
		return route, err
	}
	if net.ParseIP(host) != nil {
		return route, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return route, withSignInClass(ErrSignInUnreachable, errors.New("dynsecret AD: the domain controller's name does not resolve"))
	}
	route.Address = net.JoinHostPort(addrs[0].IP.String(), port)
	return route, nil
}

// readADSignInState reads the account and its lockout threshold as the
// provider's administrator.
func (b *LDAPBackend) readADSignInState(ctx context.Context, route ldapbind.PinnedTLS, dn string) (adSignInState, error) {
	var state adSignInState
	err := b.bindPassword.Use(func(admin []byte) error {
		raw, err := ldapbind.DialPinned(ctx, route, b.bindDN, admin)
		if errors.Is(err, ldapbind.ErrConnect) {
			return withSignInClass(ErrSignInUnreachable, err)
		}
		if err != nil {
			return errors.New("dynsecret AD: the provider's administrator could not sign in to read the account")
		}
		conn := ldap.NewConn(raw, true)
		conn.SetTimeout(5 * time.Second)
		conn.Start()
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		defer stop()
		entry, err := adBaseEntry(conn, dn, "(&(objectClass=user)(!(objectClass=computer)))", "sAMAccountName", "userAccountControl", "msDS-User-Account-Control-Computed", "badPwdCount", "pwdLastSet", "accountExpires", "msDS-ResultantPSO")
		if err != nil {
			return errors.New("dynsecret AD: cannot read the exact account state")
		}
		names := entry.GetAttributeValues("sAMAccountName")
		if len(names) != 1 || len(names[0]) == 0 || len(names[0]) > 128 || strings.ContainsAny(names[0], "\x00\r\n") {
			return errors.New("dynsecret AD: invalid logon name; no user bind attempted")
		}
		for _, field := range []struct {
			name string
			into *uint64
			zero bool
		}{
			{"userAccountControl", &state.uac, false}, {"msDS-User-Account-Control-Computed", &state.computed, false},
			{"badPwdCount", &state.bad, false}, {"pwdLastSet", &state.pwdLastSet, false}, {"accountExpires", &state.expires, true},
		} {
			if *field.into, err = adNumber(entry, field.name, field.zero); err != nil {
				return errors.New("dynsecret AD: cannot read the exact account state")
			}
		}
		if pso := entry.GetAttributeValue("msDS-ResultantPSO"); pso != "" {
			settings, err := adBaseEntry(conn, pso, "(objectClass=msDS-PasswordSettings)", "msDS-LockoutThreshold")
			if err == nil {
				state.threshold, err = adNumber(settings, "msDS-LockoutThreshold", false)
			}
			if err != nil {
				return errors.New("dynsecret AD: cannot read the lockout threshold of the account's password settings")
			}
			return nil
		}
		root, err := adBaseEntry(conn, "", "(objectClass=*)", "defaultNamingContext")
		if err != nil || root.GetAttributeValue("defaultNamingContext") == "" {
			return errors.New("dynsecret AD: cannot read the domain's naming context")
		}
		domain, err := adBaseEntry(conn, root.GetAttributeValue("defaultNamingContext"), "(objectClass=*)", "lockoutThreshold")
		if err == nil {
			state.threshold, err = adNumber(domain, "lockoutThreshold", false)
		}
		if err != nil {
			return errors.New("dynsecret AD: cannot read the domain's lockout threshold")
		}
		return nil
	})
	return state, err
}

// refusal is the class of an account its state already refuses, or of one a
// refused password would lock; nil when the check may sign in.
func (s adSignInState) refusal(now time.Time) error {
	const (
		accountDisable  = 0x2      // userAccountControl ACCOUNTDISABLE
		lockout         = 0x10     // msDS-User-Account-Control-Computed UF_LOCKOUT
		passwordExpired = 0x800000 // msDS-User-Account-Control-Computed UF_PASSWORD_EXPIRED
	)
	switch {
	case s.uac&accountDisable != 0:
		return withSignInClass(ErrSignInRejected, errors.New("dynsecret AD: the account is disabled; no sign-in attempted"))
	case s.computed&lockout != 0:
		return withSignInClass(ErrSignInLocked, errors.New("dynsecret AD: the account is locked; no sign-in attempted"))
	case adExpired(s.expires, now):
		return withSignInClass(ErrSignInExpired, errors.New("dynsecret AD: the account has expired; no sign-in attempted"))
	case s.pwdLastSet == 0 || s.computed&passwordExpired != 0:
		return withSignInClass(ErrSignInExpired, errors.New("dynsecret AD: the password has expired or must change; no sign-in attempted"))
	case s.threshold > 0 && s.bad >= s.threshold-1:
		return withSignInClass(ErrSignInLockoutRisk, fmt.Errorf("dynsecret AD: %d of the account's %d failed sign-ins before lockout; no sign-in attempted", s.bad, s.threshold))
	}
	return nil
}

// adExpired reads accountExpires, a Windows FILETIME where 0 and the largest
// int64 mean never.
func adExpired(expires uint64, now time.Time) bool {
	const epoch = uint64(116444736000000000)
	if expires == 0 || expires >= 9223372036854775807 {
		return false
	}
	unix := now.Unix()
	if unix < 0 || unix > 253402300799 {
		return true
	}
	return expires <= uint64(unix)*10000000+epoch // #nosec G115 -- unix is within year 1970..9999, so the FILETIME fits (CWE-190)
}

// classifyADSignIn is the class of a refused sign-in by Active Directory's
// sub-status (Microsoft's LDAP error reference): 52e a wrong password, 525 no
// such account, 533 disabled, 775 locked, 532 an expired password, 773 one
// that must change, 701 an expired account; 530 and 531 refuse the time or
// the workstation, not the password.
func classifyADSignIn(err error) error {
	var refusal *ldapbind.RefusalError
	switch {
	case errors.Is(err, ldapbind.ErrConnect):
		return withSignInClass(ErrSignInUnreachable, err)
	case errors.As(err, &refusal) && refusal.Result == 49:
		switch refusal.ADData {
		case 0x775:
			return ErrSignInLocked
		case 0x532, 0x773, 0x701:
			return ErrSignInExpired
		case 0x530, 0x531:
			return fmt.Errorf("dynsecret AD: the sign-in was refused for its time or place (%x)", refusal.ADData)
		}
		return ErrSignInRejected
	case errors.As(err, &refusal):
		return fmt.Errorf("dynsecret AD: the sign-in was refused with result %d", refusal.Result)
	}
	if class := classifyNetwork(err); class != nil {
		return class
	}
	return errors.New("dynsecret AD: the sign-in failed")
}

func adBaseEntry(conn *ldap.Conn, dn, filter string, attributes ...string) (*ldap.Entry, error) {
	result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, filter, attributes, nil))
	if err != nil {
		return nil, err
	}
	if len(result.Entries) != 1 {
		return nil, errors.New("dynsecret AD: not exactly one entry")
	}
	return result.Entries[0], nil
}

func adNumber(entry *ldap.Entry, attribute string, missingIsZero bool) (uint64, error) {
	values := entry.GetAttributeValues(attribute)
	if len(values) == 0 && missingIsZero {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, errors.New("dynsecret AD: missing account state")
	}
	return strconv.ParseUint(values[0], 10, 64)
}
