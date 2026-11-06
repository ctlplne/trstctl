// SPDX-License-Identifier: BUSL-1.1
package dynsecret

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"net/netip"
	"strconv"
	"time"
	"trstctl.com/trstctl/internal/crypto/ldapbind"
)

// This is a progress discriminator on one exact DC, not an atomic native
// compare-and-swap. A reset controller must still prove its one version-selected
// credential and refuse unrelated native progress before another effect.
type adNativeResetIdentity struct {
	adNativeIdentity
	KeyVersion                    uint64
	DCInvocationID, NativeAddress string
}

func (b *LDAPBackend) inspectADResetIdentity(ctx context.Context, dn string, route ldapbind.PinnedTLS, forBind ...bool) (adNativeResetIdentity, error) {
	var identity adNativeResetIdentity
	if !b.activeDirectory || !b.ownsADAccount(dn) {
		return identity, errors.New("dynsecret AD: reset progress is outside configured native authority")
	}
	err := b.bindPassword.Use(func(admin []byte) error {
		raw, e := ldapbind.DialPinned(ctx, route, b.bindDN, admin)
		if e != nil {
			return e
		}
		peer, e := netip.ParseAddrPort(raw.RemoteAddr().String())
		if e != nil || !peer.IsValid() || peer.Port() == 0 {
			_ = raw.Close()
			return errors.New("dynsecret AD: native reset route is not a literal peer address")
		}
		identity.NativeAddress = peer.String()
		conn := ldap.NewConn(raw, true)
		conn.SetTimeout(5 * time.Second)
		conn.Start()
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		defer stop()
		read := func(base, filter string, attributes []string) (*ldap.Entry, error) {
			if len(base) > 4096 {
				return nil, errors.New("dynsecret AD: native progress metadata DN exceeds bound")
			}
			result, e := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, filter, attributes, nil))
			if e != nil || len(result.Entries) != 1 {
				return nil, errors.New("dynsecret AD: exact native progress metadata is unavailable")
			}
			return result.Entries[0], nil
		}
		entry, e := read(dn, "(&(objectClass=user)(!(objectClass=computer)))", []string{"sAMAccountName", "userAccountControl", "msDS-User-Account-Control-Computed", "badPwdCount", "pwdLastSet", "accountExpires", "objectGUID", "objectSid", "msDS-KeyVersionNumber"})
		if e != nil {
			return e
		}
		identity.Name, e = validateADAccountState(entry, len(forBind) > 0 && forBind[0], time.Now())
		if e != nil {
			return e
		}
		guid, sid := entry.GetRawAttributeValue("objectGUID"), entry.GetRawAttributeValue("objectSid")
		if len(guid) != 16 || len(sid) < 8 || len(sid) > 68 {
			return errors.New("dynsecret AD: exact native progress identity is unavailable")
		}
		identity.GUID = hex.EncodeToString(guid)
		identity.SID = hex.EncodeToString(sid)
		identity.PasswordSetAt = entry.GetAttributeValue("pwdLastSet")
		versions := entry.GetAttributeValues("msDS-KeyVersionNumber")
		if len(versions) != 1 {
			return errors.New("dynsecret AD: native password attribute version is unavailable")
		}
		identity.KeyVersion, e = strconv.ParseUint(versions[0], 10, 32)
		if e != nil || identity.KeyVersion < 1 || strconv.FormatUint(identity.KeyVersion, 10) != versions[0] {
			return errors.New("dynsecret AD: native password attribute version is invalid")
		}
		root, e := read("", "(objectClass=*)", []string{"configurationNamingContext", "dsServiceName"})
		if e != nil {
			return e
		}
		configuration, service := root.GetAttributeValue("configurationNamingContext"), root.GetAttributeValue("dsServiceName")
		if configuration == "" || service == "" {
			return errors.New("dynsecret AD: exact DC configuration authority is unavailable")
		}
		if _, e = ldap.ParseDN(configuration); e != nil {
			return errors.New("dynsecret AD: native configuration DN is invalid")
		}
		if _, e = ldap.ParseDN(service); e != nil {
			return errors.New("dynsecret AD: native DC service DN is invalid")
		}
		settings, e := read("CN=Directory Service,CN=Windows NT,CN=Services,"+configuration, "(objectClass=*)", []string{"dSHeuristics"})
		if e != nil {
			return e
		}
		heuristics := settings.GetAttributeValues("dSHeuristics")
		if len(heuristics) > 1 {
			return errors.New("dynsecret AD: native version heuristic is ambiguous")
		}
		if len(heuristics) == 1 {
			if len(heuristics[0]) > 4096 {
				return errors.New("dynsecret AD: native version heuristic exceeds bound")
			}
			characters := []rune(heuristics[0])
			// MS-ADTS 6.1.1.2.4.1.2, character17: a nonzero fKVNOEmuW2K
			// makes msDS-KeyVersionNumber constant1, so it cannot identify reset progress.
			if len(characters) >= 17 && characters[16] != '0' {
				return errors.New("dynsecret AD: native key-version emulation cannot qualify durable reset progress")
			}
		}
		dc, e := read(service, "(objectClass=*)", []string{"invocationId"})
		if e != nil {
			return e
		}
		invocation := dc.GetRawAttributeValue("invocationId")
		if len(invocation) != 16 {
			return errors.New("dynsecret AD: native DC invocation identity is unavailable")
		}
		identity.DCInvocationID = hex.EncodeToString(invocation)
		return nil
	})
	return identity, err
}

// Exactly one native-version-selected generation may be proved. In particular,
// a retry never tries successive password candidates until one binds. The
// native version is not a replacement for proving that selected generation.
func (p adStaticPreparation) resetPosition(current adNativeResetIdentity) (uint8, error) {
	if p.Version != 2 || p.KeyVersion < 1 || p.KeyVersion > uint64(1<<32-1)-4 || current.KeyVersion < p.KeyVersion || current.KeyVersion > p.KeyVersion+4 || current.DCInvocationID != p.DCInvocationID || current.NativeAddress != p.NativeAddress || current.GUID != p.GUID || current.SID != p.SID || current.Name != p.Name || current.PasswordSetAt == "" {
		return 0, errors.New("dynsecret AD: current native progress differs from the frozen reset authority")
	}
	position := uint8((current.KeyVersion - p.KeyVersion) & 0xff) // The checks above bound this offset to0..4.
	if position == 0 && current.PasswordSetAt != p.PasswordSetAt || position > 0 && (current.PasswordSetAt == p.PasswordSetAt || current.PasswordSetAt == "0") {
		return 0, errors.New("dynsecret AD: native password stamp and version disagree")
	}
	return position, nil
}
