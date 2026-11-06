// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto/ldapbind"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/pamdiscovery"
)

// A260 part 2: Active Directory discovery through the LDAP provider (A239).
// The provider's bind account reads, never writes: the members, transitive
// through nested groups, of the groups that administer a domain, and every
// user AD marks protected (adminCount=1). Explicit AD mode also selects SPN and
// configured rotation accounts, without inventing administrative rights.
// Passwords are never read.

// adPrivilegedGroups are the groups that administer an Active Directory
// domain, by their names in the Users and Builtin containers.
var adPrivilegedGroups = []string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators",
	"Backup Operators", "Server Operators", "Print Operators", "DnsAdmins", "Group Policy Creator Owners"}

// adInChain is LDAP_MATCHING_RULE_IN_CHAIN: membership through nested groups.
const adInChain = "1.2.840.113556.1.4.1941"

type ldapSearcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

// domainDN is the DC= suffix of a DN: the domain the users container is in.
func domainDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, part := range parts {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(part)), "DC=") {
			return strings.Join(parts[i:], ",")
		}
	}
	return ""
}

// DiscoverPrivilegedAccounts lists the directory's privileged users: transitive
// members of the groups that administer the domain, and users with
// adminCount=1. A disabled account (userAccountControl bit 2) is marked
// disabled. Explicit active_directory mode also includes service identities under
// UsersDN (SPN-bearing or configured rotation accounts), with native SID/GUID.
func (b *LDAPBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	base := domainDN(b.usersDN)
	if base == "" {
		return nil, ErrDiscoveryNotSupported
	}
	var conn ldapConn
	var err error
	if b.activeDirectory {
		// AD discovery uses the same locked byte-backed pinned bind as rotation.
		err = b.bindPassword.Use(func(admin []byte) error {
			raw, err := ldapbind.DialPinned(ctx, b.adRoute(), b.bindDN, admin)
			if err != nil {
				return err
			}
			native := ldap.NewConn(raw, true)
			native.SetTimeout(10 * time.Second)
			native.Start()
			conn = native
			return nil
		})
	} else {
		conn, err = b.connect(ctx)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	search, ok := conn.(ldapSearcher)
	if !ok {
		return nil, ErrDiscoveryNotSupported
	}
	return b.discoverDirectoryAccounts(ctx, search)
}

func (b *LDAPBackend) discoverDirectoryAccounts(ctx context.Context, search ldapSearcher) ([]pamdiscovery.Account, error) {
	base := domainDN(b.usersDN)
	if base == "" {
		return nil, ErrDiscoveryNotSupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	attributes := []string{"sAMAccountName", "userAccountControl", "adminCount", "distinguishedName"}
	if b.activeDirectory {
		attributes = append(attributes, "objectGUID", "objectSid", "servicePrincipalName", "objectClass")
	}
	findScoped := func(root string, scope int, filter string) ([]*ldap.Entry, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var controls []ldap.Control
		if b.activeDirectory {
			controls = []ldap.Control{&ldap.ControlString{ControlType: "1.2.840.113556.1.4.1339", Criticality: true}}
		}
		request := ldap.NewSearchRequest(root, scope, ldap.NeverDerefAliases, pamdiscovery.MaxAccounts+1, 60, false, filter, attributes, controls)
		request.EnforceSizeLimit = true
		result, err := search.Search(request)
		if err != nil {
			return nil, err
		}
		if result == nil || len(result.Referrals) != 0 {
			return nil, errors.New("dynsecret ldap: discovery referrals or missing result refused")
		}
		if len(result.Entries) > pamdiscovery.MaxAccounts {
			return nil, errors.New("dynsecret ldap: directory discovery exceeds account bound")
		}
		rootDN, err := ldap.ParseDN(root)
		if err != nil {
			return nil, errors.New("dynsecret AD: invalid discovery container")
		}
		for _, entry := range result.Entries {
			if entry == nil {
				return nil, errors.New("dynsecret AD: missing native directory entry")
			}
			dn, err := ldap.ParseDN(entry.DN)
			if err != nil || (!rootDN.EqualFold(dn) && (scope == ldap.ScopeBaseObject || !rootDN.AncestorOfFold(dn))) {
				return nil, errors.New("dynsecret AD: entry escaped exact discovery scope")
			}
		}
		return result.Entries, nil
	}
	find := func(filter string) ([]*ldap.Entry, error) { return findScoped(base, ldap.ScopeWholeSubtree, filter) }
	byName := map[string]*pamdiscovery.Account{}
	var order []string
	add := func(entry *ldap.Entry, privilege string, service bool) error {
		name := entry.GetAttributeValue("sAMAccountName")
		if name == "" {
			if b.activeDirectory {
				return errors.New("dynsecret AD: account name unavailable")
			}
			return nil
		}
		if !b.activeDirectory && b.usernamePrefix != "" && strings.HasPrefix(name, b.usernamePrefix) {
			return nil
		}
		key := strings.ToLower(name)
		a := byName[key]
		if a == nil {
			if len(byName) >= pamdiscovery.MaxAccounts {
				return errors.New("dynsecret AD: directory account union exceeds bound")
			}
			uac, _ := strconv.Atoi(entry.GetAttributeValue("userAccountControl"))
			a = &pamdiscovery.Account{Key: "user:" + strings.ToLower(name), Name: name, Kind: pamdiscovery.KindDirectoryUser,
				Disabled: uac&2 != 0, Details: map[string]string{"dn": entry.DN}}
			byName[key] = a
			order = append(order, key)
		}
		if b.activeDirectory {
			if err := addADDiscoveryIdentity(a, entry, service); err != nil {
				return err
			}
		} else if a.Details["dn"] != entry.DN {
			return errors.New("dynsecret ldap: duplicate account identity differs")
		}
		if privilege != "" {
			a.Privileges = append(a.Privileges, privilege)
		}
		return nil
	}
	groups, err := find("(&(objectClass=group)(|" + func() string {
		var b strings.Builder
		for _, g := range adPrivilegedGroups {
			b.WriteString("(cn=" + ldap.EscapeFilter(g) + ")")
		}
		return b.String()
	}() + "))")
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		name := group.GetAttributeValue("sAMAccountName")
		if name == "" {
			name = strings.TrimPrefix(strings.SplitN(group.DN, ",", 2)[0], "CN=")
		}
		members, err := find("(&(objectCategory=person)(objectClass=user)(memberOf:" + adInChain + ":=" + ldap.EscapeFilter(group.DN) + "))")
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			if err := add(m, "group:"+name, false); err != nil {
				return nil, err
			}
		}
	}
	protected, err := find("(&(objectCategory=person)(objectClass=user)(adminCount=1))")
	if err != nil {
		return nil, err
	}
	for _, m := range protected {
		if err := add(m, "admincount", false); err != nil {
			return nil, err
		}
	}
	if b.activeDirectory {
		services, err := findScoped(b.usersDN, ldap.ScopeWholeSubtree, "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*))")
		if err != nil {
			return nil, err
		}
		for _, entry := range services {
			if err := add(entry, "", true); err != nil {
				return nil, err
			}
		}
		selected := map[string]bool{}
		for _, dn := range b.roleGroups {
			selected[dn] = true
		}
		for _, pair := range b.rotationAccounts {
			selected[pair[0]] = true
			selected[pair[1]] = true
		}
		if len(selected) > 256 {
			return nil, errors.New("dynsecret AD: configured discovery account bound exceeded")
		}
		var names []string
		for dn := range selected {
			names = append(names, dn)
		}
		sort.Strings(names)
		for _, dn := range names {
			if !b.underUsersDN(dn) {
				return nil, errors.New("dynsecret AD: configured discovery account is outside selected container")
			}
			entries, err := findScoped(dn, ldap.ScopeBaseObject, "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))")
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if err := add(entry, "", true); err != nil {
					return nil, err
				}
				byName[strings.ToLower(entry.GetAttributeValue("sAMAccountName"))].Details["configured_rotation_account"] = "true"
			}
		}
	}
	if len(order) > pamdiscovery.MaxAccounts {
		return nil, errors.New("dynsecret ldap: more privileged users than one discovery holds")
	}
	accounts := make([]pamdiscovery.Account, 0, len(order))
	for _, name := range order {
		accounts = append(accounts, *byName[name])
	}
	return pamdiscovery.Normalize(accounts), nil
}
