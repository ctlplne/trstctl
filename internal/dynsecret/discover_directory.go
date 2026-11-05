// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/pamdiscovery"
)

// A260 part 2: Active Directory discovery through the LDAP provider (A239).
// The provider's bind account reads, never writes: the members, transitive
// through nested groups, of the groups that administer a domain, and every
// user AD marks protected (adminCount=1). Passwords are never read.

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
// disabled.
func (b *LDAPBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	base := domainDN(b.usersDN)
	if base == "" {
		return nil, ErrDiscoveryNotSupported
	}
	conn, err := b.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	search, ok := conn.(ldapSearcher)
	if !ok {
		return nil, ErrDiscoveryNotSupported
	}
	attributes := []string{"sAMAccountName", "userAccountControl", "adminCount", "distinguishedName"}
	find := func(filter string) ([]*ldap.Entry, error) {
		result, err := search.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, pamdiscovery.MaxAccounts+1, 60, false,
			filter, attributes, nil))
		if err != nil {
			return nil, err
		}
		return result.Entries, nil
	}
	byName := map[string]*pamdiscovery.Account{}
	var order []string
	add := func(entry *ldap.Entry, privilege string) {
		name := entry.GetAttributeValue("sAMAccountName")
		if name == "" || (b.usernamePrefix != "" && strings.HasPrefix(name, b.usernamePrefix)) {
			return
		}
		a := byName[name]
		if a == nil {
			uac, _ := strconv.Atoi(entry.GetAttributeValue("userAccountControl"))
			a = &pamdiscovery.Account{Key: "user:" + strings.ToLower(name), Name: name, Kind: pamdiscovery.KindDirectoryUser,
				Disabled: uac&2 != 0, Details: map[string]string{"dn": entry.DN}}
			byName[name] = a
			order = append(order, name)
		}
		a.Privileges = append(a.Privileges, privilege)
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
			add(m, "group:"+name)
		}
	}
	protected, err := find("(&(objectCategory=person)(objectClass=user)(adminCount=1))")
	if err != nil {
		return nil, err
	}
	for _, m := range protected {
		add(m, "admincount")
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
