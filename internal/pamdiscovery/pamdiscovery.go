// SPDX-License-Identifier: BUSL-1.1

// Package pamdiscovery decides which accounts a read-only scan found are
// privileged, and why (A260). It runs nothing: the dynamic-secret providers
// read their hosts and databases through their administrator connections and
// hand the results here. A finding names the account, the privileges that
// make it privileged and whether it is disabled; the account's credential is
// never read.
package pamdiscovery

import (
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Account kinds.
const (
	KindLocalUser     = "local_user"
	KindDatabaseRole  = "database_role"
	KindDatabaseUser  = "database_user"
	KindSQLLogin      = "sql_login"
	KindDirectoryUser = "directory_user"
)

// MaxAccounts bounds one scan's findings.
const MaxAccounts = 5000

// Account is one privileged account a scan found.
type Account struct {
	// Key identifies the account within its source across scans.
	Key        string            `json:"key"`
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Privileges []string          `json:"privileges"`
	Disabled   bool              `json:"disabled,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
}

// Equal reports whether a and b describe the account the same way.
func (a Account) Equal(b Account) bool {
	if a.Key != b.Key || a.Name != b.Name || a.Kind != b.Kind || a.Disabled != b.Disabled ||
		strings.Join(a.Privileges, "\x00") != strings.Join(b.Privileges, "\x00") || len(a.Details) != len(b.Details) {
		return false
	}
	for k, v := range a.Details {
		if b.Details[k] != v {
			return false
		}
	}
	return true
}

// Normalize sorts and de-duplicates privileges and orders accounts by key.
func Normalize(accounts []Account) []Account {
	out := make([]Account, 0, len(accounts))
	for _, a := range accounts {
		seen := map[string]bool{}
		var privileges []string
		for _, p := range a.Privileges {
			if p != "" && !seen[p] {
				seen[p] = true
				privileges = append(privileges, p)
			}
		}
		sort.Strings(privileges)
		a.Privileges = privileges
		if len(a.Details) == 0 {
			a.Details = nil
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Change is how one account differs between two scans.
type Change struct {
	Account Account `json:"account"`
	// Change is added, removed or changed.
	Change string `json:"change"`
}

// Diff compares a scan with the one before it.
func Diff(previous, current []Account) []Change {
	before := map[string]Account{}
	for _, a := range previous {
		before[a.Key] = a
	}
	var changes []Change
	now := map[string]bool{}
	for _, a := range current {
		now[a.Key] = true
		prior, ok := before[a.Key]
		switch {
		case !ok:
			changes = append(changes, Change{Account: a, Change: "added"})
		case !prior.Equal(a):
			changes = append(changes, Change{Account: a, Change: "changed"})
		}
	}
	for _, a := range previous {
		if !now[a.Key] {
			changes = append(changes, Change{Account: a, Change: "removed"})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Account.Key < changes[j].Account.Key })
	return changes
}

// adminGroups are the groups whose members administer a Linux or Unix host.
var adminGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true, "root": true}

// SudoersFile is one sudoers file a host inventory read, or could not.
type SudoersFile struct {
	Path     string
	Readable bool
	Lines    []string
}

// AuthorizedKey is one key an account accepts, as its type and fingerprint.
type AuthorizedKey struct {
	Type        string
	Fingerprint string
	Restricted  bool
}

// AccountKeys is one account's authorized keys.
type AccountKeys struct {
	Account  string
	Readable bool
	Keys     []AuthorizedKey
}

// HostInventory is a Linux or Unix host's account inventory.
type HostInventory struct {
	Passwd  []string
	Group   []string
	Sudoers []SudoersFile
	Keys    []AccountKeys
	// KeyFiles are the AuthorizedKeysFile patterns the keys were read from
	// (A260-L2); KeysCommand reports an AuthorizedKeysCommand, whose keys
	// no file holds.
	KeyFiles    []string
	KeysCommand bool
	// SudoList is sudo's own listing of each login account's rights (`sudo -l
	// -U`), read when a sudoers file was unreadable and the administrator may
	// list them (A260-L3).
	SudoList map[string][]string
}

// defaultKeyFiles are sshd's AuthorizedKeysFile when none is configured.
var defaultKeyFiles = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

type localUser struct {
	name, uid, gid, home, shell string
}

// HostAccounts returns the host's privileged local accounts: uid 0, members
// of an administrators' group (sudo, wheel, admin, root), and accounts a
// sudoers rule names directly, through a group or through a user alias. Each
// carries its authorized keys' fingerprints. When a sudoers file could not be
// read, sudo's own listing of each login account's rights stands in for it
// when the administrator may read one (sudoers=listed by sudo, A260-L3);
// otherwise every account says so (sudoers=unreadable): its sudo rights are
// unknown, not absent.
func HostAccounts(inv HostInventory) []Account {
	var users []localUser
	byName := map[string]localUser{}
	for _, line := range inv.Passwd {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		u := localUser{name: f[0], uid: f[2], gid: f[3], home: f[5], shell: f[6]}
		users = append(users, u)
		byName[u.name] = u
	}
	groupMembers := map[string][]string{}
	groupByGID := map[string]string{}
	for _, line := range inv.Group {
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		groupByGID[f[2]] = f[0]
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				groupMembers[f[0]] = append(groupMembers[f[0]], m)
			}
		}
	}
	// Primary groups count as membership.
	for _, u := range users {
		if g, ok := groupByGID[u.gid]; ok {
			groupMembers[g] = append(groupMembers[g], u.name)
		}
	}
	privileges := map[string][]string{}
	add := func(name, privilege string) {
		if _, ok := byName[name]; ok {
			privileges[name] = append(privileges[name], privilege)
		}
	}
	for _, u := range users {
		if u.uid == "0" {
			add(u.name, "uid0")
		}
	}
	for group, members := range groupMembers {
		if adminGroups[group] {
			for _, m := range members {
				add(m, "group:"+group)
			}
		}
	}
	unreadable := false
	for _, file := range inv.Sudoers {
		if !file.Readable {
			unreadable = true
			continue
		}
		for name, grant := range sudoersGrants(file.Lines, groupMembers) {
			add(name, grant)
		}
	}
	// A260-L3: sudo's listing covers what an unreadable file hid.
	listed := unreadable && len(inv.SudoList) > 0
	if listed {
		for name, lines := range inv.SudoList {
			if grant := sudoListGrant(lines); grant != "" && !slices.Contains(privileges[name], grant) {
				if grant == "sudo:ALL" {
					privileges[name] = slices.DeleteFunc(privileges[name], func(p string) bool { return p == "sudo:commands" })
				} else if slices.Contains(privileges[name], "sudo:ALL") {
					continue
				}
				add(name, grant)
			}
		}
	}
	keys := map[string][]AuthorizedKey{}
	keysUnreadable := map[string]bool{}
	for _, k := range inv.Keys {
		if !k.Readable {
			keysUnreadable[k.Account] = true
			continue
		}
		keys[k.Account] = append(keys[k.Account], k.Keys...)
	}
	var out []Account
	for _, u := range users {
		p := privileges[u.name]
		if len(p) == 0 {
			continue
		}
		details := map[string]string{"uid": u.uid, "shell": u.shell}
		if unreadable {
			details["sudoers"] = "unreadable"
			if _, ok := inv.SudoList[u.name]; ok && listed {
				details["sudoers"] = "listed by sudo"
			}
		}
		// A260-L2: where the keys were read from, when it is not sshd's
		// default, and that a command can add keys no file holds.
		if len(inv.KeyFiles) > 0 && strings.Join(inv.KeyFiles, " ") != strings.Join(defaultKeyFiles, " ") {
			details["authorized_keys_files"] = strings.Join(inv.KeyFiles, " ")
		}
		if inv.KeysCommand {
			details["authorized_keys_command"] = "configured"
		}
		if keysUnreadable[u.name] {
			details["authorized_keys"] = "unreadable"
		} else if ks := keys[u.name]; len(ks) > 0 {
			var prints []string
			for _, k := range ks {
				entry := k.Type + " " + k.Fingerprint
				if k.Restricted {
					entry += " restricted"
				}
				prints = append(prints, entry)
			}
			sort.Strings(prints)
			details["authorized_keys"] = strings.Join(prints, "; ")
			p = append(p, "authorized_keys:"+strconv.Itoa(len(ks)))
		}
		disabled := strings.HasSuffix(u.shell, "/nologin") || strings.HasSuffix(u.shell, "/false")
		out = append(out, Account{Key: "user:" + u.name, Name: u.name, Kind: KindLocalUser, Privileges: p, Disabled: disabled, Details: details})
	}
	return Normalize(out)
}

// sudoersGrants maps each account a sudoers file's rules grant something to
// "sudo:ALL" (any command) or "sudo:commands" (named commands). Includes are
// read as their own files; Defaults and host, runas and command aliases are
// not grants.
func sudoersGrants(lines []string, groupMembers map[string][]string) map[string]string {
	logical := joinContinuations(lines)
	aliases := map[string][]string{}
	for _, line := range logical {
		if rest, ok := strings.CutPrefix(line, "User_Alias"); ok {
			for _, def := range strings.Split(rest, ":") {
				name, members, ok := strings.Cut(def, "=")
				if !ok {
					continue
				}
				for _, m := range strings.Split(members, ",") {
					aliases[strings.TrimSpace(name)] = append(aliases[strings.TrimSpace(name)], strings.TrimSpace(m))
				}
			}
		}
	}
	grants := map[string]string{}
	grant := func(name, what string) {
		if grants[name] != "sudo:ALL" {
			grants[name] = what
		}
	}
	var expand func(subject string, depth int) []string
	expand = func(subject string, depth int) []string {
		subject = strings.TrimSpace(subject)
		if depth > 8 || subject == "" || strings.HasPrefix(subject, "!") {
			return nil
		}
		if group, ok := strings.CutPrefix(subject, "%"); ok {
			return groupMembers[strings.Trim(group, `"`)]
		}
		if members, ok := aliases[subject]; ok {
			var out []string
			for _, m := range members {
				out = append(out, expand(m, depth+1)...)
			}
			return out
		}
		return []string{subject}
	}
	for _, line := range logical {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") || strings.HasPrefix(line, "Defaults") ||
			strings.HasSuffix(strings.Fields(line)[0], "_Alias") {
			continue
		}
		subjects, spec, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// "alice, %ops host1, host2 = (runas) commands": the user list runs
		// until a token neither ends nor starts with a comma after one that
		// did not end with one; the host list follows it.
		tokens := strings.Fields(subjects)
		var users []string
		for i, token := range tokens {
			if i > 0 && !strings.HasSuffix(tokens[i-1], ",") && !strings.HasPrefix(token, ",") {
				break
			}
			users = append(users, token)
		}
		if len(users) == 0 || len(users) == len(tokens) {
			continue
		}
		subjectList := strings.Join(users, " ")
		commands := spec
		if i := strings.Index(spec, ")"); i >= 0 {
			commands = spec[i+1:]
		}
		what := "sudo:commands"
		for _, c := range strings.Split(commands, ",") {
			c = strings.TrimSpace(c)
			for _, tag := range []string{"NOPASSWD:", "PASSWD:", "SETENV:", "NOSETENV:", "NOEXEC:", "EXEC:"} {
				c = strings.TrimSpace(strings.TrimPrefix(c, tag))
			}
			if c == "ALL" {
				what = "sudo:ALL"
			}
		}
		for _, s := range strings.Split(subjectList, ",") {
			for _, name := range expand(s, 0) {
				grant(name, what)
			}
		}
	}
	return grants
}

func joinContinuations(lines []string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, "\\") {
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(trimmed)
		out = append(out, strings.TrimSpace(cur.String()))
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// sudoListGrant reads `sudo -l -U` output (LC_ALL=C): the rules under "may
// run the following commands" grant "sudo:ALL" when one runs any command and
// "sudo:commands" when they name commands; none, or only the list
// pseudo-command, grants nothing (A260-L3).
func sudoListGrant(lines []string) string {
	grant, inRules := "", false
	for _, line := range lines {
		if strings.Contains(line, "may run the following commands") {
			inRules = true
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inRules = false // another heading ends the rules
			continue
		}
		if !inRules {
			continue
		}
		rule := strings.TrimSpace(line)
		if strings.HasPrefix(rule, "(") {
			if end := strings.Index(rule, ")"); end >= 0 {
				rule = strings.TrimSpace(rule[end+1:])
			}
		}
		for {
			tag, rest, ok := strings.Cut(rule, ":")
			if !ok || tag == "" || strings.ToUpper(tag) != tag || strings.ContainsAny(tag, " /,") {
				break
			}
			rule = strings.TrimSpace(rest)
		}
		for _, command := range strings.Split(rule, ",") {
			switch command = strings.TrimSpace(command); command {
			case "ALL":
				return "sudo:ALL"
			case "", "list":
			default:
				grant = "sudo:commands"
			}
		}
	}
	return grant
}
