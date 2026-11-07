// SPDX-License-Identifier: BUSL-1.1

package accessrules

import (
	"bytes"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

// A275: risk categories. The gateway derives them from a statement's or a
// command's own text — the tables it names, the settings it changes, the
// files and flags it passes — and only the category's name leaves it, as one
// more operation name a template rule can match with any effect. Like every
// rule here they are lexical guardrails: a stored program, a dynamically
// built statement, an alias or an interpreter can hide what they look for.

// SQL risk categories (PostgreSQL and MySQL).
const (
	RiskCredentialRead  = "CREDENTIAL_READ" // #nosec G101 -- a risk category's name matching the secret-name heuristic; no credential value present (CWE-798)
	RiskAuditTampering  = "AUDIT_TAMPERING"
	RiskBulkDelete      = "BULK_DELETE"
	RiskPrivilegeChange = "PRIVILEGE_CHANGE"
)

// SSH risk categories: the same four, spelled as SSH operations are.
const (
	SSHRiskCredentialRead  = "credential_read" // #nosec G101 -- a risk category's name matching the secret-name heuristic; no credential value present (CWE-798)
	SSHRiskAuditTampering  = "audit_tampering"
	SSHRiskBulkDelete      = "bulk_delete"
	SSHRiskPrivilegeChange = "privilege_change"
)

var (
	sqlRiskNames = []string{RiskAuditTampering, RiskBulkDelete, RiskCredentialRead, RiskPrivilegeChange}
	sshRiskNames = []string{SSHRiskAuditTampering, SSHRiskBulkDelete, SSHRiskCredentialRead, SSHRiskPrivilegeChange}
)

// RiskCategory reports whether an operation name is a risk category.
func RiskCategory(operation string) bool {
	return slices.Contains(sqlRiskNames, operation) || slices.Contains(sshRiskNames, operation)
}

// sqlToken is one lexical token of a statement: a word (ASCII lowercased), a
// quoted identifier (exact), a string literal (lowercased, bounded; it never
// leaves the gateway) or one punctuation byte.
type sqlToken struct {
	kind byte // 'w', 'i', 's' or 'p'
	text string
}

const sqlRiskLiteralBytes = 128

// PostgresRuleOperations is what a PostgreSQL statement offers rules: its
// operation names and its risk categories.
func PostgresRuleOperations(sql []byte) ([]string, error) {
	ops, err := PostgresOperations(sql)
	if err != nil {
		return nil, err
	}
	return mergeOperations(ops, sqlRiskCategories(sql, false)), nil
}

// MySQLRuleOperations is what a MySQL statement offers rules: its operation
// names and its risk categories.
func MySQLRuleOperations(sql []byte) ([]string, error) {
	ops, err := MySQLOperations(sql)
	if err != nil {
		return nil, err
	}
	return mergeOperations(ops, sqlRiskCategories(sql, true)), nil
}

// SSHRuleOperations is what an SSH exec command offers rules: its program
// names and its risk categories.
func SSHRuleOperations(raw []byte) ([]string, error) {
	ops, err := SSHOperations(raw)
	if err != nil {
		return nil, err
	}
	categories, err := SSHRiskCategories(raw)
	if err != nil {
		return nil, err
	}
	return mergeOperations(ops, categories), nil
}

func mergeOperations(a, b []string) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

// PostgresRiskCategories returns a PostgreSQL statement's risk categories,
// read under both ordinary-string escape modes, as its operations are.
func PostgresRiskCategories(sql []byte) []string { return sqlRiskCategories(sql, false) }

// MySQLRiskCategories returns a MySQL statement's risk categories, executable
// version comments included.
func MySQLRiskCategories(sql []byte) []string { return sqlRiskCategories(sql, true) }

func sqlRiskCategories(sql []byte, mysql bool) []string {
	if len(sql) > MaxStatementBytes || !utf8.Valid(sql) || bytes.IndexByte(sql, 0) >= 0 {
		return nil
	}
	found := map[string]bool{}
	for _, backslash := range []bool{false, true} {
		var tokens []sqlToken
		if sqlRiskTokens(sql, mysql, backslash, 0, &tokens) != nil {
			continue
		}
		start := 0
		for i := 0; i <= len(tokens); i++ {
			if i == len(tokens) || tokens[i].kind == 'p' && tokens[i].text == ";" {
				classifySQLRisk(tokens[start:i], mysql, found)
				start = i + 1
			}
		}
	}
	out := []string{}
	for _, name := range sqlRiskNames {
		if found[name] {
			out = append(out, name)
		}
	}
	return out
}

func sqlRiskTokens(raw []byte, mysql, backslash bool, depth int, out *[]sqlToken) error {
	if depth > 8 {
		return ErrUninspectable
	}
	for i := 0; i < len(raw); {
		c := raw[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(raw) && raw[i+1] == '-' && (!mysql || i+2 >= len(raw) || raw[i+2] <= 32), mysql && c == '#':
			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
		case c == '/' && i+1 < len(raw) && raw[i+1] == '*':
			if mysql {
				start := i + 2
				end := bytes.Index(raw[start:], []byte("*/"))
				if end < 0 {
					return ErrUninspectable
				}
				end += start
				if start < end && raw[start] == '!' {
					start++
					for start < end && raw[start] >= '0' && raw[start] <= '9' {
						start++
					}
					if err := sqlRiskTokens(raw[start:end], mysql, backslash, depth+1, out); err != nil {
						return err
					}
				}
				i = end + 2
				continue
			}
			i += 2
			nested := 1
			for i < len(raw) && nested > 0 {
				switch {
				case i+1 < len(raw) && raw[i] == '/' && raw[i+1] == '*':
					nested++
					i += 2
				case i+1 < len(raw) && raw[i] == '*' && raw[i+1] == '/':
					nested--
					i += 2
				default:
					i++
				}
				if nested > 64 {
					return ErrUninspectable
				}
			}
			if nested != 0 {
				return ErrUninspectable
			}
		case c == '\'' || mysql && c == '"':
			escaped := backslash
			if !mysql && c == '\'' && i > 0 && (raw[i-1] == 'e' || raw[i-1] == 'E') && (i == 1 || !pgWord(raw[i-2])) {
				escaped = true
				if n := len(*out); n > 0 && (*out)[n-1].kind == 'w' && (*out)[n-1].text == "e" {
					*out = (*out)[:n-1]
				}
			}
			text, next, ok := sqlQuoted(raw, i+1, c, escaped)
			if !ok {
				return ErrUninspectable
			}
			*out = append(*out, sqlToken{kind: 's', text: strings.ToLower(text)})
			i = next
		case !mysql && c == '"' || mysql && c == '`':
			text, next, ok := sqlQuoted(raw, i+1, c, false)
			if !ok {
				return ErrUninspectable
			}
			*out = append(*out, sqlToken{kind: 'i', text: text})
			i = next
		case !mysql && c == '$':
			end := i + 1
			for end < len(raw) && end-i <= 256 && pgDollarTag(raw[end]) {
				end++
			}
			if end < len(raw) && raw[end] == '$' && (end == i+1 || !pgDigit(raw[i+1])) {
				delimiter := raw[i : end+1]
				n := bytes.Index(raw[end+1:], delimiter)
				if n < 0 {
					return ErrUninspectable
				}
				*out = append(*out, sqlToken{kind: 's'})
				i = end + 1 + n + len(delimiter)
				continue
			}
			i++
		case pgWordStart(c):
			start := i
			i++
			for i < len(raw) && pgWord(raw[i]) {
				i++
			}
			*out = append(*out, sqlToken{kind: 'w', text: strings.ToLower(string(raw[start:i]))})
		case pgDigit(c):
			for i < len(raw) && (pgWord(raw[i]) || raw[i] == '.') {
				i++
			}
		default:
			*out = append(*out, sqlToken{kind: 'p', text: string(c)})
			i++
		}
	}
	return nil
}

// sqlQuoted reads a quoted run from just past its opening quote: its text
// (doubled quotes undone, at most sqlRiskLiteralBytes kept) and the index
// past its closing quote.
func sqlQuoted(raw []byte, i int, quote byte, escaped bool) (string, int, bool) {
	var b strings.Builder
	keep := func(c byte) {
		if b.Len() < sqlRiskLiteralBytes {
			b.WriteByte(c)
		}
	}
	for i < len(raw) {
		c := raw[i]
		if escaped && c == '\\' {
			if i+1 >= len(raw) {
				return "", 0, false
			}
			keep(raw[i+1])
			i += 2
			continue
		}
		if c == quote {
			if i+1 < len(raw) && raw[i+1] == quote {
				keep(quote)
				i += 2
				continue
			}
			return b.String(), i + 1, true
		}
		keep(c)
		i++
	}
	return "", 0, false
}

// classifySQLRisk adds one statement's categories to found.
func classifySQLRisk(st []sqlToken, mysql bool, found map[string]bool) {
	var words []string // the statement's words in order, for keyword shapes
	for _, t := range st {
		if t.kind == 'w' {
			words = append(words, t.text)
		}
	}
	if len(words) == 0 {
		return
	}
	at := func(i int) string {
		if i < len(words) {
			return words[i]
		}
		return ""
	}
	has := func(w string) bool { return slices.Contains(words, w) }
	w0, w1 := at(0), at(1)

	// Privilege changes: grants, roles and users, ownership, role switches.
	switch {
	case w0 == "grant" || w0 == "revoke":
		found[RiskPrivilegeChange] = true
	case (w0 == "create" || w0 == "alter" || w0 == "drop" || w0 == "rename") && (w1 == "role" || w1 == "user" || w1 == "group"):
		found[RiskPrivilegeChange] = true
	case w0 == "alter" && w1 == "default" && at(2) == "privileges":
		found[RiskPrivilegeChange] = true
	case w0 == "alter" && sqlSequence(words, "owner", "to"):
		found[RiskPrivilegeChange] = true
	case w0 == "set" && (w1 == "role" || w1 == "password" || w1 == "default" && at(2) == "role" ||
		(w1 == "session" || w1 == "local") && (at(2) == "role" || at(2) == "authorization")):
		found[RiskPrivilegeChange] = true
	}

	// Credential reads: the catalogs that hold password hashes and secrets.
	for i, t := range st {
		if t.kind != 'w' && t.kind != 'i' {
			continue
		}
		if mysql {
			if t.text == "authentication_string" || t.text == "user" && i >= 2 && st[i-1].kind == 'p' && st[i-1].text == "." &&
				(st[i-2].kind == 'w' || st[i-2].kind == 'i') && st[i-2].text == "mysql" {
				found[RiskCredentialRead] = true
			}
			continue
		}
		switch t.text {
		case "pg_authid", "pg_shadow", "pg_user_mapping", "pg_user_mappings":
			found[RiskCredentialRead] = true
		}
	}

	// Audit tampering: the settings and statements that stop, redirect or
	// discard the server's own record.
	if mysql {
		switch {
		case w0 == "set":
			for _, w := range words[1:] {
				if w == "general_log" || w == "slow_query_log" || w == "sql_log_off" || w == "sql_log_bin" || w == "log_output" ||
					strings.HasPrefix(w, "audit_log") || strings.HasPrefix(w, "binlog") || strings.HasPrefix(w, "log_") {
					found[RiskAuditTampering] = true
				}
			}
		case w0 == "uninstall":
			found[RiskAuditTampering] = true
		case w0 == "purge" && (w1 == "binary" || w1 == "master"):
			found[RiskAuditTampering] = true
		case w0 == "reset" && (w1 == "master" || w1 == "binary"):
			found[RiskAuditTampering] = true
		}
	} else {
		param := func(w string) bool {
			return strings.HasPrefix(w, "log_") || w == "logging_collector" || strings.HasPrefix(w, "pgaudit")
		}
		switch {
		case w0 == "alter" && w1 == "system":
			found[RiskAuditTampering] = true
		case w0 == "set" || w0 == "reset":
			name := w1
			if name == "session" || name == "local" {
				name = at(2)
			}
			if param(name) {
				found[RiskAuditTampering] = true
			}
		case (w0 == "drop" || w0 == "alter") && w1 == "extension" && slices.Contains(words[2:], "pgaudit"):
			found[RiskAuditTampering] = true
		}
		for i := 0; i+2 < len(st); i++ {
			if st[i].kind == 'w' && st[i].text == "set_config" && st[i+1].kind == 'p' && st[i+1].text == "(" && st[i+2].kind == 's' && param(st[i+2].text) {
				found[RiskAuditTampering] = true
			}
		}
	}

	// Bulk deletes: a whole table, schema or database, or a DELETE that names
	// no rows.
	switch {
	case w0 == "truncate":
		found[RiskBulkDelete] = true
	case w0 == "drop" && (w1 == "table" || w1 == "schema" || w1 == "database" || w1 == "owned"):
		found[RiskBulkDelete] = true
	case has("delete") && !has("where") && (sqlSequence(words, "delete", "from") || w0 == "delete"):
		found[RiskBulkDelete] = true
	}
}

// sqlSequence reports whether b directly follows a somewhere in words.
func sqlSequence(words []string, a, b string) bool {
	for i := 0; i+1 < len(words); i++ {
		if words[i] == a && words[i+1] == b {
			return true
		}
	}
	return false
}

// sshCommand is one simple command of an exec request: its words in order,
// its environment assignments and its redirections.
type sshCommand struct {
	argv, assignments []string
	redirects         []sshRedirect
}

// sshRedirect is one redirection: where it points, and whether it writes.
type sshRedirect struct {
	target string
	out    bool
}

// SSHRiskCategories returns an SSH exec command's risk categories. It reads
// every simple command's program and arguments locally; only category names
// leave it.
func SSHRiskCategories(raw []byte) ([]string, error) {
	if len(raw) > MaxSSHCommandBytes || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrUninspectable
	}
	var commands []sshCommand
	cur := sshCommand{}
	flush := func() {
		if len(cur.argv)+len(cur.assignments)+len(cur.redirects) > 0 {
			commands = append(commands, cur)
		}
		cur = sshCommand{}
	}
	redirect, redirectOut := false, false
	for i := 0; i < len(raw); {
		c := raw[i]
		switch c {
		case ' ', '\t', '\r':
			i++
			continue
		case '\n', ';', '|', '&', '(', ')', '{', '}':
			flush()
			redirect = false
			i++
			continue
		case '#':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			continue
		case '<', '>':
			if c == '<' && i+1 < len(raw) && raw[i+1] == '<' {
				return nil, ErrUninspectable
			}
			redirect, redirectOut = true, c == '>'
			i++
			for i < len(raw) && (raw[i] == c || raw[i] == '|' || raw[i] == '&') {
				i++
			}
			continue
		}
		word, next, _, _, err := sshCommandWord(raw, i, true)
		if err != nil {
			return nil, err
		}
		i = next
		w := string(word)
		clear(word)
		switch {
		case redirect:
			cur.redirects = append(cur.redirects, sshRedirect{target: w, out: redirectOut})
			redirect = false
		case len(cur.argv) == 0 && sshAssignment([]byte(w)):
			cur.assignments = append(cur.assignments, w)
		default:
			// A file descriptor number directly before a redirection is part of
			// it, not an argument.
			if i < len(raw) && (raw[i] == '<' || raw[i] == '>') && strings.Trim(w, "0123456789") == "" {
				continue
			}
			cur.argv = append(cur.argv, w)
		}
	}
	flush()
	found := map[string]bool{}
	for _, cmd := range commands {
		classifySSHRisk(cmd, found)
	}
	out := []string{}
	for _, name := range sshRiskNames {
		if found[name] {
			out = append(out, name)
		}
	}
	return out, nil
}

// sshWrappers run the program named after them (and their own options).
var sshWrappers = map[string]bool{"sudo": true, "doas": true, "env": true, "nohup": true, "nice": true, "ionice": true, "time": true,
	"timeout": true, "command": true, "exec": true, "builtin": true, "xargs": true, "stdbuf": true}

var sshFileReaders = map[string]bool{"cat": true, "tac": true, "nl": true, "less": true, "more": true, "head": true, "tail": true,
	"strings": true, "xxd": true, "od": true, "hexdump": true, "base64": true, "base32": true, "cp": true, "scp": true, "rsync": true,
	"dd": true, "grep": true, "egrep": true, "fgrep": true, "rg": true, "zcat": true, "awk": true, "gawk": true, "sed": true,
	"vi": true, "vim": true, "view": true, "nano": true, "emacs": true, "openssl": true, "sort": true, "uniq": true, "cut": true,
	"diff": true, "cmp": true, "tar": true, "zip": true, "gzip": true, "curl": true, "nc": true, "ncat": true, "socat": true, "tee": true}

var sshLogUnits = map[string]bool{"auditd": true, "rsyslog": true, "syslog": true, "syslog-ng": true, "systemd-journald": true, "journald": true}

// sshCredentialPath reports whether a path names a stored credential.
func sshCredentialPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "-") {
		return false
	}
	switch p {
	case "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/master.passwd", "/etc/security/opasswd", "/etc/kubernetes/admin.conf":
		return true
	}
	base := path.Base(p)
	if strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub") && (strings.Contains(p, ".ssh/") || base == "id_rsa" || base == "id_dsa" ||
		base == "id_ecdsa" || base == "id_ed25519" || base == "id_ecdsa_sk" || base == "id_ed25519_sk") {
		return true
	}
	if strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key") {
		return true
	}
	for _, suffix := range []string{".aws/credentials", ".kube/config", ".docker/config.json", ".pgpass", ".my.cnf", ".netrc", ".git-credentials", ".vault-token"} {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return strings.HasPrefix(p, "/etc/ssl/private/") || strings.HasPrefix(p, "/etc/kubernetes/pki/") && strings.HasSuffix(p, ".key")
}

// sshAuditPath reports whether a path is the system's own record: its logs,
// audit trail, login records or a shell history.
func sshAuditPath(p string) bool {
	if strings.HasPrefix(p, "/var/log/") || p == "/var/log" {
		return true
	}
	base := path.Base(p)
	return base == ".bash_history" || base == ".zsh_history" || base == ".history" || base == ".sh_history"
}

// sshOperands are a command's arguments that are not options.
func sshOperands(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func classifySSHRisk(cmd sshCommand, found map[string]bool) {
	for _, a := range cmd.assignments {
		if strings.HasPrefix(a, "HISTFILE=") || a == "HISTSIZE=0" || a == "HISTFILESIZE=0" {
			found[SSHRiskAuditTampering] = true
		}
	}
	for _, r := range cmd.redirects {
		switch {
		case !r.out && sshCredentialPath(r.target):
			found[SSHRiskCredentialRead] = true
		case r.out && sshAuditPath(r.target):
			found[SSHRiskAuditTampering] = true
		case r.out && (strings.HasPrefix(r.target, "/etc/sudoers") || strings.HasSuffix(r.target, ".ssh/authorized_keys")):
			found[SSHRiskPrivilegeChange] = true
		}
	}
	argv := cmd.argv
	// Skip wrappers and their options to the program they run.
	for len(argv) > 0 && sshWrappers[path.Base(argv[0])] {
		argv = argv[1:]
		for len(argv) > 0 && (strings.HasPrefix(argv[0], "-") || sshAssignment([]byte(argv[0]))) {
			argv = argv[1:]
		}
	}
	if len(argv) == 0 {
		return
	}
	program, args := path.Base(argv[0]), argv[1:]
	hasArg := func(match func(string) bool) bool { return slices.ContainsFunc(args, match) }
	shortFlag := func(letters string) bool {
		return hasArg(func(a string) bool {
			return len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], letters)
		})
	}

	if sshFileReaders[program] && hasArg(sshCredentialPath) || program == "getent" && hasArg(func(a string) bool { return a == "shadow" || a == "gshadow" }) || program == "unshadow" {
		found[SSHRiskCredentialRead] = true
	}
	switch program {
	case "auditctl":
		if hasArg(func(a string) bool { return a == "-D" || a == "-e0" }) || sqlSequence(args, "-e", "0") {
			found[SSHRiskAuditTampering] = true
		}
	case "systemctl", "service":
		verb := hasArg(func(a string) bool { return a == "stop" || a == "disable" || a == "mask" || a == "kill" })
		unit := hasArg(func(a string) bool { return sshLogUnits[strings.TrimSuffix(a, ".service")] })
		if verb && unit {
			found[SSHRiskAuditTampering] = true
		}
	case "journalctl":
		if hasArg(func(a string) bool { return strings.HasPrefix(a, "--vacuum") }) {
			found[SSHRiskAuditTampering] = true
		}
	case "history":
		if shortFlag("c") {
			found[SSHRiskAuditTampering] = true
		}
	case "unset":
		if hasArg(func(a string) bool { return a == "HISTFILE" }) {
			found[SSHRiskAuditTampering] = true
		}
	case "export", "declare", "typeset":
		if hasArg(func(a string) bool {
			return strings.HasPrefix(a, "HISTFILE=") || a == "HISTSIZE=0" || a == "HISTFILESIZE=0"
		}) {
			found[SSHRiskAuditTampering] = true
		}
	case "set":
		if sqlSequence(args, "+o", "history") {
			found[SSHRiskAuditTampering] = true
		}
	case "rm", "shred", "truncate", "unlink", "srm", "wipe", "tee", "mv":
		// Removing, overwriting or moving away the record.
		if hasArg(sshAuditPath) {
			found[SSHRiskAuditTampering] = true
		}
	case "cp", "install":
		// Copying over the record; copying it out is a read.
		if operands := sshOperands(args); len(operands) >= 2 && sshAuditPath(operands[len(operands)-1]) {
			found[SSHRiskAuditTampering] = true
		}
	case "ln":
		if hasArg(func(a string) bool { return a == "/dev/null" }) && hasArg(sshAuditPath) {
			found[SSHRiskAuditTampering] = true
		}
	}
	switch program {
	case "rm":
		if shortFlag("rR") || hasArg(func(a string) bool { return a == "--recursive" }) {
			found[SSHRiskBulkDelete] = true
		}
	case "find":
		if hasArg(func(a string) bool { return a == "-delete" }) || sqlSequence(args, "-exec", "rm") {
			found[SSHRiskBulkDelete] = true
		}
	case "wipefs", "mkfs", "mke2fs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat":
		found[SSHRiskBulkDelete] = true
	case "dd", "shred", "wipe":
		if hasArg(func(a string) bool {
			return strings.HasPrefix(a, "of=/dev/") || strings.HasPrefix(a, "/dev/") && !strings.HasPrefix(a, "/dev/null")
		}) {
			found[SSHRiskBulkDelete] = true
		}
	}
	switch program {
	case "passwd", "chpasswd", "usermod", "useradd", "userdel", "adduser", "deluser", "groupadd", "groupdel", "groupmod",
		"gpasswd", "chage", "visudo", "setcap", "chgpasswd", "newusers", "vipw", "vigr":
		found[SSHRiskPrivilegeChange] = true
	case "chmod":
		if hasArg(func(a string) bool {
			if strings.Contains(a, "+s") {
				return true
			}
			return len(a) == 4 && strings.Trim(a, "01234567") == "" && strings.ContainsAny(a[:1], "2467")
		}) {
			found[SSHRiskPrivilegeChange] = true
		}
	case "tee", "cp", "mv", "install":
		if hasArg(func(a string) bool {
			return strings.HasPrefix(a, "/etc/sudoers") || strings.HasSuffix(a, ".ssh/authorized_keys")
		}) {
			found[SSHRiskPrivilegeChange] = true
		}
	}
}
