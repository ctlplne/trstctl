// SPDX-License-Identifier: BUSL-1.1

package accessrules

import (
	"slices"
	"testing"
)

// TestSQLRiskCategoriesA275: a PostgreSQL or MySQL statement's risk
// categories come from its own tables, settings and shape — quoted
// identifiers, executable comments and E-strings included — never from a
// value, a comment or a string that merely mentions them.
func TestSQLRiskCategoriesA275(t *testing.T) {
	for _, tc := range []struct {
		mysql bool
		sql   string
		want  []string
	}{
		{false, "GRANT SELECT ON orders TO PUBLIC", []string{RiskPrivilegeChange}},
		{false, "revoke all on orders from app", []string{RiskPrivilegeChange}},
		{false, "CREATE ROLE helper LOGIN SUPERUSER", []string{RiskPrivilegeChange}},
		{false, "ALTER USER app WITH PASSWORD 'x'", []string{RiskPrivilegeChange}},
		{false, "ALTER TABLE orders OWNER TO intruder", []string{RiskPrivilegeChange}},
		{false, "SET ROLE postgres", []string{RiskPrivilegeChange}},
		{false, "SET SESSION AUTHORIZATION postgres", []string{RiskPrivilegeChange}},
		{false, "SELECT rolname, rolpassword FROM pg_authid", []string{RiskCredentialRead}},
		{false, `SELECT * FROM pg_catalog."pg_shadow"`, []string{RiskCredentialRead}},
		{false, "COPY (SELECT * FROM pg_user_mappings) TO STDOUT", []string{RiskCredentialRead}},
		{false, "ALTER SYSTEM SET log_statement = 'none'", []string{RiskAuditTampering}},
		{false, "SET log_min_duration_statement TO -1", []string{RiskAuditTampering}},
		{false, "set session pgaudit.log = 'none'", []string{RiskAuditTampering}},
		{false, "DROP EXTENSION IF EXISTS pgaudit", []string{RiskAuditTampering}},
		{false, "SELECT set_config('log_statement', 'none', false)", []string{RiskAuditTampering}},
		{false, "TRUNCATE orders", []string{RiskBulkDelete}},
		{false, "DROP TABLE IF EXISTS orders CASCADE", []string{RiskBulkDelete}},
		{false, "DELETE FROM orders", []string{RiskBulkDelete}},
		{false, "WITH gone AS (DELETE FROM orders RETURNING id) SELECT count(*) FROM gone", []string{RiskBulkDelete}},
		{false, "SELECT 1; TRUNCATE a; GRANT SELECT ON a TO b", []string{RiskBulkDelete, RiskPrivilegeChange}},
		// Not risky: a scoped delete, values, comments and strings that
		// mention the words, a session setting of an application GUC.
		{false, "DELETE FROM orders WHERE id = 7", nil},
		{false, "SELECT 'GRANT ALL ON pg_authid TO PUBLIC' AS note", nil},
		{false, "SELECT 1 /* TRUNCATE orders; ALTER SYSTEM SET log_statement='none' */", nil},
		{false, "-- DROP TABLE orders\nSELECT 1", nil},
		{false, "SELECT set_config('trstctl.tenant_id', 'x', true)", nil},
		{false, "SELECT E'\\' TRUNCATE orders'", nil},
		{false, "SELECT $$ DELETE FROM orders $$", nil},
		{false, "SET search_path TO app", nil},
		{true, "GRANT ALL ON *.* TO 'x'@'%'", []string{RiskPrivilegeChange}},
		{true, "CREATE USER 'x'@'%' IDENTIFIED BY 'y'", []string{RiskPrivilegeChange}},
		{true, "SET PASSWORD FOR app = 'z'", []string{RiskPrivilegeChange}},
		{true, "SELECT user, authentication_string FROM mysql.user", []string{RiskCredentialRead}},
		{true, "SELECT * FROM `mysql`.`user`", []string{RiskCredentialRead}},
		{true, "SET GLOBAL general_log = 'OFF'", []string{RiskAuditTampering}},
		{true, "SET @@global.sql_log_bin = 0", []string{RiskAuditTampering}},
		{true, "/*!50000 SET GLOBAL audit_log_policy = 'NONE' */", []string{RiskAuditTampering}},
		{true, "UNINSTALL PLUGIN audit_log", []string{RiskAuditTampering}},
		{true, "PURGE BINARY LOGS BEFORE NOW()", []string{RiskAuditTampering}},
		{true, "DROP DATABASE app", []string{RiskBulkDelete}},
		{true, "DELETE FROM orders LIMIT 1000", []string{RiskBulkDelete}},
		{true, "DELETE FROM orders WHERE id = 7", nil},
		{true, `SELECT "DROP DATABASE app", 'mysql.user'`, nil},
		{true, "SELECT 1 # TRUNCATE orders", nil},
		{true, "SELECT user FROM app.user", nil},
	} {
		got := sqlRiskCategories([]byte(tc.sql), tc.mysql)
		if len(got) == 0 {
			got = nil
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("mysql=%v %q: %v, want %v", tc.mysql, tc.sql, got, tc.want)
		}
	}
	ops, err := PostgresRuleOperations([]byte("TRUNCATE orders"))
	if err != nil || !slices.Equal(ops, []string{RiskBulkDelete, "TRUNCATE"}) {
		t.Fatalf("a statement offers its operations and categories together: %v %v", ops, err)
	}
	if _, err := PostgresRuleOperations([]byte("SELECT 'unterminated")); err == nil {
		t.Fatal("an uninspectable statement offered operations")
	}
}

// TestSSHRiskCategoriesA275: an exec command's risk categories come from its
// programs, flags, paths and redirections, through wrappers such as sudo,
// never from a comment or a read of a log.
func TestSSHRiskCategoriesA275(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want []string
	}{
		{"cat /etc/shadow", []string{SSHRiskCredentialRead}},
		{"sudo -n head -c 100 /home/app/.ssh/id_ed25519", []string{SSHRiskCredentialRead}},
		{"base64 < ~/.aws/credentials", []string{SSHRiskCredentialRead}},
		{"getent shadow root", []string{SSHRiskCredentialRead}},
		{"systemctl stop auditd.service", []string{SSHRiskAuditTampering}},
		{"service rsyslog stop", []string{SSHRiskAuditTampering}},
		{"auditctl -D", []string{SSHRiskAuditTampering}},
		{"auditctl -e 0", []string{SSHRiskAuditTampering}},
		{"journalctl --vacuum-time=1s", []string{SSHRiskAuditTampering}},
		{"history -c", []string{SSHRiskAuditTampering}},
		{"unset HISTFILE; rm -f /var/log/auth.log", []string{SSHRiskAuditTampering}},
		{"HISTFILE=/dev/null bash", []string{SSHRiskAuditTampering}},
		{"echo > /var/log/secure", []string{SSHRiskAuditTampering}},
		{"rm -rf /srv/app/data", []string{SSHRiskBulkDelete}},
		{"rm --recursive old", []string{SSHRiskBulkDelete}},
		{"find /srv -name '*.tmp' -delete", []string{SSHRiskBulkDelete}},
		{"dd if=/dev/zero of=/dev/sda bs=1M", []string{SSHRiskBulkDelete}},
		{"passwd app", []string{SSHRiskPrivilegeChange}},
		{"usermod -aG sudo intruder", []string{SSHRiskPrivilegeChange}},
		{"chmod u+s /usr/bin/find", []string{SSHRiskPrivilegeChange}},
		{"chmod 4755 /tmp/sh", []string{SSHRiskPrivilegeChange}},
		{"echo 'app ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers.d/app", []string{SSHRiskPrivilegeChange}},
		{"echo ssh-ed25519 AAAA >> /home/app/.ssh/authorized_keys", []string{SSHRiskPrivilegeChange}},
		{"cat /etc/shadow 2>&1 | tee /var/log/copy; rm -r x", []string{SSHRiskAuditTampering, SSHRiskBulkDelete, SSHRiskCredentialRead}},
		// Not risky.
		{"cat /etc/passwd", nil},
		{"grep sshd < /var/log/auth.log", nil},
		{"tail -n 50 /var/log/syslog", nil},
		{"cp /var/log/syslog /tmp/syslog-copy", nil},
		{"cp /tmp/forged /var/log/auth.log", []string{SSHRiskAuditTampering}},
		{"mv /var/log/auth.log /tmp/gone", []string{SSHRiskAuditTampering}},
		{"rm -f /tmp/build.log", nil},
		{"cat /home/app/.ssh/id_ed25519.pub", nil},
		{"systemctl restart nginx", nil},
		{"ls -la # rm -rf /", nil},
		{"chmod 0644 /srv/app/config", nil},
	} {
		got, err := SSHRiskCategories([]byte(tc.cmd))
		if err != nil {
			t.Fatalf("%q: %v", tc.cmd, err)
		}
		if len(got) == 0 {
			got = nil
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: %v, want %v", tc.cmd, got, tc.want)
		}
	}
	ops, err := SSHRuleOperations([]byte("sudo rm -rf /srv"))
	// The program lexer names only the direct program (sudo); the category
	// reads through the wrapper.
	if err != nil || !slices.Equal(ops, []string{SSHRiskBulkDelete, "sudo"}) {
		t.Fatalf("a command offers its programs and categories together: %v %v", ops, err)
	}
	if _, err := SSHRiskCategories([]byte("cat <<EOF")); err == nil {
		t.Fatal("a here-document was categorized")
	}
	for _, protocol := range []string{"postgres", "mysql"} {
		if !KnownOperation(protocol, RiskCredentialRead) || KnownOperation(protocol, SSHRiskCredentialRead) {
			t.Fatalf("%s's categories are its own spelling", protocol)
		}
	}
	if !KnownOperation("ssh", SSHRiskBulkDelete) || KnownOperation("redis", RiskBulkDelete) || !KnownAnyOperation(RiskAuditTampering) {
		t.Fatal("the category vocabulary")
	}
	if rules, err := CanonicalRules([]Rule{{ID: "11111111-1111-4111-8111-111111111111", Name: "Credential reads", Enabled: true, Protocol: "ssh",
		Operations: []string{"CREDENTIAL_READ"}, Effect: EffectAlert, Severity: SeverityCritical}}); err != nil || rules[0].Operations[0] != SSHRiskCredentialRead {
		t.Fatalf("an SSH rule names a category in any case: %v %v", rules, err)
	}
}
