// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pamdiscovery"
	"trstctl.com/trstctl/internal/secrettext"
)

// A260: privileged account discovery. A provider whose administrator
// connection can read its target's accounts lists the privileged ones in a
// read-only transaction (databases) or with one fixed read-only command
// (hosts). Nothing on the target changes, and no account's credential is
// read. The provider's own leased accounts are left out: trstctl manages
// them already.

// ErrDiscoveryNotSupported is a backend that cannot list its target's
// accounts.
var ErrDiscoveryNotSupported = errors.New("dynsecret: this provider cannot list its target's accounts")

// AccountDiscoverer is a backend that can list its target's privileged
// accounts.
type AccountDiscoverer interface {
	DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error)
}

// postgresPowerfulRoles are the predefined roles whose membership is a
// privilege of its own.
var postgresPowerfulRoles = []string{"pg_read_all_data", "pg_write_all_data", "pg_read_server_files", "pg_write_server_files",
	"pg_execute_server_program", "pg_signal_backend", "pg_monitor", "pg_create_subscription", "pg_checkpoint", "pg_maintain",
	"pg_use_reserved_connections"}

const postgresDiscoverRoles = `SELECT r.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls, r.rolcanlogin,
  COALESCE(to_char(r.rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), ''),
  CASE WHEN r.rolsuper THEN '' ELSE COALESCE((SELECT string_agg(g.rolname, ',' ORDER BY g.rolname) FROM pg_roles g
    WHERE g.rolname = ANY($1::text[]) AND g.oid <> r.oid AND pg_has_role(r.oid, g.oid, 'MEMBER')), '') END,
  CASE WHEN r.rolsuper THEN '' ELSE COALESCE((SELECT string_agg(s.rolname, ',' ORDER BY s.rolname) FROM pg_roles s
    WHERE s.rolsuper AND s.oid <> r.oid AND pg_has_role(r.oid, s.oid, 'MEMBER')), '') END,
  COALESCE((SELECT string_agg(d.datname, ',' ORDER BY d.datname) FROM pg_database d WHERE d.datdba = r.oid AND NOT d.datistemplate), '')
FROM pg_roles r WHERE r.rolname NOT LIKE 'pg\_%' ORDER BY r.rolname`

// DiscoverPrivilegedAccounts lists the PostgreSQL roles that are superusers,
// may create roles or databases, replicate, bypass row security, belong to a
// superuser or a powerful predefined role, or own a database. A superuser's
// memberships are not listed: PostgreSQL counts it a member of every role.
func (b *PostgresBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	conn, err := pgconn.Connect(ctx, secrettext.String(b.dsn.Bytes()))
	if err != nil {
		return nil, classifyPostgresSignIn(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if err := conn.Exec(ctx, "BEGIN READ ONLY").Close(); err != nil {
		return nil, err
	}
	defer func() { _ = conn.Exec(context.WithoutCancel(ctx), "ROLLBACK").Close() }()
	result := conn.ExecParams(ctx, postgresDiscoverRoles, [][]byte{[]byte("{" + strings.Join(postgresPowerfulRoles, ",") + "}")}, nil, nil, nil).Read()
	if result.Err != nil {
		return nil, result.Err
	}
	var accounts []pamdiscovery.Account
	for _, row := range result.Rows {
		if len(row) != 11 {
			return nil, errors.New("dynsecret postgres: unexpected discovery row")
		}
		name := string(row[0])
		if b.usernamePrefix != "" && strings.HasPrefix(name, b.usernamePrefix) {
			continue
		}
		var privileges []string
		for i, attr := range []string{"superuser", "createrole", "createdb", "replication", "bypassrls"} {
			if string(row[1+i]) == "t" {
				privileges = append(privileges, attr)
			}
		}
		for _, role := range splitList(string(row[8])) {
			privileges = append(privileges, "member:"+role)
		}
		for _, role := range splitList(string(row[9])) {
			privileges = append(privileges, "member_of_superuser:"+role)
		}
		for _, db := range splitList(string(row[10])) {
			privileges = append(privileges, "owns_database:"+db)
		}
		if len(privileges) == 0 {
			continue
		}
		details := map[string]string{"can_login": boolText(string(row[6]) == "t")}
		if until := string(row[7]); until != "" {
			details["valid_until"] = until
		}
		accounts = append(accounts, pamdiscovery.Account{Key: "role:" + name, Name: name, Kind: pamdiscovery.KindDatabaseRole,
			Privileges: privileges, Disabled: string(row[6]) != "t", Details: details})
		if len(accounts) > pamdiscovery.MaxAccounts {
			return nil, errors.New("dynsecret postgres: more privileged roles than one discovery holds")
		}
	}
	return pamdiscovery.Normalize(accounts), nil
}

// mysqlGlobalPrivileges are the global privileges that administer a server.
var mysqlGlobalPrivileges = []string{"Super_priv", "Grant_priv", "Create_user_priv", "Shutdown_priv", "File_priv", "Process_priv",
	"Reload_priv", "Repl_slave_priv"}

// mysqlDynamicPrivileges are the dynamic privileges that administer a
// server.
var mysqlDynamicPrivileges = []string{"SYSTEM_USER", "SYSTEM_VARIABLES_ADMIN", "CONNECTION_ADMIN", "ROLE_ADMIN", "AUDIT_ADMIN",
	"BINLOG_ADMIN", "ENCRYPTION_KEY_ADMIN", "GROUP_REPLICATION_ADMIN", "REPLICATION_SLAVE_ADMIN", "PERSIST_RO_VARIABLES_ADMIN",
	"SET_ANY_DEFINER", "SET_USER_ID", "SERVICE_CONNECTION_ADMIN", "TABLE_ENCRYPTION_ADMIN"}

type sqlQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// DiscoverPrivilegedAccounts lists the MySQL accounts that hold a server
// administration privilege (global or dynamic) or may write the grant
// tables.
func (b *MySQLBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	q, ok := b.exec.(sqlQuerier)
	if !ok {
		return nil, ErrDiscoveryNotSupported
	}
	columns := strings.Join(mysqlGlobalPrivileges, ", ")
	rows, err := q.QueryContext(ctx, "SELECT User, Host, "+columns+", account_locked, password_expired FROM mysql.user ORDER BY User, Host") // #nosec G202 -- fixed column names, no input (CWE-89)
	if err != nil {
		return nil, err
	}
	byKey := map[string]*pamdiscovery.Account{}
	var order []string
	for rows.Next() {
		values := make([]sql.NullString, 4+len(mysqlGlobalPrivileges))
		dest := make([]any, len(values))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			_ = rows.Close()
			return nil, err
		}
		user, host := values[0].String, values[1].String
		key := "user:" + user + "@" + host
		account := &pamdiscovery.Account{Key: key, Name: user + "@" + host, Kind: pamdiscovery.KindDatabaseUser,
			Disabled: values[2+len(mysqlGlobalPrivileges)].String == "Y",
			Details:  map[string]string{"password_expired": boolText(values[3+len(mysqlGlobalPrivileges)].String == "Y")}}
		for i, column := range mysqlGlobalPrivileges {
			if values[2+i].String == "Y" {
				account.Privileges = append(account.Privileges, strings.ToLower(strings.TrimSuffix(column, "_priv")))
			}
		}
		byKey[key] = account
		order = append(order, key)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	dynamic, err := q.QueryContext(ctx, "SELECT USER, HOST, PRIV FROM mysql.global_grants ORDER BY USER, HOST, PRIV")
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, p := range mysqlDynamicPrivileges {
		wanted[p] = true
	}
	for dynamic.Next() {
		var user, host, priv string
		if err := dynamic.Scan(&user, &host, &priv); err != nil {
			_ = dynamic.Close()
			return nil, err
		}
		if a := byKey["user:"+user+"@"+host]; a != nil && wanted[priv] {
			a.Privileges = append(a.Privileges, strings.ToLower(priv))
		}
	}
	if err := dynamic.Close(); err != nil {
		return nil, err
	}
	grantTables, err := q.QueryContext(ctx, "SELECT User, Host FROM mysql.db WHERE Db = 'mysql' AND (Insert_priv = 'Y' OR Update_priv = 'Y' OR Delete_priv = 'Y')")
	if err != nil {
		return nil, err
	}
	for grantTables.Next() {
		var user, host string
		if err := grantTables.Scan(&user, &host); err != nil {
			_ = grantTables.Close()
			return nil, err
		}
		if a := byKey["user:"+user+"@"+host]; a != nil {
			a.Privileges = append(a.Privileges, "writes_grant_tables")
		}
	}
	if err := grantTables.Close(); err != nil {
		return nil, err
	}
	var accounts []pamdiscovery.Account
	for _, key := range order {
		a := byKey[key]
		user := strings.TrimPrefix(strings.SplitN(a.Name, "@", 2)[0], "")
		if len(a.Privileges) == 0 || (b.usernamePrefix != "" && strings.HasPrefix(user, b.usernamePrefix)) ||
			strings.HasPrefix(user, "mysql.") {
			continue
		}
		accounts = append(accounts, *a)
	}
	if len(accounts) > pamdiscovery.MaxAccounts {
		return nil, errors.New("dynsecret mysql: more privileged accounts than one discovery holds")
	}
	return pamdiscovery.Normalize(accounts), nil
}

// DiscoverPrivilegedAccounts reads the host's accounts with the fixed
// read-only inventory as its administrator.
func (b *UnixAccountsBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	var inv crypto.SSHAccountInventory
	err := b.adminKey.Use(func(key []byte) error {
		var err error
		inv, err = crypto.ReadSSHAccountInventory(ctx, b.target, key)
		return err
	})
	if err != nil {
		return nil, err
	}
	host := pamdiscovery.HostInventory{Passwd: inv.Passwd, Group: inv.Group, KeyFiles: inv.KeyFiles, KeysCommand: inv.KeysCommand}
	for _, f := range inv.Sudoers {
		host.Sudoers = append(host.Sudoers, pamdiscovery.SudoersFile{Path: f.Path, Readable: f.Readable, Lines: f.Lines})
	}
	for _, k := range inv.Keys {
		keys := pamdiscovery.AccountKeys{Account: k.Account, Readable: k.Readable}
		for _, key := range k.Keys {
			keys.Keys = append(keys.Keys, pamdiscovery.AuthorizedKey{Type: key.Type, Fingerprint: key.Fingerprint, Restricted: key.Restricted})
		}
		host.Keys = append(host.Keys, keys)
	}
	accounts := pamdiscovery.HostAccounts(host)
	if len(accounts) > pamdiscovery.MaxAccounts {
		return nil, errors.New("dynsecret unix: more privileged accounts than one discovery holds")
	}
	return accounts, nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// mssqlServerRoles are the fixed server roles that administer SQL Server.
var mssqlServerRoles = map[string]bool{"sysadmin": true, "securityadmin": true, "serveradmin": true, "setupadmin": true,
	"processadmin": true, "diskadmin": true, "dbcreator": true, "bulkadmin": true}

const mssqlDiscoverLogins = `SELECT p.name, p.type_desc, p.is_disabled,
  COALESCE((SELECT STRING_AGG(r.name, ',') WITHIN GROUP (ORDER BY r.name) FROM sys.server_role_members m
    JOIN sys.server_principals r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = p.principal_id), ''),
  CASE WHEN EXISTS (SELECT 1 FROM sys.server_permissions sp WHERE sp.grantee_principal_id = p.principal_id
    AND sp.permission_name = 'CONTROL SERVER' AND sp.state IN ('G', 'W')) THEN 1 ELSE 0 END
FROM sys.server_principals p WHERE p.type IN ('S', 'U', 'G', 'E', 'X') AND p.name NOT LIKE '##%' ORDER BY p.name`

// DiscoverPrivilegedAccounts lists the SQL Server logins that belong to a
// fixed server role that administers the server, or hold CONTROL SERVER. A
// contained database (Azure SQL) has no server logins to read.
func (b *MSSQLBackend) DiscoverPrivilegedAccounts(ctx context.Context) ([]pamdiscovery.Account, error) {
	q, ok := b.exec.(sqlQuerier)
	if !ok || b.contained {
		return nil, ErrDiscoveryNotSupported
	}
	rows, err := q.QueryContext(ctx, mssqlDiscoverLogins)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var accounts []pamdiscovery.Account
	for rows.Next() {
		var name, kind, roles string
		var disabled bool
		var control int
		if err := rows.Scan(&name, &kind, &disabled, &roles, &control); err != nil {
			return nil, err
		}
		if b.prefix != "" && strings.HasPrefix(name, b.prefix) {
			continue
		}
		var privileges []string
		for _, role := range splitList(roles) {
			if mssqlServerRoles[role] {
				privileges = append(privileges, role)
			}
		}
		if control == 1 {
			privileges = append(privileges, "control_server")
		}
		if len(privileges) == 0 {
			continue
		}
		accounts = append(accounts, pamdiscovery.Account{Key: "login:" + name, Name: name, Kind: pamdiscovery.KindSQLLogin,
			Privileges: privileges, Disabled: disabled, Details: map[string]string{"type": strings.ToLower(kind)}})
		if len(accounts) > pamdiscovery.MaxAccounts {
			return nil, errors.New("dynsecret mssql: more privileged logins than one discovery holds")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return pamdiscovery.Normalize(accounts), nil
}
