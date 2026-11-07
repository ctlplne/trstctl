// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pamsignin"
	"trstctl.com/trstctl/internal/secrettext"
)

// A274: bypass detection. A backend that can read its target's sign-in
// records does so through its administrator connection, for the named
// managed accounts only, and returns their metadata — never a credential
// or what a session did.

// SignInReader reads a target's sign-ins of the named accounts since a time.
type SignInReader interface {
	ReadSignIns(ctx context.Context, accounts []string, since time.Time) ([]pamsignin.SignIn, string, error)
}

// ErrSignInsNotSupported is a backend whose target's sign-ins cannot be read.
var ErrSignInsNotSupported = errors.New("dynsecret: this target's sign-ins cannot be read")

// Collectors: what read a sign-in, for the finding's evidence.
const (
	CollectorSSHD           = "sshd"
	CollectorWindowsLogon   = "windows_security_4624"
	CollectorPostgresAct    = "pg_stat_activity"
	CollectorMySQLThreads   = "performance_schema_threads"
	CollectorSQLServerLogin = "sys_dm_exec_sessions"
)

// ReadSignIns reads the host's sshd sign-ins (Linux and Unix: the journal
// and the auth log files) or its Security log's logon events (Windows over
// OpenSSH), with the fixed read-only script as the provider's administrator.
func (b *UnixAccountsBackend) ReadSignIns(ctx context.Context, accounts []string, since time.Time) ([]pamsignin.SignIn, string, error) {
	if err := pamsignin.ValidAccounts(accounts); err != nil {
		return nil, "", err
	}
	var raw []byte
	err := b.adminKey.Use(func(key []byte) error {
		var err error
		raw, err = crypto.ReadSSHSignInReport(ctx, b.target, key, accounts, since)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	if b.target.Windows {
		signIns, err := pamsignin.ParseWindowsReport(raw, accounts, since)
		return signIns, CollectorWindowsLogon, err
	}
	signIns, err := pamsignin.ParseSSHReport(raw, time.Now(), accounts, since)
	return signIns, CollectorSSHD, err
}

// postgresSignIns are the client sessions of the named roles a PostgreSQL
// server holds now, with when each began and its client's address.
const postgresSignIns = `SELECT usename, COALESCE(host(client_addr), ''),
  to_char(backend_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), pid::text
FROM pg_stat_activity
WHERE backend_type = 'client backend' AND usename = ANY($1::text[]) AND backend_start >= $2::timestamptz
ORDER BY backend_start, pid`

// ReadSignIns reads the sessions of the named roles the server holds now
// (pg_stat_activity, in a read-only transaction): each with when it began.
// A session that began and ended between two collections is not seen.
func (b *PostgresBackend) ReadSignIns(ctx context.Context, accounts []string, since time.Time) ([]pamsignin.SignIn, string, error) {
	if err := pamsignin.ValidAccounts(accounts); err != nil {
		return nil, "", err
	}
	conn, err := pgconn.Connect(ctx, secrettext.String(b.dsn.Bytes()))
	if err != nil {
		return nil, "", classifyPostgresSignIn(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if err := conn.Exec(ctx, "BEGIN READ ONLY").Close(); err != nil {
		return nil, "", err
	}
	defer func() { _ = conn.Exec(context.WithoutCancel(ctx), "ROLLBACK").Close() }()
	names := make([]string, len(accounts))
	for i, a := range accounts {
		names[i] = `"` + strings.ReplaceAll(a, `\`, `\\`) + `"`
	}
	result := conn.ExecParams(ctx, postgresSignIns, [][]byte{[]byte("{" + strings.Join(names, ",") + "}"), []byte(since.UTC().Format(time.RFC3339Nano))}, nil, nil, nil).Read()
	if result.Err != nil {
		return nil, "", result.Err
	}
	var out []pamsignin.SignIn
	for _, row := range result.Rows {
		if len(row) != 4 {
			return nil, "", errors.New("dynsecret postgres: unexpected sign-in row")
		}
		at, err := time.Parse(time.RFC3339Nano, string(row[2]))
		if err != nil {
			return nil, "", errors.New("dynsecret postgres: unreadable session start")
		}
		out = append(out, pamsignin.SignIn{Account: string(row[0]), At: at, Source: string(row[1]), Method: "database",
			Ref: "pid " + string(row[3]) + "@" + string(row[2])})
	}
	return out, CollectorPostgresAct, nil
}

// mysqlSignIns are the foreground connections of the named accounts a MySQL
// server holds now. MySQL keeps no connection start time, so a connection is
// dated when a collection first sees it, no earlier than the previous one.
const mysqlSignIns = `SELECT t.PROCESSLIST_USER, COALESCE(t.PROCESSLIST_HOST, ''), t.PROCESSLIST_ID,
  DATE_FORMAT(UTC_TIMESTAMP(6) - INTERVAL (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Uptime') SECOND, '%Y-%m-%dT%H:%i:%sZ')
FROM performance_schema.threads t
WHERE t.TYPE = 'FOREGROUND' AND t.PROCESSLIST_USER IS NOT NULL`

// ReadSignIns reads the named accounts' connections the server holds now
// (performance_schema.threads): each first seen now, after since.
func (b *MySQLBackend) ReadSignIns(ctx context.Context, accounts []string, since time.Time) ([]pamsignin.SignIn, string, error) {
	if err := pamsignin.ValidAccounts(accounts); err != nil {
		return nil, "", err
	}
	q, ok := b.exec.(sqlQuerier)
	if !ok {
		return nil, "", ErrSignInsNotSupported
	}
	managed := map[string]bool{}
	for _, a := range accounts {
		managed[a] = true
	}
	rows, err := q.QueryContext(ctx, mysqlSignIns)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	now := time.Now().UTC()
	var out []pamsignin.SignIn
	for rows.Next() {
		var user, host, id, booted string
		if err := rows.Scan(&user, &host, &id, &booted); err != nil {
			return nil, "", err
		}
		if !managed[user] {
			continue
		}
		if i := strings.LastIndexByte(host, ':'); i > 0 {
			host = host[:i]
		}
		// The connection id is unique for one server start: the reference
		// names both, so a later collection seeing it again is the same
		// sign-in.
		out = append(out, pamsignin.SignIn{Account: user, At: now, Earliest: since.UTC(), Source: host, Method: "database",
			Ref: "connection " + id + " since " + booted})
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return out, CollectorMySQLThreads, nil
}

// mssqlSignIns are the user sessions of the named logins a SQL Server holds
// now, with when each logged in (in UTC) and its client's address.
const mssqlSignIns = `SELECT s.login_name, COALESCE(c.client_net_address, ''),
  CONVERT(varchar(33), DATEADD(minute, DATEDIFF(minute, GETDATE(), GETUTCDATE()), s.login_time), 126), CAST(s.session_id AS varchar(12))
FROM sys.dm_exec_sessions s LEFT JOIN sys.dm_exec_connections c ON c.session_id = s.session_id
WHERE s.is_user_process = 1`

// ReadSignIns reads the named logins' sessions the server holds now
// (sys.dm_exec_sessions), each with its login time.
func (b *MSSQLBackend) ReadSignIns(ctx context.Context, accounts []string, since time.Time) ([]pamsignin.SignIn, string, error) {
	if err := pamsignin.ValidAccounts(accounts); err != nil {
		return nil, "", err
	}
	q, ok := b.exec.(sqlQuerier)
	if !ok || b.contained {
		return nil, "", ErrSignInsNotSupported
	}
	managed := map[string]bool{}
	for _, a := range accounts {
		managed[strings.ToLower(a)] = true
	}
	rows, err := q.QueryContext(ctx, mssqlSignIns)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	var out []pamsignin.SignIn
	for rows.Next() {
		var login, address, loginTime, sessionID string
		if err := rows.Scan(&login, &address, &loginTime, &sessionID); err != nil {
			return nil, "", err
		}
		if !managed[strings.ToLower(login)] {
			continue
		}
		at, err := time.Parse("2006-01-02T15:04:05", loginTime)
		if err != nil || at.Before(since) {
			continue
		}
		out = append(out, pamsignin.SignIn{Account: login, At: at.UTC(), Source: address, Method: "database", Ref: "session " + sessionID + "@" + loginTime})
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return out, CollectorSQLServerLogin, nil
}
