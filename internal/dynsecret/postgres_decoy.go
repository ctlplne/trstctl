// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Decoy database logins (Q6). A PostgreSQL provider whose allowed roles
// include DecoyRole mints bait logins: a LOGIN role with CONNECT on its own
// empty database and on nothing else. trstctl never connects with the bait, so
// the database's session counter (pg_stat_database.sessions, PostgreSQL 14+)
// counts only uses of it. A TLS or port probe establishes no session, so
// scanning the server never looks like a login.

// DecoyRole is the dynamic-secret role name that mints a decoy login.
const DecoyRole = "decoy"

// Nothing in a decoy's DSN may say "decoy": the login is named like any other
// generated application login of the provider and its database after the
// login. A login name is at most 60 characters, so the database name stays
// within PostgreSQL's 63.
const (
	decoyLoginFragment    = "app"
	decoyDatabaseSuffix   = "_db"
	decoyLoginNameMaximum = 63 - len(decoyDatabaseSuffix)
)

// DecoyDatabaseName is the database a decoy login role was minted for.
func DecoyDatabaseName(role string) string { return role + decoyDatabaseSuffix }

// errPostgresDecoyCreate never carries the generated password or DSN.
var errPostgresDecoyCreate = errors.New("dynsecret postgres: create decoy login failed")

// createDecoyCredential mints the bait: its own database (no PUBLIC connect),
// a login role valid for the lease, and CONNECT on that database only. The
// returned DSN names the decoy database, so the bait as found logs in there.
func (b *PostgresBackend) createDecoyCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	named := req
	named.Role = decoyLoginFragment
	user, err := scopedNameForRequest(b.usernamePrefix, named, decoyLoginNameMaximum, "_")
	if err != nil {
		return "", nil, err
	}
	// An interrupted attempt left this exact role and database; replace them.
	if err := b.Revoke(ctx, user); err != nil {
		return "", nil, fmt.Errorf("dynsecret postgres: clean interrupted decoy: %w", err)
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	conn, err := connectPostgresAdmin(ctx, b.dsn.Bytes())
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = conn.Close(ctx) }()
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	database := DecoyDatabaseName(user)
	// CREATE DATABASE cannot run inside a transaction. A database left by an
	// interrupted attempt for this same lease is reused, never a second one.
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, database).Scan(&exists); err != nil {
		return "", nil, errPostgresDecoyCreate
	}
	if !exists {
		if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgQuoteIdent(database)); err != nil {
			return "", nil, errPostgresDecoyCreate
		}
	}
	if _, err := conn.Exec(ctx, "REVOKE CONNECT, TEMPORARY ON DATABASE "+pgQuoteIdent(database)+" FROM PUBLIC"); err != nil {
		return "", nil, errPostgresDecoyCreate
	}
	if err := createPostgresRole(ctx, conn, user, password, time.Now().UTC().Add(ttl).Format("2006-01-02 15:04:05Z")); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, errPostgresDecoyCreate
	}
	if _, err := conn.Exec(ctx, "GRANT CONNECT ON DATABASE "+pgQuoteIdent(database)+" TO "+pgQuoteIdent(user)); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, errPostgresDecoyCreate
	}
	dsn, err := postgresDecoyDSN(b.dsn.Bytes(), user, password, database)
	if err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, err
	}
	return user, dsn, nil
}

// dropDecoyDatabase removes a decoy's own database. Revoke runs for every
// lease, so only a database with exactly the decoy's shape is dropped: named
// after the role, connectable by that role and closed to PUBLIC. No database an
// operator made matches that by accident.
func dropDecoyDatabase(ctx context.Context, conn *pgx.Conn, role string) error {
	database := DecoyDatabaseName(role)
	var decoy bool
	if err := conn.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM pg_database d
		   WHERE d.datname = $1
		     AND CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $2)
		              THEN has_database_privilege($2, d.oid, 'CONNECT')
		                   AND NOT has_database_privilege('public', d.oid, 'CONNECT')
		              ELSE false END)`, database, role).Scan(&decoy); err != nil {
		return fmt.Errorf("dynsecret postgres: lookup decoy database: %w", err)
	}
	if !decoy {
		return nil
	}
	if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgQuoteIdent(database)+" WITH (FORCE)"); err != nil {
		return fmt.Errorf("dynsecret postgres: drop decoy database: %w", err)
	}
	return nil
}

// DecoySessions returns how many sessions were ever established to the
// decoy's own database (since the server's statistics were last reset) and
// whether that database still exists.
func (b *PostgresBackend) DecoySessions(ctx context.Context, role string) (int64, bool, error) {
	conn, err := connectPostgresAdmin(ctx, b.dsn.Bytes())
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = conn.Close(ctx) }()
	var sessions int64
	err = conn.QueryRow(ctx, `SELECT sessions FROM pg_stat_database WHERE datname = $1`, DecoyDatabaseName(role)).Scan(&sessions)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("dynsecret postgres: read decoy sessions: %w", err)
	}
	return sessions, true, nil
}

// DecoyElsewhere returns the other databases the decoy login has a session in
// now (Q6-L8). The login has CONNECT only on its own database, but PUBLIC
// keeps CONNECT on databases such as postgres, and PostgreSQL has no per-role
// refusal of it; a session there does not count on the decoy's own database,
// so the watcher reads the server's live sessions for the role as well. A
// session that opens and closes between two checks is not seen.
func (b *PostgresBackend) DecoyElsewhere(ctx context.Context, role string) ([]string, error) {
	conn, err := connectPostgresAdmin(ctx, b.dsn.Bytes())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close(ctx) }()
	rows, err := conn.Query(ctx, `
		SELECT DISTINCT datname FROM pg_stat_activity
		 WHERE usename = $1 AND datname IS NOT NULL AND datname <> $2
		 ORDER BY datname`, role, DecoyDatabaseName(role))
	if err != nil {
		return nil, fmt.Errorf("dynsecret postgres: read decoy sessions elsewhere: %w", err)
	}
	defer rows.Close()
	var databases []string
	for rows.Next() {
		var database string
		if err := rows.Scan(&database); err != nil {
			return nil, fmt.Errorf("dynsecret postgres: read decoy sessions elsewhere: %w", err)
		}
		databases = append(databases, database)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dynsecret postgres: read decoy sessions elsewhere: %w", err)
	}
	return databases, nil
}

// postgresDecoyDSN is the credential DSN with the decoy database in place of
// the admin database: the URI path is replaced, a keyword DSN gets dbname.
func postgresDecoyDSN(adminDSN []byte, user string, password []byte, database string) ([]byte, error) {
	dsn, err := postgresCredentialDSN(adminDSN, user, password)
	if err != nil {
		return nil, err
	}
	scheme, _, authorityEnd, _, ok := splitURIAuthority(dsn)
	if !ok || (!bytes.EqualFold(scheme, []byte("postgres")) && !bytes.EqualFold(scheme, []byte("postgresql"))) {
		return append(dsn, []byte(" dbname="+database)...), nil
	}
	rest := dsn[authorityEnd:]
	tail := bytes.IndexAny(rest, "?#")
	if tail < 0 {
		tail = len(rest)
	}
	out := make([]byte, 0, len(dsn)+len(database)+1)
	out = append(out, dsn[:authorityEnd]...)
	out = append(out, '/')
	out = append(out, database...)
	out = append(out, rest[tail:]...)
	secret.Wipe(dsn)
	return out, nil
}
