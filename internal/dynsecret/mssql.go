// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	mssql "github.com/microsoft/go-mssqldb"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

var (
	mssqlRole     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_@#$]{0,127}$`)
	mssqlDatabase = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_@#$-]{0,127}$`)
	mssqlUser     = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
)

// The T-SQL below never carries the generated password in its text: it arrives
// as a varbinary parameter, and SQL Server quotes it into the statement it
// executes itself. Every name is passed as a parameter and quoted with
// QUOTENAME; only the validated database name is spliced into the statement
// that switches databases, bracket-quoted.
const (
	mssqlUpsertLogin = `DECLARE @pw nvarchar(128) = CONVERT(nvarchar(128), CONVERT(varchar(128), @password));
DECLARE @stmt nvarchar(max);
IF SUSER_ID(@login) IS NULL
	SET @stmt = N'CREATE LOGIN ' + QUOTENAME(@login) + N' WITH PASSWORD = ' + QUOTENAME(@pw, N'''') +
		N', DEFAULT_DATABASE = ' + QUOTENAME(@db) + N', CHECK_EXPIRATION = OFF, CHECK_POLICY = ON';
ELSE
	SET @stmt = N'ALTER LOGIN ' + QUOTENAME(@login) + N' WITH PASSWORD = ' + QUOTENAME(@pw, N'''') +
		N'; ALTER LOGIN ' + QUOTENAME(@login) + N' ENABLE';
SET @pw = NULL;
EXEC (@stmt);`
	mssqlEnsureUser = `IF DATABASE_PRINCIPAL_ID(@login) IS NULL
BEGIN
	DECLARE @stmt nvarchar(max) = N'CREATE USER ' + QUOTENAME(@login) + N' FOR LOGIN ' + QUOTENAME(@login);
	EXEC (@stmt);
END`
	mssqlUpsertContainedUser = `DECLARE @pw nvarchar(128) = CONVERT(nvarchar(128), CONVERT(varchar(128), @password));
DECLARE @stmt nvarchar(max);
IF DATABASE_PRINCIPAL_ID(@login) IS NULL
	SET @stmt = N'CREATE USER ' + QUOTENAME(@login) + N' WITH PASSWORD = ' + QUOTENAME(@pw, N'''');
ELSE
	SET @stmt = N'ALTER USER ' + QUOTENAME(@login) + N' WITH PASSWORD = ' + QUOTENAME(@pw, N'''');
SET @pw = NULL;
EXEC (@stmt);`
	mssqlAddRole = `IF ISNULL(IS_ROLEMEMBER(@role, @login), 0) = 0
BEGIN
	DECLARE @stmt nvarchar(max) = N'ALTER ROLE ' + QUOTENAME(@role) + N' ADD MEMBER ' + QUOTENAME(@login);
	EXEC (@stmt);
END`
	// mssqlEndSessions disables the login (when there is one) so no session
	// starts while the others are killed: SQL Server keeps a dropped principal's
	// open sessions, and refuses to drop a login that is logged in.
	mssqlEndSessions = `IF SUSER_ID(@login) IS NOT NULL AND @contained = 0
BEGIN
	DECLARE @disable nvarchar(max) = N'ALTER LOGIN ' + QUOTENAME(@login) + N' DISABLE';
	EXEC (@disable);
END
DECLARE @kill nvarchar(max) = N'';
SELECT @kill = @kill + N'KILL ' + CONVERT(nvarchar(11), session_id) + N';'
	FROM sys.dm_exec_sessions WHERE (login_name = @login OR original_login_name = @login) AND session_id <> @@SPID;
EXEC (@kill);`
	mssqlDropUser = `IF DATABASE_PRINCIPAL_ID(@login) IS NOT NULL
BEGIN
	DECLARE @stmt nvarchar(max) = N'DROP USER ' + QUOTENAME(@login);
	EXEC (@stmt);
END`
	mssqlDropLogin = `IF SUSER_ID(@login) IS NOT NULL
BEGIN
	DECLARE @stmt nvarchar(max) = N'DROP LOGIN ' + QUOTENAME(@login);
	EXEC (@stmt);
END`
)

// MSSQLConfig configures the SQL Server and Azure SQL providers (A239).
type MSSQLConfig struct {
	// Contained makes each lease a contained database user (Azure SQL
	// Database, or a SQL Server database with partial containment) instead of
	// a server login with a user in Database.
	Contained bool
	Database  string
	// RoleBindings maps each allowed role to the database roles its users
	// join, comma separated, for example "db_datareader".
	RoleBindings   map[string]string
	UsernamePrefix string
}

// MSSQLBackend issues SQL Server logins (or contained database users) with
// database role memberships.
type MSSQLBackend struct {
	exec      SQLExecutor
	contained bool
	database  string
	roles     map[string][]string
	prefix    string
}

// NewMSSQLBackend validates cfg; exec runs as an administrator allowed to
// manage logins (or, contained, users) and end sessions.
func NewMSSQLBackend(exec SQLExecutor, cfg MSSQLConfig) (*MSSQLBackend, error) {
	if exec == nil {
		return nil, errors.New("dynsecret mssql: executor required")
	}
	if !mssqlDatabase.MatchString(cfg.Database) {
		return nil, errors.New("dynsecret mssql: database must be a plain database name")
	}
	b := &MSSQLBackend{exec: exec, contained: cfg.Contained, database: cfg.Database, roles: map[string][]string{}, prefix: cfg.UsernamePrefix}
	for role, binding := range cfg.RoleBindings {
		for _, name := range strings.Split(binding, ",") {
			name = strings.TrimSpace(name)
			if !mssqlRole.MatchString(name) {
				return nil, fmt.Errorf("dynsecret mssql: role %q: %q is not a database role name", role, name)
			}
			b.roles[role] = append(b.roles[role], name)
		}
	}
	if len(b.roles) == 0 {
		return nil, errors.New("dynsecret mssql: every allowed role needs database roles in role_bindings")
	}
	return b, nil
}

// inDatabase runs statement in the configured database through its
// sp_executesql, with @login (and the extra parameters) bound.
func (b *MSSQLBackend) inDatabase(ctx context.Context, statement, declarations string, args ...any) error {
	quoted := "[" + strings.ReplaceAll(b.database, "]", "]]") + "]"
	_, err := b.exec.ExecContext(ctx, "EXEC "+quoted+".sys.sp_executesql @statement, N'"+declarations+"', "+mssqlArgList(declarations),
		append([]any{sql.Named("statement", statement)}, args...)...)
	return err
}

// mssqlArgList passes each declared parameter through by name ("@a = @a").
func mssqlArgList(declarations string) string {
	var out []string
	for _, declaration := range strings.Split(declarations, ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(declaration), " ")
		out = append(out, name+" = "+name)
	}
	return strings.Join(out, ", ")
}

// Create implements Backend.
func (b *MSSQLBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

// CreateCredential implements RequestBackend. The principal's name derives
// from the lease, and every step finds what an earlier attempt left (the login
// or user gets the new password, an existing membership stays), so a retry
// after an uncertain attempt converges on one principal. If a role
// membership fails, the new principal is removed again.
func (b *MSSQLBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.Static {
		return "", nil, errors.New("dynsecret mssql: static credentials are not served")
	}
	roles, ok := b.roles[req.Role]
	if !ok {
		return "", nil, fmt.Errorf("dynsecret mssql: role %q has no database roles", req.Role)
	}
	user, err := scopedNameForRequest(b.prefix, req, 128, "_")
	if err != nil {
		return "", nil, err
	}
	if !mssqlUser.MatchString(user) {
		return "", nil, fmt.Errorf("dynsecret mssql: generated user name %q is not plain", user)
	}
	password, err := randomPolicyPassword(32)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	login, pw := sql.Named("login", user), sql.Named("password", password)
	if b.contained {
		err = b.inDatabase(ctx, mssqlUpsertContainedUser, "@login sysname, @password varbinary(256)", login, pw)
	} else if _, err = b.exec.ExecContext(ctx, mssqlUpsertLogin, login, pw, sql.Named("db", b.database)); err == nil {
		err = b.inDatabase(ctx, mssqlEnsureUser, "@login sysname", login)
	}
	if err != nil {
		// Driver errors can quote statement text; only the error number leaves.
		return "", nil, fmt.Errorf("dynsecret mssql: create %s failed (%s)", user, mssqlErrorNumber(err))
	}
	for _, role := range roles {
		if err := b.inDatabase(ctx, mssqlAddRole, "@login sysname, @role sysname", login, sql.Named("role", role)); err != nil {
			_ = b.Revoke(ctx, user)
			return "", nil, fmt.Errorf("dynsecret mssql: add %s to role %s failed (%s)", user, role, mssqlErrorNumber(err))
		}
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the lease credential is this provider's output: the outbox seals it and only the authorized issue response opens it (CWE-200)
		Username string           `json:"username"`
		Password secret.JSONBytes `json:"password"`
		Database string           `json:"database"`
	}{Username: user, Password: password, Database: b.database})
	if err != nil {
		return "", nil, err
	}
	return user, credential, nil
}

// Revoke implements Backend: the login is disabled and the principal's open
// sessions are killed (SQL Server keeps a dropped principal's sessions), then
// the database user and the login are dropped, so its next login fails. Only
// principals this provider names are touched; one already gone counts as
// revoked.
func (b *MSSQLBackend) Revoke(ctx context.Context, ref string) error {
	if !mssqlUser.MatchString(ref) || !issuedPrincipalName(b.prefix, ref) {
		return fmt.Errorf("dynsecret mssql: refusing to revoke %q, which this provider did not create", ref)
	}
	login := sql.Named("login", ref)
	contained := 0
	if b.contained {
		contained = 1
	}
	if _, err := b.exec.ExecContext(ctx, mssqlEndSessions, login, sql.Named("contained", contained)); err != nil {
		return fmt.Errorf("dynsecret mssql: end the sessions of %s failed (%s)", ref, mssqlErrorNumber(err))
	}
	if err := b.inDatabase(ctx, mssqlDropUser, "@login sysname", login); err != nil {
		return fmt.Errorf("dynsecret mssql: drop user %s failed (%s)", ref, mssqlErrorNumber(err))
	}
	if !b.contained {
		if _, err := b.exec.ExecContext(ctx, mssqlDropLogin, login); err != nil {
			return fmt.Errorf("dynsecret mssql: drop login %s failed (%s)", ref, mssqlErrorNumber(err))
		}
	}
	return nil
}

// mssqlErrorNumber names a SQL Server error by its number only.
func mssqlErrorNumber(err error) string {
	var server mssql.Error
	if errors.As(err, &server) {
		return fmt.Sprintf("SQL Server error %d", server.Number)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err.Error()
	}
	return "connection error"
}

// OpenMSSQLExecutor opens and verifies a go-mssqldb client from an admin DSN
// (sqlserver://user:password@host:1433?database=master). Callers close it after
// the operation, keeping the authority-bearing DSN out of long-lived state.
func OpenMSSQLExecutor(ctx context.Context, adminDSN []byte) (*sql.DB, error) {
	adminDSN = bytes.TrimRight(adminDSN, "\r\n")
	if len(adminDSN) == 0 {
		return nil, errors.New("dynsecret mssql: admin DSN required")
	}
	db, err := sql.Open("sqlserver", secrettext.String(adminDSN))
	if err != nil {
		return nil, errors.New("dynsecret mssql: open admin connection failed")
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errors.New("dynsecret mssql: ping admin connection failed")
	}
	return db, nil
}

// randomPolicyPassword returns n characters drawn uniformly from upper and
// lower case letters and digits (rejection sampling, no modulo bias), with each
// class present, so a server enforcing Windows password complexity
// (CHECK_POLICY) accepts it.
func randomPolicyPassword(n int) ([]byte, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	const limit = 256 - 256%len(alphabet) // bytes at or above this are redrawn
	for attempt := 0; attempt < 32; attempt++ {
		out := make([]byte, 0, n)
		for len(out) < n {
			raw, err := crypto.RandomBytes(n)
			if err != nil {
				secret.Wipe(out)
				return nil, err
			}
			for _, b := range raw {
				if int(b) < limit && len(out) < n {
					out = append(out, alphabet[int(b)%len(alphabet)])
				}
			}
			secret.Wipe(raw)
		}
		var upper, lower, digit bool
		for _, c := range out {
			upper = upper || (c >= 'A' && c <= 'Z')
			lower = lower || (c >= 'a' && c <= 'z')
			digit = digit || (c >= '0' && c <= '9')
		}
		if upper && lower && digit {
			return out, nil
		}
		secret.Wipe(out)
	}
	return nil, errors.New("dynsecret: could not draw a complex password")
}
