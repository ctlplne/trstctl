// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/scram"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func connectPostgresAdmin(ctx context.Context, adminDSN []byte, transport *DatabaseTransport) (*pgx.Conn, error) {
	config, err := postgresDriverConfig(adminDSN, transport, dbdsn.Admin)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, errors.New("dynsecret postgres: connect failed")
	}
	return conn, nil
}

// createPostgresRole sends only a client-computed SCRAM verifier as a bytea
// bind parameter; even log_statement=all cannot record the lease password.
// PostgreSQL utility statements do not accept bind parameters in PASSWORD, so a
// transaction-local server setting carries the verifier into a short DO block. The
// dynamic SQL is built inside PostgreSQL; no Go string ever contains the secret.
func createPostgresRole(ctx context.Context, conn *pgx.Conn, user string, password []byte, validUntil string) error {
	verifier, err := scram.PostgreSQLVerifier(password)
	if err != nil {
		return errPostgresRoleCreate
	}
	defer secret.Wipe(verifier)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return errPostgresRoleCreate
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`SELECT set_config('trstctl.dynamic_secret_password', convert_from($1::bytea, 'UTF8'), true)`,
		verifier); err != nil {
		return errPostgresRoleCreate
	}
	statement := `DO $trstctl$
BEGIN
  EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L VALID UNTIL %L', ` +
		pgQuoteLiteral(user) + `, current_setting('trstctl.dynamic_secret_password'), ` + pgQuoteLiteral(validUntil) + `);
END
$trstctl$`
	if _, err := tx.Exec(ctx, statement); err != nil {
		return errPostgresRoleCreate
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.dynamic_secret_password', '', true)`); err != nil {
		return errPostgresRoleCreate
	}
	if err := tx.Commit(ctx); err != nil {
		return errPostgresRoleCreate
	}
	return nil
}

// setPostgresRolePassword gives an existing login role a new password, valid
// with no native expiry, keeping the password out of the statement text the
// way createPostgresRole does. It refuses a role that does not exist: a
// two-user account is provisioned, with its grants, by the database's owner.
func setPostgresRolePassword(ctx context.Context, conn *pgx.Conn, role string, password []byte) error {
	verifier, err := scram.PostgreSQLVerifier(password)
	if err != nil {
		return errPostgresRolePassword
	}
	defer secret.Wipe(verifier)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return errPostgresRolePassword
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1 AND rolcanlogin)`, role).Scan(&exists); err != nil || !exists {
		return fmt.Errorf("dynsecret postgres: two-user account %s is not a login role; provision it with the role's grants first", role)
	}
	if _, err := tx.Exec(ctx,
		`SELECT set_config('trstctl.dynamic_secret_password', convert_from($1::bytea, 'UTF8'), true)`,
		verifier); err != nil {
		return errPostgresRolePassword
	}
	statement := `DO $trstctl$
BEGIN
  EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L VALID UNTIL %L', ` +
		pgQuoteLiteral(role) + `, current_setting('trstctl.dynamic_secret_password'), 'infinity');
END
$trstctl$`
	if _, err := tx.Exec(ctx, statement); err != nil {
		return errPostgresRolePassword
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.dynamic_secret_password', '', true)`); err != nil {
		return errPostgresRolePassword
	}
	if err := tx.Commit(ctx); err != nil {
		return errPostgresRolePassword
	}
	return nil
}

// OpenMySQLExecutor opens and verifies an official go-sql-driver/mysql client.
// Callers close the returned pool immediately after one create/revoke operation;
// this keeps the authority-bearing admin DSN out of long-lived process state.
func OpenMySQLExecutor(ctx context.Context, adminDSN []byte) (*sql.DB, error) {
	return OpenMySQLExecutorWithTransport(ctx, adminDSN, nil)
}

// createMySQLUser keeps lease passwords out of separately logged SQL. MySQL
// 8.4 creates the password inside its redacted CREATE USER statement and
// returns it as a result row. MariaDB has no matching result form; it receives
// only a client-computed mysql_native_password verifier, never plaintext, in
// the session variable that constructs its CREATE USER statement.
func createMySQLUser(ctx context.Context, executor SQLExecutor, account, user, host string) ([]byte, error) {
	type connectionProvider interface {
		Conn(context.Context) (*sql.Conn, error)
	}
	provider, ok := executor.(connectionProvider)
	if !ok {
		// Test/third-party executors may natively support parameters in CREATE USER.
		// The shipped go-sql-driver/mysql path always takes a pinned branch below.
		password, err := randomSecretHex(24)
		if err != nil {
			return nil, errMySQLUserCreate
		}
		if _, err := executor.ExecContext(ctx, "CREATE USER "+account+" IDENTIFIED BY ?", password); err != nil {
			secret.Wipe(password)
			return nil, errMySQLUserCreate
		}
		return password, nil
	}
	conn, err := provider.Conn(ctx)
	if err != nil {
		return nil, errMySQLUserCreate
	}
	defer func() { _ = conn.Close() }()
	var version string
	if err := conn.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version); err != nil {
		return nil, errMySQLUserCreate
	}
	if strings.Contains(strings.ToLower(version), "mariadb") {
		return createMariaDBUser(ctx, conn, account)
	}
	rows, err := conn.QueryContext(ctx, "CREATE USER "+account+" IDENTIFIED BY RANDOM PASSWORD")
	if err != nil {
		return nil, errMySQLUserCreate
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return nil, errMySQLUserCreate
	}
	var gotUser, gotHost string
	var factor int
	var password []byte
	if err := rows.Scan(&gotUser, &gotHost, &password, &factor); err != nil {
		secret.Wipe(password)
		return nil, errMySQLUserCreate
	}
	if gotUser != user || gotHost != host || factor != 1 || len(password) == 0 || rows.Next() || rows.Err() != nil {
		secret.Wipe(password)
		return nil, errMySQLUserCreate
	}
	return password, nil
}

func createMariaDBUser(ctx context.Context, conn *sql.Conn, account string) ([]byte, error) {
	password, err := randomSecretHex(24)
	if err != nil {
		return nil, errMySQLUserCreate
	}
	succeeded := false
	defer func() {
		if !succeeded {
			secret.Wipe(password)
		}
	}()
	verifier, err := crypto.MySQLNativePasswordVerifier(password)
	if err != nil {
		return nil, errMySQLUserCreate
	}
	defer secret.Wipe(verifier)
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SET @trstctl_dynamic_password_verifier = NULL, @trstctl_create_user = NULL`)
	}()
	if _, err := conn.ExecContext(ctx, `SET @trstctl_dynamic_password_verifier = ?`, verifier); err != nil {
		return nil, errMySQLUserCreate
	}
	prefix := "CREATE USER " + account + " IDENTIFIED VIA mysql_native_password USING "
	if _, err := conn.ExecContext(ctx,
		`SET @trstctl_create_user = CONCAT(?, QUOTE(CONVERT(@trstctl_dynamic_password_verifier USING utf8mb4)))`,
		prefix); err != nil {
		return nil, errMySQLUserCreate
	}
	if _, err := conn.ExecContext(ctx, `PREPARE trstctl_create_user_stmt FROM @trstctl_create_user`); err != nil {
		return nil, errMySQLUserCreate
	}
	prepared := true
	defer func() {
		if prepared {
			_, _ = conn.ExecContext(context.Background(), `DEALLOCATE PREPARE trstctl_create_user_stmt`)
		}
	}()
	if _, err := conn.ExecContext(ctx, `EXECUTE trstctl_create_user_stmt`); err != nil {
		return nil, errMySQLUserCreate
	}
	if _, err := conn.ExecContext(ctx, `DEALLOCATE PREPARE trstctl_create_user_stmt`); err != nil {
		return nil, errMySQLUserCreate
	}
	prepared = false
	succeeded = true
	return password, nil
}

// MongoDriverAdmin is the official MongoDB-driver implementation of MongoAdmin.
// It is intentionally short-lived; production factories construct it only for a
// single create/revoke call and close it before returning.
type MongoDriverAdmin struct {
	client *mongo.Client
}

// CheckTwoUserRetirement refuses a sharded router. MongoDB documents that a
// role change on one mongos can take minutes to reach another router's user
// cache, so a local roles readback cannot prove retirement across the cluster.
func (a *MongoDriverAdmin) CheckTwoUserRetirement(ctx context.Context) error {
	if a == nil || a.client == nil {
		return errors.New("dynsecret mongodb: disconnected admin")
	}
	var hello struct {
		Msg string `bson:"msg"`
	}
	if err := a.client.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello); err != nil {
		return errors.New("dynsecret mongodb: cannot verify two-user retirement topology")
	}
	if hello.Msg == "isdbgrid" {
		return errors.New("dynsecret mongodb: two-user rotation cannot verify immediate role retirement across sharded routers")
	}
	return nil
}

// OpenMongoAdmin connects and pings a MongoDB deployment using an operator-owned
// admin URI. The driver receives the URI only for the lifetime of this adapter.
func OpenMongoAdmin(ctx context.Context, adminURI []byte) (*MongoDriverAdmin, error) {
	return OpenMongoAdminWithTransport(ctx, adminURI, nil)
}

// CreateUser implements MongoAdmin with MongoDB's native createUser command.
func (a *MongoDriverAdmin) CreateUser(ctx context.Context, db, user string, password []byte, roles []MongoRole) error {
	if a == nil || a.client == nil {
		return errors.New("dynsecret mongodb: disconnected admin")
	}
	cmd := mongoCreateUserCommand(user, password, roles)
	defer secret.Wipe(cmd)
	if err := a.client.Database(db).RunCommand(ctx, bson.Raw(cmd)).Err(); err != nil {
		// Driver/server errors may include the command document. Keep the generated
		// password out of the returned immutable error string.
		return errors.New("createUser failed")
	}
	return nil
}

// SetUserPassword implements MongoAdmin with MongoDB's native updateUser
// command; the user's roles are not touched (A240).
func (a *MongoDriverAdmin) SetUserPassword(ctx context.Context, db, user string, password []byte) error {
	if a == nil || a.client == nil {
		return errors.New("dynsecret mongodb: disconnected admin")
	}
	cmd := mongoUpdateUserPasswordCommand(user, password)
	defer secret.Wipe(cmd)
	if err := a.client.Database(db).RunCommand(ctx, bson.Raw(cmd)).Err(); err != nil {
		// As for createUser, keep the generated password out of the error.
		return errors.New("updateUser failed")
	}
	return nil
}

// SetUserPasswordAndRoles changes both fields in one server command. Clearing
// roles makes an already-authenticated retired account lose its authority;
// staging restores the active pair member's configured roles.
func (a *MongoDriverAdmin) SetUserPasswordAndRoles(ctx context.Context, db, user string, password []byte, roles []MongoRole) error {
	if a == nil || a.client == nil {
		return errors.New("dynsecret mongodb: disconnected admin")
	}
	cmd := mongoUpdateUserPasswordRolesCommand(user, password, roles)
	defer secret.Wipe(cmd)
	if err := a.client.Database(db).RunCommand(ctx, bson.Raw(cmd)).Err(); err != nil {
		return errors.New("updateUser failed")
	}
	return nil
}

func mongoUpdateUserPasswordRolesCommand(user string, password []byte, roles []MongoRole) []byte {
	rolesArray := mongoRolesArray(roles)
	cmd, start := beginBSONDocument(make([]byte, 0, mongoCommandCapacity(user, password, rolesArray)))
	cmd = appendBSONString(cmd, "updateUser", []byte(user))
	cmd = appendBSONString(cmd, "pwd", password)
	cmd = appendBSONDocument(cmd, 0x04, "roles", rolesArray)
	return finishBSONDocument(cmd, start)
}

// mongoUpdateUserPasswordCommand encodes {updateUser: user, pwd: password}
// directly as BSON with its capacity reserved up front, so the password is
// written once into an array the caller wipes (see mongoCreateUserCommand).
func mongoUpdateUserPasswordCommand(user string, password []byte) []byte {
	cmd, start := beginBSONDocument(make([]byte, 0, mongoCommandCapacity(user, password, nil)))
	cmd = appendBSONString(cmd, "updateUser", []byte(user))
	cmd = appendBSONString(cmd, "pwd", password)
	return finishBSONDocument(cmd, start)
}

// VerifyMongoCredential proves a credential URI opens a session: the driver
// connects with it and pings its database (A240).
func VerifyMongoCredential(ctx context.Context, credential []byte) error {
	return VerifyMongoCredentialWithTransport(ctx, credential, nil)
}

func VerifyMongoCredentialWithTransport(ctx context.Context, credential []byte, transport *DatabaseTransport) error {
	client, err := openMongoProfile(ctx, credential, transport, dbdsn.Credential)
	if err != nil {
		return errors.New("dynsecret mongodb: the credential does not authenticate")
	}
	closeMongoClient(client)
	return nil
}

// mongoCreateUserCommand encodes the command directly as BSON bytes. The MongoDB
// wire type for pwd is a BSON string, but constructing bson.D would first turn the
// generated password into an immutable Go string. bson.Raw lets the driver send
// the required wire type while custody remains byte-native and explicitly wiped.
func mongoCreateUserCommand(user string, password []byte, roles []MongoRole) []byte {
	rolesArray := mongoRolesArray(roles)

	// Preallocate the whole command before the password goes in. CreateUser wipes
	// the buffer this returns, but append() reallocates as it grows: writing the
	// password and THEN appending the roles document copies the password into a
	// fresh array and abandons the old one, which the wipe can never reach. That
	// abandoned copy is exactly the AN-8 failure the wipe was added to prevent.
	// With capacity reserved up front there is one backing array from start to
	// finish, so wiping the returned slice really does erase the password.
	//
	// The reserve is generous rather than exact — BSON field overhead is a handful
	// of bytes per key — because over-reserving costs nothing and under-reserving
	// silently reintroduces the bug.
	cmd, start := beginBSONDocument(make([]byte, 0, mongoCommandCapacity(user, password, rolesArray)))
	cmd = appendBSONString(cmd, "createUser", []byte(user))
	cmd = appendBSONString(cmd, "pwd", password)
	cmd = appendBSONDocument(cmd, 0x04, "roles", rolesArray)
	return finishBSONDocument(cmd, start)
}

func mongoRolesArray(roles []MongoRole) []byte {
	rolesArray, rolesStart := beginBSONDocument(nil)
	for i, role := range roles {
		roleDoc, roleStart := beginBSONDocument(nil)
		roleDoc = appendBSONString(roleDoc, "role", []byte(role.Role))
		roleDoc = appendBSONString(roleDoc, "db", []byte(role.DB))
		roleDoc = finishBSONDocument(roleDoc, roleStart)
		rolesArray = appendBSONDocument(rolesArray, 0x03, strconv.Itoa(i), roleDoc)
	}
	rolesArray = finishBSONDocument(rolesArray, rolesStart)
	return rolesArray
}

// mongoCommandCapacity reserves enough room that appending never reallocates
// after the password has been written.
func mongoCommandCapacity(user string, password, rolesArray []byte) int {
	const perFieldOverhead = 32 // type byte + key + NUL + length prefix, rounded up
	return 4 +                  // document length prefix
		perFieldOverhead + len("createUser") + len(user) +
		perFieldOverhead + len("pwd") + len(password) +
		perFieldOverhead + len("roles") + len(rolesArray) +
		1 // terminating NUL
}

func beginBSONDocument(dst []byte) ([]byte, int) {
	start := len(dst)
	return append(dst, 0, 0, 0, 0), start
}

func finishBSONDocument(dst []byte, start int) []byte {
	dst = append(dst, 0)
	binary.LittleEndian.PutUint32(dst[start:start+4], uint32(len(dst)-start)) // #nosec G115 -- SQL Server TDS prelogin framing of short bounded fields (CWE-190)
	return dst
}

func appendBSONString(dst []byte, key string, value []byte) []byte {
	dst = append(dst, 0x02)
	dst = append(dst, key...)
	dst = append(dst, 0)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(value)+1)) // #nosec G115 -- SQL Server TDS prelogin framing of short bounded fields (CWE-190)
	dst = append(dst, value...)
	return append(dst, 0)
}

func appendBSONDocument(dst []byte, elementType byte, key string, document []byte) []byte {
	dst = append(dst, elementType)
	dst = append(dst, key...)
	dst = append(dst, 0)
	return append(dst, document...)
}

// DropUser implements MongoAdmin with MongoDB's native dropUser command.
func (a *MongoDriverAdmin) DropUser(ctx context.Context, db, user string) error {
	if a == nil || a.client == nil {
		return errors.New("dynsecret mongodb: disconnected admin")
	}
	if err := a.client.Database(db).RunCommand(ctx, bson.D{{Key: "dropUser", Value: user}}).Err(); err != nil {
		return fmt.Errorf("dropUser: %w", err)
	}
	return nil
}

// Close disconnects the short-lived MongoDB admin client.
func (a *MongoDriverAdmin) Close(ctx context.Context) error {
	if a == nil || a.client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := a.client.Disconnect(ctx)
	a.client = nil
	return err
}
