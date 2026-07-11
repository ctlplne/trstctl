// SPDX-License-Identifier: MPL-2.0

package dynsecret

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

// connectPostgresAdmin is the final pgx compatibility edge. pgx accepts a DSN
// only as string, so the operator-owned byte buffer is converted immediately at
// the call and the connection is kept only for this one create/revoke operation.
// Generated passwords never pass through this edge.
func connectPostgresAdmin(ctx context.Context, adminDSN []byte) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, secrettext.String(adminDSN))
	if err != nil {
		return nil, errors.New("dynsecret postgres: connect failed")
	}
	return conn, nil
}

// createPostgresRole sends the generated password as a bytea bind parameter.
// PostgreSQL utility statements do not accept bind parameters in PASSWORD, so a
// transaction-local server setting carries the bytes into a short DO block. The
// dynamic SQL is built inside PostgreSQL; no Go string ever contains the secret.
func createPostgresRole(ctx context.Context, conn *pgx.Conn, user string, password []byte, validUntil string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return errPostgresRoleCreate
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`SELECT set_config('trstctl.dynamic_secret_password', convert_from($1::bytea, 'UTF8'), true)`,
		password); err != nil {
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

// OpenMySQLExecutor opens and verifies an official go-sql-driver/mysql client.
// Callers close the returned pool immediately after one create/revoke operation;
// this keeps the authority-bearing admin DSN out of long-lived process state.
func OpenMySQLExecutor(ctx context.Context, adminDSN []byte) (*sql.DB, error) {
	if len(adminDSN) == 0 {
		return nil, errors.New("dynsecret mysql: admin DSN required")
	}
	db, err := sql.Open("mysql", secrettext.String(adminDSN))
	if err != nil {
		return nil, errors.New("dynsecret mysql: open admin connection failed")
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errors.New("dynsecret mysql: ping admin connection failed")
	}
	return db, nil
}

// createMySQLUser keeps the generated password as a []byte bind while handling
// MySQL's CREATE USER grammar, which does not accept a parameter marker directly
// in IDENTIFIED BY. A pinned database/sql connection stores the byte bind in a
// session variable, constructs the utility statement inside MySQL, executes it,
// then clears and deallocates every session object before returning.
func createMySQLUser(ctx context.Context, executor SQLExecutor, account string, password []byte) error {
	type connectionProvider interface {
		Conn(context.Context) (*sql.Conn, error)
	}
	provider, ok := executor.(connectionProvider)
	if !ok {
		// Test/third-party executors may natively support parameters in CREATE USER.
		// The shipped go-sql-driver/mysql path always takes the pinned branch below.
		if _, err := executor.ExecContext(ctx, "CREATE USER "+account+" IDENTIFIED BY ?", password); err != nil {
			return errMySQLUserCreate
		}
		return nil
	}
	conn, err := provider.Conn(ctx)
	if err != nil {
		return errMySQLUserCreate
	}
	defer func() { _ = conn.Close() }()
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SET @trstctl_dynamic_password = NULL, @trstctl_create_user = NULL`)
	}()
	if _, err := conn.ExecContext(ctx, `SET @trstctl_dynamic_password = ?`, password); err != nil {
		return errMySQLUserCreate
	}
	prefix := "CREATE USER " + account + " IDENTIFIED BY "
	if _, err := conn.ExecContext(ctx,
		`SET @trstctl_create_user = CONCAT(?, QUOTE(CONVERT(@trstctl_dynamic_password USING utf8mb4)))`,
		prefix); err != nil {
		return errMySQLUserCreate
	}
	if _, err := conn.ExecContext(ctx, `PREPARE trstctl_create_user_stmt FROM @trstctl_create_user`); err != nil {
		return errMySQLUserCreate
	}
	prepared := true
	defer func() {
		if prepared {
			_, _ = conn.ExecContext(context.Background(), `DEALLOCATE PREPARE trstctl_create_user_stmt`)
		}
	}()
	if _, err := conn.ExecContext(ctx, `EXECUTE trstctl_create_user_stmt`); err != nil {
		return errMySQLUserCreate
	}
	if _, err := conn.ExecContext(ctx, `DEALLOCATE PREPARE trstctl_create_user_stmt`); err != nil {
		return errMySQLUserCreate
	}
	prepared = false
	return nil
}

// MongoDriverAdmin is the official MongoDB-driver implementation of MongoAdmin.
// It is intentionally short-lived; production factories construct it only for a
// single create/revoke call and close it before returning.
type MongoDriverAdmin struct {
	client *mongo.Client
}

// OpenMongoAdmin connects and pings a MongoDB deployment using an operator-owned
// admin URI. The driver receives the URI only for the lifetime of this adapter.
func OpenMongoAdmin(ctx context.Context, adminURI []byte) (*MongoDriverAdmin, error) {
	if len(adminURI) == 0 {
		return nil, errors.New("dynsecret mongodb: admin URI required")
	}
	client, err := mongo.Connect(options.Client().ApplyURI(secrettext.String(adminURI)))
	if err != nil {
		return nil, errors.New("dynsecret mongodb: connect failed")
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, errors.New("dynsecret mongodb: ping failed")
	}
	return &MongoDriverAdmin{client: client}, nil
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

// mongoCreateUserCommand encodes the command directly as BSON bytes. The MongoDB
// wire type for pwd is a BSON string, but constructing bson.D would first turn the
// generated password into an immutable Go string. bson.Raw lets the driver send
// the required wire type while custody remains byte-native and explicitly wiped.
func mongoCreateUserCommand(user string, password []byte, roles []MongoRole) []byte {
	rolesArray, rolesStart := beginBSONDocument(nil)
	for i, role := range roles {
		roleDoc, roleStart := beginBSONDocument(nil)
		roleDoc = appendBSONString(roleDoc, "role", []byte(role.Role))
		roleDoc = appendBSONString(roleDoc, "db", []byte(role.DB))
		roleDoc = finishBSONDocument(roleDoc, roleStart)
		rolesArray = appendBSONDocument(rolesArray, 0x03, strconv.Itoa(i), roleDoc)
	}
	rolesArray = finishBSONDocument(rolesArray, rolesStart)

	cmd, start := beginBSONDocument(nil)
	cmd = appendBSONString(cmd, "createUser", []byte(user))
	cmd = appendBSONString(cmd, "pwd", password)
	cmd = appendBSONDocument(cmd, 0x04, "roles", rolesArray)
	return finishBSONDocument(cmd, start)
}

func beginBSONDocument(dst []byte) ([]byte, int) {
	start := len(dst)
	return append(dst, 0, 0, 0, 0), start
}

func finishBSONDocument(dst []byte, start int) []byte {
	dst = append(dst, 0)
	binary.LittleEndian.PutUint32(dst[start:start+4], uint32(len(dst)-start))
	return dst
}

func appendBSONString(dst []byte, key string, value []byte) []byte {
	dst = append(dst, 0x02)
	dst = append(dst, key...)
	dst = append(dst, 0)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(value)+1))
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
	err := a.client.Disconnect(ctx)
	a.client = nil
	return err
}
