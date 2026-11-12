// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Access target kinds for database logins (G2-L2).
const (
	AccessTargetMySQLDatabase   = "mysql_database"
	AccessTargetMongoDBDatabase = "mongodb_database"
	AccessTargetRedisServer     = "redis_server"
)

// SQLQuerier is the read side of a database/sql connection. The MySQL
// backend's executor implements it when it is a *sql.DB.
type SQLQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ResolveAccess reads the lease user's privileges as MySQL reports them
// (SHOW GRANTS for the user at the provider's account host). USAGE on *.*,
// which MySQL lists for every account and which grants nothing, is left out.
func (b *MySQLBackend) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	access := Access{TargetKind: AccessTargetMySQLDatabase, TargetRef: "mysql://" + b.addr + "/" + b.database, Login: strings.TrimSpace(backendRef)}
	if access.Login == "" {
		return access, fmt.Errorf("%w: the lease names no login", ErrAccessLoginMissing)
	}
	querier, ok := b.exec.(SQLQuerier)
	if !ok {
		return access, ErrAccessUnsupported
	}
	rows, err := querier.QueryContext(ctx, "SHOW GRANTS FOR "+mysqlAccount(access.Login, b.accountHost))
	if err != nil {
		return access, mysqlAccessError(err)
	}
	defer func() { _ = rows.Close() }()
	var grants []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return access, ErrAccessUnreadable
		}
		if grant := mysqlGrantText(line); grant != "" {
			grants = append(grants, grant)
		}
	}
	if err := rows.Err(); err != nil {
		return access, mysqlAccessError(err)
	}
	return boundGrants(access, grants), nil
}

// mysqlGrantText turns one SHOW GRANTS line into the grant it states:
// "GRANT SELECT ON `app`.* TO `u`@`h`" is "SELECT on app.*", and a role grant
// "GRANT `reader`@`%` TO `u`@`h`" is "member of role reader@%".
func mysqlGrantText(line string) string {
	body, found := strings.CutPrefix(strings.TrimSpace(line), "GRANT ")
	if !found {
		return ""
	}
	if to := strings.LastIndex(body, " TO "); to >= 0 {
		body = body[:to]
	}
	body = strings.ReplaceAll(body, "`", "")
	privileges, object, isPrivilege := strings.Cut(body, " ON ")
	if !isPrivilege {
		return "member of role " + strings.TrimSpace(body)
	}
	privileges, object = strings.TrimSpace(privileges), strings.TrimSpace(object)
	if privileges == "USAGE" && object == "*.*" {
		return ""
	}
	return privileges + " on " + object
}

// mysqlAccessError classifies a MySQL error without keeping its text, which a
// driver may build from the statement.
func mysqlAccessError(err error) error {
	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		switch myErr.Number {
		case 1141: // ER_NONEXISTING_GRANT: no such user at that host
			return ErrAccessLoginMissing
		case 1044, 1045, 1142, 1227: // access denied, or a privilege the admin lacks
			return ErrAccessDenied
		}
		return ErrAccessUnreadable
	}
	var netErr net.Error
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, mysql.ErrInvalidConn) || errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		return ErrAccessUnreachable
	}
	return ErrAccessUnreadable
}

// MongoUserReader reads a user's roles (G2-L2). MongoDriverAdmin implements it.
type MongoUserReader interface {
	UserRoles(ctx context.Context, db, user string) (roles []MongoRole, found bool, err error)
}

// ResolveAccess reads the lease user's roles as MongoDB reports them
// (usersInfo in the provider's database).
func (b *MongoBackend) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	access := Access{TargetKind: AccessTargetMongoDBDatabase, TargetRef: mongoTargetRef(b.uri, b.database), Login: strings.TrimSpace(backendRef)}
	if access.Login == "" {
		return access, fmt.Errorf("%w: the lease names no login", ErrAccessLoginMissing)
	}
	reader, ok := b.admin.(MongoUserReader)
	if !ok {
		return access, ErrAccessUnsupported
	}
	roles, found, err := reader.UserRoles(ctx, b.database, access.Login)
	if err != nil {
		return access, err
	}
	if !found {
		return access, ErrAccessLoginMissing
	}
	grants := make([]string, 0, len(roles))
	for _, role := range roles {
		grants = append(grants, "role "+role.Role+" on database "+role.DB)
	}
	return boundGrants(access, grants), nil
}

// mongoTargetRef names the deployment and database a backend reaches without
// credentials: mongodb://host[,host...]/database.
func mongoTargetRef(uri *secret.Buffer, database string) string {
	host := "localhost"
	if uri != nil && uri.Len() > 0 {
		if _, _, authorityEnd, hostStart, ok := splitURIAuthority(uri.Bytes()); ok && hostStart <= authorityEnd {
			host = string(uri.Bytes()[hostStart:authorityEnd])
		}
	}
	return "mongodb://" + host + "/" + database
}

// UserRoles implements MongoUserReader with MongoDB's usersInfo command.
func (a *MongoDriverAdmin) UserRoles(ctx context.Context, db, user string) ([]MongoRole, bool, error) {
	if a == nil || a.client == nil {
		return nil, false, ErrAccessUnreachable
	}
	var answer struct {
		Users []struct {
			Roles []struct {
				Role string `bson:"role"`
				DB   string `bson:"db"`
			} `bson:"roles"`
		} `bson:"users"`
	}
	cmd := bson.D{{Key: "usersInfo", Value: bson.D{{Key: "user", Value: user}, {Key: "db", Value: db}}}}
	if err := a.client.Database(db).RunCommand(ctx, cmd).Decode(&answer); err != nil {
		return nil, false, mongoAccessError(err)
	}
	if len(answer.Users) == 0 {
		return nil, false, nil
	}
	roles := make([]MongoRole, 0, len(answer.Users[0].Roles))
	for _, role := range answer.Users[0].Roles {
		roles = append(roles, MongoRole{Role: role.Role, DB: role.DB})
	}
	return roles, true, nil
}

// mongoAccessError classifies a MongoDB error without keeping its text.
func mongoAccessError(err error) error {
	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) {
		if cmdErr.Code == 13 || cmdErr.Code == 18 { // Unauthorized, AuthenticationFailed
			return ErrAccessDenied
		}
		return ErrAccessUnreadable
	}
	if mongo.IsNetworkError(err) || mongo.IsTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
		return ErrAccessUnreachable
	}
	return ErrAccessUnreadable
}

// ResolveAccess reads the lease user's ACL rules as Redis reports them (ACL
// GETUSER): its flags, commands, key patterns and channels. The password
// hashes Redis returns beside them are never kept.
func (b *RedisBackend) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	access := Access{TargetKind: AccessTargetRedisServer, TargetRef: "redis://" + b.addr, Login: strings.TrimSpace(backendRef)}
	if access.Login == "" {
		return access, fmt.Errorf("%w: the lease names no login", ErrAccessLoginMissing)
	}
	reply, err := b.redisQuery(ctx, [][]byte{[]byte("ACL"), []byte("GETUSER"), []byte(access.Login)})
	if err != nil {
		return access, err
	}
	if reply.null {
		return access, ErrAccessLoginMissing
	}
	if len(reply.items)%2 != 0 {
		return access, ErrAccessUnreadable
	}
	var grants []string
	for i := 0; i < len(reply.items); i += 2 {
		field := reply.items[i].text
		switch field {
		case "flags", "commands", "keys", "channels":
		default:
			continue // passwords, selectors, and fields a later Redis adds
		}
		value := reply.items[i+1]
		var words []string
		if len(value.items) > 0 {
			for _, item := range value.items {
				words = append(words, item.text)
			}
		} else {
			words = strings.Fields(value.text)
		}
		if len(words) > 0 {
			grants = append(grants, field+" "+strings.Join(words, " "))
		}
	}
	return boundGrants(access, grants), nil
}

// redisQuery sends one command as the admin and reads its whole reply.
func (b *RedisBackend) redisQuery(ctx context.Context, command [][]byte) (respValue, error) {
	conn, err := b.connect(ctx)
	if err != nil {
		return respValue{}, ErrAccessUnreachable
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	reader := bufio.NewReader(conn)
	if b.password != nil && b.password.Len() > 0 {
		if err := redisWriteArray(conn, [][]byte{[]byte("AUTH"), b.password.Bytes()}); err != nil {
			return respValue{}, ErrAccessUnreachable
		}
		if err := redisReadOK(reader); err != nil {
			return respValue{}, ErrAccessDenied
		}
	}
	if err := redisWriteArray(conn, command); err != nil {
		return respValue{}, ErrAccessUnreachable
	}
	budget := maxRESPReplyBytes
	reply, err := readRESPValue(reader, 0, &budget)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) || errors.Is(err, io.EOF) {
			return respValue{}, ErrAccessUnreachable
		}
		return respValue{}, err
	}
	if reply.err != "" {
		if strings.HasPrefix(reply.err, "NOPERM") || strings.HasPrefix(reply.err, "NOAUTH") {
			return respValue{}, ErrAccessDenied
		}
		return respValue{}, ErrAccessUnreadable
	}
	return reply, nil
}

// Bounds on one RESP reply read for access: its total size, nesting and the
// elements of one array.
const (
	maxRESPReplyBytes = 256 << 10
	maxRESPDepth      = 4
	maxRESPElements   = 1024
)

// respValue is one RESP2/RESP3 reply value: a string (simple, bulk, verbatim
// or a number's text), an array or map's items in order, a null, or an error.
type respValue struct {
	text  string
	items []respValue
	null  bool
	err   string
}

// readRESPValue reads one reply value within the remaining byte budget.
func readRESPValue(r *bufio.Reader, depth int, budget *int) (respValue, error) {
	if depth > maxRESPDepth {
		return respValue{}, ErrAccessUnreadable
	}
	line, err := readRESPLine(r, budget)
	if err != nil {
		return respValue{}, err
	}
	if len(line) == 0 {
		return respValue{}, ErrAccessUnreadable
	}
	prefix, rest := line[0], string(line[1:])
	switch prefix {
	case '+', ':', ',', '#', '(':
		return respValue{text: rest}, nil
	case '-', '!':
		return respValue{err: rest}, nil
	case '_':
		return respValue{null: true}, nil
	case '$', '=':
		n, err := strconv.Atoi(rest)
		if err != nil || n < -1 {
			return respValue{}, ErrAccessUnreadable
		}
		if n == -1 {
			return respValue{null: true}, nil
		}
		if n+2 > *budget {
			return respValue{}, ErrAccessUnreadable
		}
		*budget -= n + 2
		body := make([]byte, n+2)
		if _, err := io.ReadFull(r, body); err != nil {
			return respValue{}, err
		}
		if !bytes.HasSuffix(body, []byte("\r\n")) {
			return respValue{}, ErrAccessUnreadable
		}
		return respValue{text: string(body[:n])}, nil
	case '*', '%', '~', '>':
		n, err := strconv.Atoi(rest)
		if err != nil || n < -1 {
			return respValue{}, ErrAccessUnreadable
		}
		if n == -1 {
			return respValue{null: true}, nil
		}
		if prefix == '%' {
			n *= 2 // a map's keys and values, in order
		}
		if n > maxRESPElements {
			return respValue{}, ErrAccessUnreadable
		}
		out := respValue{items: make([]respValue, 0, n)}
		for range n {
			item, err := readRESPValue(r, depth+1, budget)
			if err != nil {
				return respValue{}, err
			}
			out.items = append(out.items, item)
		}
		return out, nil
	default:
		return respValue{}, ErrAccessUnreadable
	}
}

// readRESPLine reads one CRLF-terminated line within the byte budget.
func readRESPLine(r *bufio.Reader, budget *int) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, ErrAccessUnreadable
		}
		return nil, err
	}
	if len(line) > *budget || len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, ErrAccessUnreadable
	}
	*budget -= len(line)
	return bytes.Clone(line[:len(line)-2]), nil
}
