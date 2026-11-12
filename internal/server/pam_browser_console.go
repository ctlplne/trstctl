// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
	"go.mongodb.org/mongo-driver/v2/bson"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mongosignin"
)

// A259-L5: database consoles for MySQL, MongoDB and Redis sessions opened for
// the browser, beside PostgreSQL's. Each console keeps one connection
// through the session's gateway for its opener and runs one SQL statement or
// command at a time on it. The gateway signs in as the session's account and
// records and masks each one, as it does for a stock client. The browser gets
// the result, never a credential.

// pamConsoleClient runs one text on a console's connection. A refusal by the
// database is a result; an error means the connection can no longer be used.
type pamConsoleClient interface {
	run(ctx context.Context, text string) (api.PAMQueryResult, error)
	close()
}

// errPAMConsoleInput is a text the console could not send; the connection is
// still good.
var errPAMConsoleInput = errors.New("console input")

// pamConsoleCell is one result cell: cut at the console's cell size, as
// valid UTF-8, and whether it was cut.
func pamConsoleCell(value []byte) (*string, bool) {
	if value == nil {
		return nil, false
	}
	cell, cut := string(value), false
	if len(cell) > pamConsoleMaxCell {
		cell, cut = strings.ToValidUTF8(cell[:pamConsoleMaxCell], "")+"…", true
	}
	if !utf8.ValidString(cell) {
		cell = strings.ToValidUTF8(cell, "�")
	}
	return &cell, cut
}

// mysqlConsole runs SQL through the gateway with the MySQL driver, on the one
// connection the gateway admitted. The gateway answers the handshake itself
// and signs in upstream as the session's account; the console sends no
// password.
type mysqlConsole struct {
	db   *sql.DB
	conn *sql.Conn
}

func newMySQLConsole(ctx context.Context, raw net.Conn) (*mysqlConsole, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Net, cfg.Addr = "browser", "tcp", "trstctl-gateway:3306"
	cfg.AllowNativePasswords = true
	var mu sync.Mutex
	cfg.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if raw == nil {
			return nil, errors.New("the console's gateway connection is spent")
		}
		conn := raw
		raw = nil
		return conn, nil
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &mysqlConsole{db: db, conn: conn}, nil
}

// mysqlRefusal is the server's refusal as the mysql client shows it: the
// error number and its SQLSTATE.
func mysqlRefusal(err error) *api.PAMQueryError {
	var refused *mysql.MySQLError
	if !errors.As(err, &refused) {
		return nil
	}
	code := strconv.Itoa(int(refused.Number))
	if refused.SQLState != [5]byte{} {
		code += " (" + string(refused.SQLState[:]) + ")"
	}
	return &api.PAMQueryError{Code: code, Message: refused.Message}
}

func (c *mysqlConsole) run(ctx context.Context, text string) (api.PAMQueryResult, error) {
	rows, err := c.conn.QueryContext(ctx, text)
	if err != nil {
		if refusal := mysqlRefusal(err); refusal != nil {
			return api.PAMQueryResult{Error: refusal}, nil
		}
		return api.PAMQueryResult{}, err
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		return api.PAMQueryResult{}, err
	}
	out := api.PAMQueryResult{Columns: append([]string{}, columns...), Rows: [][]*string{}}
	values := make([]sql.RawBytes, len(columns))
	dest := make([]any, len(columns))
	for i := range values {
		dest[i] = &values[i]
	}
	// Every row is read, so the connection stays in step; the first
	// thousand are kept.
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return api.PAMQueryResult{}, err
		}
		if len(out.Rows) == pamConsoleMaxRows {
			out.Truncated = true
			continue
		}
		cells := make([]*string, len(values))
		for i, value := range values {
			var cut bool
			cells[i], cut = pamConsoleCell(value)
			out.Truncated = out.Truncated || cut
		}
		out.Rows = append(out.Rows, cells)
	}
	if err := rows.Err(); err != nil {
		if refusal := mysqlRefusal(err); refusal != nil {
			return api.PAMQueryResult{Error: refusal}, nil
		}
		return api.PAMQueryResult{}, err
	}
	if len(columns) == 0 {
		out.CommandTag = "OK"
	}
	return out, nil
}

func (c *mysqlConsole) close() {
	_ = c.conn.Close()
	_ = c.db.Close()
}

// redisConsole sends one command at a time as a RESP array on the admitted
// connection; the gateway signed in upstream as the session's ACL user.
type redisConsole struct {
	conn net.Conn
	r    *bufio.Reader
}

// A Redis reply is read whole, so the connection stays in step, and kept to
// the console's bounds; nesting deeper than this ends the connection.
const pamRedisMaxDepth = 8

// splitRedisCommand splits a command line as redis-cli does: words separated
// by spaces; a double-quoted word takes \n, \r, \t, \", \\ and \xHH escapes,
// a single-quoted word takes \'.
func splitRedisCommand(line string) ([]string, error) {
	var args []string
	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\n' || line[i] == '\r') {
			i++
		}
		if i == len(line) {
			break
		}
		var word strings.Builder
		switch quote := line[i]; quote {
		case '"', '\'':
			i++
			closed := false
			for i < len(line) {
				ch := line[i]
				if ch == quote {
					closed = true
					i++
					break
				}
				if ch == '\\' && i+1 < len(line) {
					next := line[i+1]
					switch {
					case quote == '\'' && next == '\'':
						word.WriteByte('\'')
						i += 2
						continue
					case quote == '"' && next == 'x' && i+3 < len(line):
						if b, err := strconv.ParseUint(line[i+2:i+4], 16, 8); err == nil {
							word.WriteByte(byte(b))
							i += 4
							continue
						}
					case quote == '"':
						if escaped, ok := map[byte]byte{'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'a': '\a', '"': '"', '\\': '\\'}[next]; ok {
							word.WriteByte(escaped)
							i += 2
							continue
						}
					}
				}
				word.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("%w: an unclosed quote", errPAMConsoleInput)
			}
			if i < len(line) && line[i] != ' ' && line[i] != '\t' {
				return nil, fmt.Errorf("%w: a closing quote must end its word", errPAMConsoleInput)
			}
		default:
			for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '\n' && line[i] != '\r' {
				word.WriteByte(line[i])
				i++
			}
		}
		args = append(args, word.String())
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("%w: a command is required", errPAMConsoleInput)
	}
	return args, nil
}

// respReply is a RESP2 reply as the console shows it.
type respReply struct {
	kind      byte // '+', '-', ':', '$', '*'
	text      string
	null      bool
	elems     []respReply
	truncated bool
}

// readRESP reads one reply whole: a string beyond the console's cell size and
// an array beyond its rows are read and dropped.
func readRESP(r *bufio.Reader, depth int) (respReply, error) {
	if depth > pamRedisMaxDepth {
		return respReply{}, errors.New("the Redis reply nests too deeply")
	}
	kind, err := r.ReadByte()
	if err != nil {
		return respReply{}, err
	}
	line, cut, err := readRESPLine(r)
	if err != nil {
		return respReply{}, err
	}
	switch kind {
	case '+', '-', ':':
		return respReply{kind: kind, text: line, truncated: cut}, nil
	case '$':
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil || n < -1 {
			return respReply{}, errors.New("the Redis reply has a bad bulk length")
		}
		if n == -1 {
			return respReply{kind: kind, null: true}, nil
		}
		keep := min(n, int64(pamConsoleMaxCell))
		buf := make([]byte, keep)
		if _, err := io.ReadFull(r, buf); err != nil {
			return respReply{}, err
		}
		if _, err := io.CopyN(io.Discard, r, n-keep+2); err != nil {
			return respReply{}, err
		}
		cell, cutCell := pamConsoleCell(buf)
		text := *cell
		if keep < n && !cutCell {
			// The string went on past the kept bytes: mark the cut as a
			// longer cell's is marked.
			text = strings.ToValidUTF8(text, "") + "…"
		}
		return respReply{kind: kind, text: text, truncated: cutCell || keep < n}, nil
	case '*':
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil || n < -1 {
			return respReply{}, errors.New("the Redis reply has a bad array length")
		}
		if n == -1 {
			return respReply{kind: kind, null: true}, nil
		}
		out := respReply{kind: kind, elems: []respReply{}}
		for i := int64(0); i < n; i++ {
			elem, err := readRESP(r, depth+1)
			if err != nil {
				return respReply{}, err
			}
			if len(out.elems) == pamConsoleMaxRows {
				out.truncated = true
				continue
			}
			out.elems = append(out.elems, elem)
		}
		return out, nil
	}
	return respReply{}, fmt.Errorf("the Redis reply type %q is not RESP2", kind)
}

// readRESPLine reads a CRLF line, keeping at most the console's cell size.
func readRESPLine(r *bufio.Reader) (string, bool, error) {
	var line []byte
	cut := false
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) <= pamConsoleMaxCell+2 {
			line = append(line, chunk...)
		} else {
			cut = true
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", false, err
		}
		break
	}
	text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	cell, cutCell := pamConsoleCell([]byte(text))
	return *cell, cut || cutCell, nil
}

// inline is a reply as one cell: a nested array is shown in brackets.
func (rep respReply) inline() *string {
	if rep.null {
		return nil
	}
	if rep.kind != '*' {
		text := rep.text
		return &text
	}
	parts := make([]string, 0, len(rep.elems))
	for _, elem := range rep.elems {
		if cell := elem.inline(); cell == nil {
			parts = append(parts, "(nil)")
		} else {
			parts = append(parts, strconv.Quote(*cell))
		}
	}
	text := "[" + strings.Join(parts, ", ") + "]"
	return &text
}

func (c *redisConsole) run(ctx context.Context, text string) (api.PAMQueryResult, error) {
	args, err := splitRedisCommand(text)
	if err != nil {
		return api.PAMQueryResult{}, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(deadline)
	}
	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	request := []byte("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, arg := range args {
		request = append(request, "$"+strconv.Itoa(len(arg))+"\r\n"...)
		request = append(append(request, arg...), "\r\n"...)
	}
	if _, err := c.conn.Write(request); err != nil {
		return api.PAMQueryResult{}, err
	}
	reply, err := readRESP(c.r, 0)
	if err != nil {
		return api.PAMQueryResult{}, err
	}
	out := api.PAMQueryResult{Columns: []string{"value"}, Rows: [][]*string{}, CommandTag: strings.ToUpper(args[0]), Truncated: reply.truncated}
	switch reply.kind {
	case '-':
		code, message, _ := strings.Cut(reply.text, " ")
		return api.PAMQueryResult{Error: &api.PAMQueryError{Code: code, Message: message}}, nil
	case ':':
		out.Columns = []string{"integer"}
		out.Rows = append(out.Rows, []*string{reply.inline()})
	case '*':
		if reply.null {
			out.Rows = append(out.Rows, []*string{nil})
			break
		}
		out.Columns = []string{"#", "value"}
		for i, elem := range reply.elems {
			index := strconv.Itoa(i + 1)
			out.Rows = append(out.Rows, []*string{&index, elem.inline()})
			out.Truncated = out.Truncated || elem.truncated
		}
	default:
		out.Rows = append(out.Rows, []*string{reply.inline()})
	}
	return out, nil
}

func (c *redisConsole) close() { _ = c.conn.Close() }

// mongoConsole sends one command document at a time as an OP_MSG on the
// admitted connection; the gateway signed in upstream as the session's user.
// A command names its database with $db, or runs on the provider's.
type mongoConsole struct {
	conn     net.Conn
	r        *bufio.Reader
	database string
	nextID   int32
}

// pamMongoMaxMessage is the largest reply the console reads: MongoDB's own
// message limit.
const pamMongoMaxMessage = 48 << 20

func (c *mongoConsole) run(ctx context.Context, text string) (api.PAMQueryResult, error) {
	var command bson.D
	if err := bson.UnmarshalExtJSON([]byte(text), false, &command); err != nil || len(command) == 0 {
		return api.PAMQueryResult{}, fmt.Errorf("%w: a MongoDB command is one JSON document naming the command first", errPAMConsoleInput)
	}
	hasDB := false
	for _, elem := range command {
		hasDB = hasDB || elem.Key == "$db"
	}
	if !hasDB {
		command = append(command, bson.E{Key: "$db", Value: c.database})
	}
	payload, err := bson.Marshal(command)
	if err != nil {
		return api.PAMQueryResult{}, fmt.Errorf("%w: %v", errPAMConsoleInput, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(deadline)
	}
	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	c.nextID++
	body := append([]byte{0, 0, 0, 0, 0}, payload...)
	if _, err := c.conn.Write(append(mongosignin.MessageHeader(16+len(body), c.nextID, 0, mongosignin.OpMsg), body...)); err != nil {
		return api.PAMQueryResult{}, err
	}
	header := make([]byte, 16)
	if _, err := io.ReadFull(c.r, header); err != nil {
		return api.PAMQueryResult{}, err
	}
	length := binary.LittleEndian.Uint32(header)
	if length < 16+5 || length > pamMongoMaxMessage || int32(binary.LittleEndian.Uint32(header[12:])) != mongosignin.OpMsg { // #nosec G115 -- an opcode's two's-complement bits (CWE-190)
		return api.PAMQueryResult{}, errors.New("the MongoDB reply is not an OP_MSG within MongoDB's message limit")
	}
	message := make([]byte, length-16)
	if _, err := io.ReadFull(c.r, message); err != nil {
		return api.PAMQueryResult{}, err
	}
	if int32(binary.LittleEndian.Uint32(header[8:])) != c.nextID || message[4] != 0 { // #nosec G115 -- a request id's two's-complement bits (CWE-190)
		return api.PAMQueryResult{}, errors.New("the MongoDB reply does not answer the command")
	}
	reply := bson.Raw(message[5:])
	if err := reply.Validate(); err != nil {
		return api.PAMQueryResult{}, err
	}
	out := api.PAMQueryResult{Columns: []string{"document"}, Rows: [][]*string{}, CommandTag: command[0].Key}
	if ok, _ := reply.Lookup("ok").AsFloat64OK(); ok != 1 {
		code, _ := reply.Lookup("codeName").StringValueOK()
		if code == "" {
			if n, isNum := reply.Lookup("code").AsInt64OK(); isNum {
				code = strconv.FormatInt(n, 10)
			}
		}
		message, _ := reply.Lookup("errmsg").StringValueOK()
		return api.PAMQueryResult{Error: &api.PAMQueryError{Code: code, Message: message}}, nil
	}
	documents := []bson.Raw{reply}
	if cursor, isDoc := reply.Lookup("cursor").DocumentOK(); isDoc {
		if batch, isArray := cursor.Lookup("firstBatch").ArrayOK(); isArray {
			values, err := batch.Values()
			if err != nil {
				return api.PAMQueryResult{}, err
			}
			documents = documents[:0]
			for _, value := range values {
				if doc, isDoc := value.DocumentOK(); isDoc {
					documents = append(documents, doc)
				}
			}
			if id, _ := cursor.Lookup("id").AsInt64OK(); id != 0 {
				out.Truncated = true
			}
		}
	}
	for _, doc := range documents {
		if len(out.Rows) == pamConsoleMaxRows {
			out.Truncated = true
			break
		}
		text, err := bson.MarshalExtJSON(doc, false, false)
		if err != nil {
			return api.PAMQueryResult{}, err
		}
		cell, cut := pamConsoleCell(text)
		out.Truncated = out.Truncated || cut
		out.Rows = append(out.Rows, []*string{cell})
	}
	return out, nil
}

func (c *mongoConsole) close() { _ = c.conn.Close() }
