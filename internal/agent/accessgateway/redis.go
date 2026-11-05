// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/redissignin"
)

// What a Redis session's recording keeps of each command and reply (A256),
// and the bounds the relay reads under.
const (
	redisRecordArgBytes  = 256
	redisRecordTextBytes = 4 << 10
	// redisParsedCommand is the most of one command held whole, and recorded,
	// before it is forwarded; the rest of a longer one streams.
	redisParsedCommand = 1 << 20
	// redisNameBytes bounds the command name read before the gateway decides
	// whether to forward a command; no refused name is longer.
	redisNameBytes = 64
	redisMaxLine   = 64 << 10
	redisMaxArgs   = 1 << 20
	redisMaxBulk   = 512 << 20
	redisMaxDepth  = 32
	// redisHelloArgs and redisHelloArgBytes bound a HELLO, read whole to see
	// whether it carries AUTH.
	redisHelloArgs     = 16
	redisHelloArgBytes = 1 << 10
)

// redisRefusedCommand prefixes the command forwarded in place of one that
// would change the connection's login. The server answers it with an error,
// so the refusal reaches the client in order with every other reply.
const redisRefusedCommand = "TRSTCTL-GATEWAY-REFUSED-"

var errRedisInline = errors.New("accessgateway: the Redis client sent an inline command; the gateway relays RESP commands only")

// serveRedis signs in upstream as the session's ACL user and relays a stock
// Redis client's commands (A256). The client sends no credential: the
// admitted tunnel is its authentication. A command that would change the
// connection's login — AUTH, HELLO with AUTH, RESET — is never forwarded, so
// the connection keeps the session's user and nothing else. The client never
// receives the credential.
func serveRedis(ctx context.Context, client net.Conn, credential []byte, deadline time.Time, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder, guards ...*commandConnection) error {
	signInCtx, cancel := context.WithDeadline(ctx, earliest(deadline, time.Now().Add(30*time.Second)))
	defer cancel()
	server, err := redissignin.SignIn(signInCtx, credential, redissignin.Options{Dial: dial})
	if err != nil {
		_, _ = io.WriteString(client, "-ERR the access gateway could not sign in to the target as this session's user\r\n")
		return err
	}
	defer func() { _ = server.Close() }()
	_ = server.SetDeadline(deadline)
	recordCommand := func(redisCommand) {}
	if rec != nil {
		recordCommand = func(c redisCommand) {
			if c.refused != "" {
				rec.event("redis", "refused", c.refused, 0)
				return
			}
			rec.event("redis", "command", c.text.String(), 0)
		}
	}
	if len(guards) > 0 && guards[0] != nil {
		return relayRedisRuleCommands(ctx, client, server, guards[0], rec, recordCommand)
	}
	var relayErr error
	done := make(chan struct{}, 2)
	go func() {
		relayErr = relayRedisCommands(server, bufio.NewReaderSize(client, 32<<10), recordCommand)
		_ = server.Close()
		done <- struct{}{}
	}()
	go func() {
		if rec == nil {
			_, _ = io.Copy(client, server)
		} else {
			_ = relayRedisReplies(client, bufio.NewReaderSize(server, 32<<10), func(kind, text string) { rec.event("result", kind, text, 0) })
		}
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
	if errors.Is(relayErr, errRedisInline) {
		return relayErr
	}
	return nil
}

// redisCommand is one client command as recorded: its name and arguments,
// bounded, or the name of a refused one (whose arguments are never kept).
type redisCommand struct {
	text    boundedText
	refused string
}

// relayRedisCommands forwards a client's commands one at a time. A command is
// read whole up to redisParsedCommand and recorded before it is forwarded; a
// longer one is forwarded as it streams and recorded once through. Inline
// commands end the connection: every stock client sends RESP arrays.
func relayRedisCommands(dst io.Writer, src *bufio.Reader, record func(redisCommand)) error {
	for {
		lead, err := src.ReadByte()
		if err != nil {
			return err
		}
		if lead != '*' {
			return errRedisInline
		}
		n, err := readRESPNumber(src)
		if err != nil {
			return err
		}
		if n <= 0 {
			continue // an empty array is no command; Redis skips it too
		}
		if n > redisMaxArgs {
			return errors.New("accessgateway: a Redis command has too many arguments")
		}
		name, err := readRESPBulk(src, redisNameBytes)
		if err != nil {
			return err
		}
		upper := strings.ToUpper(string(name.data))
		switch {
		case name.whole && (upper == "AUTH" || upper == "RESET"):
			if err := discardRESPBulks(src, n-1); err != nil {
				return err
			}
			if err := refuseRedis(dst, upper, record); err != nil {
				return err
			}
			continue
		case name.whole && upper == "HELLO":
			refused, args, err := readRedisHello(src, n-1)
			if err != nil {
				return err
			}
			if refused {
				if err := refuseRedis(dst, upper, record); err != nil {
					return err
				}
				continue
			}
			var c redisCommand
			raw := append(respArrayHeader(n), respBulk(name.data)...)
			c.text.add(upper)
			for _, arg := range args {
				c.text.addArg(arg, len(arg))
				raw = append(raw, respBulk(arg)...)
			}
			record(c)
			if _, err := dst.Write(raw); err != nil {
				return err
			}
			continue
		}
		if err := forwardRedisCommand(dst, src, n, name, record); err != nil {
			return err
		}
	}
}

// refuseRedis forwards, in place of a refused command, one the server answers
// with an error.
func refuseRedis(dst io.Writer, name string, record func(redisCommand)) error {
	record(redisCommand{refused: name})
	_, err := dst.Write(append(respArrayHeader(1), respBulk([]byte(redisRefusedCommand+name))...))
	return err
}

// readRedisHello reads a HELLO's arguments whole and reports whether it
// would sign in (an AUTH option); one too large to read is refused too.
func readRedisHello(src *bufio.Reader, n int) (bool, [][]byte, error) {
	if n > redisHelloArgs {
		return true, nil, discardRESPBulks(src, n)
	}
	var args [][]byte
	refused := false
	for i := 0; i < n; i++ {
		arg, err := readRESPBulk(src, redisHelloArgBytes)
		if err != nil {
			return false, nil, err
		}
		if !arg.whole {
			if err := discardRESPRest(src, arg); err != nil {
				return false, nil, err
			}
			if err := discardRESPBulks(src, n-i-1); err != nil {
				return false, nil, err
			}
			return true, nil, nil
		}
		if strings.EqualFold(string(arg.data), "AUTH") {
			refused = true
		}
		args = append(args, arg.data)
	}
	if refused {
		return true, nil, nil
	}
	return false, args, nil
}

// forwardRedisCommand forwards one ordinary command, its name already read.
func forwardRedisCommand(dst io.Writer, src *bufio.Reader, n int, name respBulkRead, record func(redisCommand)) error {
	var c redisCommand
	pending := respArrayHeader(n)
	streaming := false
	write := func(b []byte) error {
		if streaming {
			_, err := dst.Write(b)
			return err
		}
		pending = append(pending, b...)
		if len(pending) > redisParsedCommand {
			streaming = true
			_, err := dst.Write(pending)
			pending = nil
			return err
		}
		return nil
	}
	arg := name
	for i := 0; ; i++ {
		c.text.addArg(arg.data, arg.size)
		if err := write(respBulkHeader(arg.size)); err != nil {
			return err
		}
		if err := write(arg.data); err != nil {
			return err
		}
		if !arg.whole {
			// The rest of a long argument: streamed once the command is
			// past its bound, held otherwise.
			rest := int64(arg.size - len(arg.data))
			if streaming || len(pending)+int(rest) > redisParsedCommand {
				if !streaming {
					streaming = true
					if _, err := dst.Write(pending); err != nil {
						return err
					}
					pending = nil
				}
				if _, err := io.CopyN(dst, src, rest); err != nil {
					return err
				}
			} else {
				buf := make([]byte, rest)
				if _, err := io.ReadFull(src, buf); err != nil {
					return err
				}
				if err := write(buf); err != nil {
					return err
				}
			}
			if err := expectCRLF(src); err != nil {
				return err
			}
		}
		if err := write([]byte("\r\n")); err != nil {
			return err
		}
		if i == n-1 {
			break
		}
		var err error
		if arg, err = readRESPBulk(src, redisRecordArgBytes); err != nil {
			return err
		}
	}
	record(c)
	if !streaming {
		_, err := dst.Write(pending)
		return err
	}
	return nil
}

// relayRedisReplies copies the server's replies to the client one at a time,
// recording each once it has passed whole: its type and a bounded rendering.
func relayRedisReplies(dst io.Writer, src *bufio.Reader, record func(kind, text string)) error {
	w := bufio.NewWriterSize(dst, 32<<10)
	for {
		var text boundedText
		kind, err := copyRESPValue(w, src, 0, &text)
		if err != nil {
			_ = w.Flush()
			return err
		}
		record(kind, text.String())
		if err := w.Flush(); err != nil {
			return err
		}
	}
}

// respKinds names each RESP2 and RESP3 type a reply can have.
var respKinds = map[byte]string{
	'+': "status", '-': "error", ':': "integer", '$': "bulk", '*': "array",
	'_': "null", ',': "double", '#': "boolean", '!': "error", '=': "bulk", '(': "bignum",
	'%': "map", '~': "set", '>': "push", '|': "attribute",
}

// copyRESPValue copies one value, nested values included, and renders it into
// text under its bound.
func copyRESPValue(dst *bufio.Writer, src *bufio.Reader, depth int, text *boundedText) (string, error) {
	if depth > redisMaxDepth {
		return "", errors.New("accessgateway: a Redis reply nests too deep")
	}
	t, err := src.ReadByte()
	if err != nil {
		return "", err
	}
	kind, ok := respKinds[t]
	if !ok {
		return "", fmt.Errorf("accessgateway: a Redis reply has unknown type %q", t)
	}
	line, err := readRESPLine(src)
	if err != nil {
		return "", err
	}
	_ = dst.WriteByte(t)
	_, _ = dst.Write(line)
	_, _ = dst.WriteString("\r\n")
	switch t {
	case '+', '-', ':', ',', '#', '(':
		text.add(string(line))
	case '_':
		text.add("(nil)")
	case '$', '!', '=':
		size, err := strconv.Atoi(string(line))
		if err != nil || size < -1 || size > redisMaxBulk {
			return "", errors.New("accessgateway: a Redis reply has a bad length")
		}
		if size == -1 {
			text.add("(nil)")
			return kind, nil
		}
		head := make([]byte, min(size, redisRecordArgBytes))
		if _, err := io.ReadFull(src, head); err != nil {
			return "", err
		}
		_, _ = dst.Write(head)
		text.addArg(head, size)
		if _, err := io.CopyN(dst, src, int64(size-len(head))+2); err != nil {
			return "", err
		}
	case '*', '~', '>', '%', '|':
		n, err := strconv.Atoi(string(line))
		if err != nil || n < -1 || n > redisMaxArgs {
			return "", errors.New("accessgateway: a Redis reply has a bad length")
		}
		if n == -1 {
			text.add("(nil)")
			return kind, nil
		}
		if t == '%' || t == '|' {
			n *= 2
		}
		text.open()
		for i := 0; i < n; i++ {
			if _, err := copyRESPValue(dst, src, depth+1, text); err != nil {
				return "", err
			}
		}
		text.close()
		if t == '|' {
			// An attribute annotates the value that follows it.
			return copyRESPValue(dst, src, depth+1, text)
		}
	}
	return kind, nil
}

// boundedText renders a command or reply under redisRecordTextBytes, each
// value cut at redisRecordArgBytes; binary values appear by their size.
type boundedText struct {
	b         strings.Builder
	truncated bool
	fresh     bool // the next value opens a list and needs no separator
}

func (t *boundedText) add(s string) {
	if t.truncated {
		return
	}
	if t.b.Len() > 0 && !t.fresh {
		t.b.WriteByte(' ')
	}
	t.fresh = false
	if t.b.Len()+len(s) > redisRecordTextBytes {
		t.b.WriteString("[truncated]")
		t.truncated = true
		return
	}
	t.b.WriteString(s)
}

// addArg adds a value of size bytes whose first bytes are head.
func (t *boundedText) addArg(head []byte, size int) {
	switch {
	case !printable(head):
		t.add("<" + strconv.Itoa(size) + " bytes>")
	case size > len(head) || size > redisRecordArgBytes:
		t.add(string(head[:min(len(head), redisRecordArgBytes)]) + "...<" + strconv.Itoa(size) + " bytes>")
	default:
		t.add(string(head))
	}
}

func (t *boundedText) open() {
	t.add("[")
	t.fresh = true
}

func (t *boundedText) close() {
	if !t.truncated {
		t.b.WriteByte(']')
	}
	t.fresh = false
}

func (t *boundedText) String() string { return t.b.String() }

// respBulkRead is one bulk string as read: its size and up to a bound of
// its bytes; whole when that is all of it (its CRLF consumed).
type respBulkRead struct {
	size  int
	data  []byte
	whole bool
}

// readRESPBulk reads a bulk string's header and up to limit of its bytes.
func readRESPBulk(src *bufio.Reader, limit int) (respBulkRead, error) {
	lead, err := src.ReadByte()
	if err != nil {
		return respBulkRead{}, err
	}
	if lead != '$' {
		return respBulkRead{}, errors.New("accessgateway: a Redis command argument is not a bulk string")
	}
	size, err := readRESPNumber(src)
	if err != nil {
		return respBulkRead{}, err
	}
	if size < 0 || size > redisMaxBulk {
		return respBulkRead{}, errors.New("accessgateway: a Redis command argument has a bad length")
	}
	data := make([]byte, min(size, limit))
	if _, err := io.ReadFull(src, data); err != nil {
		return respBulkRead{}, err
	}
	if len(data) < size {
		return respBulkRead{size: size, data: data}, nil
	}
	if err := expectCRLF(src); err != nil {
		return respBulkRead{}, err
	}
	return respBulkRead{size: size, data: data, whole: true}, nil
}

// discardRESPRest discards what is left of a bulk string read in part.
func discardRESPRest(src *bufio.Reader, b respBulkRead) error {
	if _, err := io.CopyN(io.Discard, src, int64(b.size-len(b.data))); err != nil {
		return err
	}
	return expectCRLF(src)
}

// discardRESPBulks reads and drops n bulk strings.
func discardRESPBulks(src *bufio.Reader, n int) error {
	for i := 0; i < n; i++ {
		b, err := readRESPBulk(src, 0)
		if err != nil {
			return err
		}
		if !b.whole {
			if err := discardRESPRest(src, b); err != nil {
				return err
			}
		}
	}
	return nil
}

func expectCRLF(src *bufio.Reader) error {
	var crlf [2]byte
	if _, err := io.ReadFull(src, crlf[:]); err != nil {
		return err
	}
	if crlf != [2]byte{'\r', '\n'} {
		return errors.New("accessgateway: a Redis value does not end with CRLF")
	}
	return nil
}

// readRESPLine reads a line up to its CRLF, under redisMaxLine.
func readRESPLine(src *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := src.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > redisMaxLine {
			return nil, errors.New("accessgateway: a Redis line is too long")
		}
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, errors.New("accessgateway: a Redis line does not end with CRLF")
	}
	return line[:len(line)-2], nil
}

func readRESPNumber(src *bufio.Reader) (int, error) {
	line, err := readRESPLine(src)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(string(line))
	if err != nil {
		return 0, errors.New("accessgateway: a Redis length is not a number")
	}
	return n, nil
}

func respArrayHeader(n int) []byte { return []byte("*" + strconv.Itoa(n) + "\r\n") }

func respBulkHeader(size int) []byte { return []byte("$" + strconv.Itoa(size) + "\r\n") }

func respBulk(b []byte) []byte {
	return append(append(respBulkHeader(len(b)), b...), '\r', '\n')
}
