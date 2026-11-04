// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/mysqlsignin"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// MySQL commands the gateway reads (A256).
const (
	mysqlComQuit        = 0x01
	mysqlComInitDB      = 0x02
	mysqlComQuery       = 0x03
	mysqlComChangeUser  = 0x11
	mysqlComStmtPrepare = 0x16
	mysqlComStmtExecute = 0x17
)

// What a MySQL session's recording keeps of each result, and the largest
// packet read whole for recording; a bigger one is relayed as it streams and
// recorded by its size.
const (
	mysqlRecordRows        = 10
	mysqlRecordValueBytes  = 256
	mysqlRecordResultBytes = 4 << 10
	mysqlParsedPacket      = 1 << 20
)

// serveMySQL answers a stock MySQL client's handshake itself and signs in
// upstream as the session's account (A256): the client's own answer is not
// checked (the admitted tunnel is its authentication); the gateway signs in
// with the session's DSN, speaking the client's capability flags so the
// relayed command phase means the same to both ends, hands the client the
// server's OK and relays commands and results. COM_CHANGE_USER, which would
// sign the connection in as another account, is refused. The client never
// receives the DSN.
func serveMySQL(ctx context.Context, client net.Conn, dsn []byte, deadline time.Time, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	target, err := mysqlsignin.ParseDSN(dsn)
	if err != nil {
		return err
	}
	defer target.Wipe()
	signInCtx, cancel := context.WithDeadline(ctx, earliest(deadline, time.Now().Add(30*time.Second)))
	defer cancel()
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	server, err := dial(signInCtx, "tcp", target.Address)
	if err != nil {
		_ = mysqlRefuse(client, 0, "the access gateway cannot reach the target")
		return err
	}
	defer func() { _ = server.Close() }()
	signInDeadline, _ := signInCtx.Deadline()
	_ = server.SetDeadline(signInDeadline)
	_, payload, err := mysqlsignin.ReadPacket(server)
	if err != nil {
		_ = mysqlRefuse(client, 0, "the target sent no handshake")
		return err
	}
	handshake, err := mysqlsignin.ParseHandshake(payload)
	if err != nil {
		_ = mysqlRefuse(client, 0, "the target refused the connection")
		return err
	}
	greeting, err := mysqlsignin.ClientHandshake(handshake)
	if err != nil {
		return err
	}
	if err := mysqlsignin.WritePacket(client, 0, greeting); err != nil {
		return err
	}
	_, payload, err = mysqlsignin.ReadPacket(client)
	if err != nil {
		return err
	}
	response, err := mysqlsignin.ParseClientResponse(payload)
	secret.Wipe(payload)
	if err != nil {
		return err
	}
	if response.SSLRequest {
		// The gateway offered no TLS: the client's hop is its CLI's loopback
		// listener, and the tunnel to the gateway is already TLS.
		return errors.New("accessgateway: the MySQL client asked for TLS, which the gateway's handshake does not offer")
	}
	ok, err := mysqlsignin.SignIn(server, handshake, target, response)
	if err != nil {
		_ = mysqlRefuse(client, 2, "the upstream database refused the session's account")
		return err
	}
	_ = server.SetDeadline(deadline)
	if err := mysqlsignin.WritePacket(client, 2, ok); err != nil {
		return err
	}
	negotiated := response.Capabilities & handshake.Capabilities
	relay := &mysqlRelay{client: client, rec: rec,
		deprecateEOF:    negotiated&mysqlsignin.ClientDeprecateEOF != 0,
		queryAttributes: negotiated&mysqlsignin.ClientQueryAttributes != 0}
	done := make(chan struct{}, 2)
	go func() { _ = relay.commands(server, client); _ = server.Close(); done <- struct{}{} }()
	go func() { _ = relay.responses(server); _ = client.Close(); done <- struct{}{} }()
	<-done
	<-done
	return nil
}

// mysqlRefuse sends an ERR packet: access denied, with the gateway's reason,
// never the upstream's text (it can name the account).
func mysqlRefuse(w io.Writer, seq byte, message string) error {
	p := []byte{0xff}
	p = binary.LittleEndian.AppendUint16(p, 1045)
	p = append(p, "#28000"...)
	p = append(p, message...)
	return mysqlsignin.WritePacket(w, seq, p)
}

// mysqlRelay relays one signed-in connection's command phase. MySQL is
// request and response: a client packet with sequence number 0 is a command
// (continuations and LOAD DATA LOCAL file packets never are), and the last
// command tells the response relay how to read what follows.
type mysqlRelay struct {
	client       io.Writer
	rec          *connRecorder
	deprecateEOF bool
	// queryAttributes is set when the connection negotiated query
	// attributes: each COM_QUERY carries them before its statement.
	queryAttributes bool

	// clientMu serializes writes to the client: the response relay's and a
	// refusal the gateway answers itself.
	clientMu sync.Mutex
	mu       sync.Mutex
	command  byte

	// The response relay's place in a result.
	state     int
	columns   int
	names     []string
	rows      int
	rowBytes  int
	truncated bool
}

const (
	mysqlAwaitFirst = iota
	mysqlColumnDefs
	mysqlColumnsEOF
	mysqlRows
)

// readMySQLPacket reads one packet's header and, up to mysqlParsedPacket,
// its payload; a bigger payload is left for the caller to stream.
func readMySQLPacket(src io.Reader) (header [4]byte, payload []byte, size int, err error) {
	if _, err = io.ReadFull(src, header[:]); err != nil {
		return
	}
	size = int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if size > mysqlParsedPacket {
		return
	}
	payload = make([]byte, size)
	_, err = io.ReadFull(src, payload)
	return
}

// forward writes a packet read by readMySQLPacket, streaming the payload it
// left unread.
func forwardMySQLPacket(dst io.Writer, src io.Reader, header [4]byte, payload []byte, size int) error {
	if _, err := dst.Write(header[:]); err != nil {
		return err
	}
	if payload == nil && size > 0 {
		_, err := io.CopyN(dst, src, int64(size))
		return err
	}
	_, err := dst.Write(payload)
	return err
}

// commands forwards the client's packets. A command packet's first byte is
// read before any of it is forwarded, however long the packet, so a refused
// command never reaches the server; the rest of a refused command that spans
// packets is discarded with it.
func (m *mysqlRelay) commands(server io.Writer, client io.Reader) error {
	discarding := false
	for {
		var header [4]byte
		if _, err := io.ReadFull(client, header[:]); err != nil {
			return err
		}
		size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
		if discarding {
			if _, err := io.CopyN(io.Discard, client, int64(size)); err != nil {
				return err
			}
			discarding = size == mysqlMaxPacket
			continue
		}
		if header[3] != 0 || size == 0 {
			// Not a command: a continuation, a LOAD DATA LOCAL file packet
			// or an empty packet.
			if err := forwardMySQLPacket(server, client, header, nil, size); err != nil {
				return err
			}
			continue
		}
		var command [1]byte
		if _, err := io.ReadFull(client, command[:]); err != nil {
			return err
		}
		if command[0] == mysqlComChangeUser {
			// Another account on this connection: refused, answered here
			// and never forwarded.
			if _, err := io.CopyN(io.Discard, client, int64(size-1)); err != nil {
				return err
			}
			discarding = size == mysqlMaxPacket
			m.record("sql", "refused", "COM_CHANGE_USER")
			m.clientMu.Lock()
			err := mysqlRefuse(m.client, 1, "COM_CHANGE_USER is refused: the access gateway signs in as the session's account")
			m.clientMu.Unlock()
			if err != nil {
				return err
			}
			continue
		}
		m.mu.Lock()
		m.command, m.state = command[0], mysqlAwaitFirst
		m.mu.Unlock()
		if size > mysqlParsedPacket {
			// Recorded by its size and forwarded as it streams.
			m.record("sql", "command", "0x"+strconv.FormatUint(uint64(command[0]), 16)+" ("+strconv.Itoa(size)+" bytes)")
			if _, err := server.Write(append(header[:], command[0])); err != nil {
				return err
			}
			if _, err := io.CopyN(server, client, int64(size-1)); err != nil {
				return err
			}
			continue
		}
		payload := make([]byte, size)
		payload[0] = command[0]
		if _, err := io.ReadFull(client, payload[1:]); err != nil {
			return err
		}
		m.recordCommand(payload)
		if err := forwardMySQLPacket(server, client, header, payload, size); err != nil {
			return err
		}
	}
}

// responses forwards the server's packets to the client, recording results.
func (m *mysqlRelay) responses(server io.Reader) error {
	for {
		header, payload, size, err := readMySQLPacket(server)
		if err != nil {
			return err
		}
		m.recordResponse(header[3], payload, size)
		m.clientMu.Lock()
		err = forwardMySQLPacket(m.client, server, header, payload, size)
		m.clientMu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (m *mysqlRelay) record(name, kind, text string) {
	if m.rec != nil {
		m.rec.event(name, kind, text, 0)
	}
}

// recordCommand records what a command asked: its statement, database or
// prepared statement and the size of what it bound. A statement is recorded
// without the whitespace around it (a client splitting a script keeps the
// space after each semicolon); the relayed bytes are unchanged.
func (m *mysqlRelay) recordCommand(p []byte) {
	switch p[0] {
	case mysqlComQuery:
		m.record("sql", "query", mysqlQueryText(p[1:], m.queryAttributes))
	case mysqlComStmtPrepare:
		m.record("sql", "prepare", strings.TrimSpace(string(p[1:])))
	case mysqlComStmtExecute:
		if len(p) >= 5 {
			m.record("sql", "execute", "statement "+strconv.FormatUint(uint64(binary.LittleEndian.Uint32(p[1:])), 10)+", "+strconv.Itoa(len(p)-5)+" bytes")
		}
	case mysqlComInitDB:
		m.record("sql", "use", strings.TrimSpace(string(p[1:])))
	case mysqlComQuit:
		m.record("sql", "terminate", "")
	}
}

// recordResponse follows a command's response: OK, ERR, or a result's
// column definitions, its first rows up to a bound and its terminator. It
// only reads; the packet is forwarded as it came whatever it records.
func (m *mysqlRelay) recordResponse(seq byte, p []byte, size int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p == nil {
		if m.state == mysqlRows {
			m.recordRow(nil, size)
		}
		return
	}
	switch m.state {
	case mysqlAwaitFirst:
		if seq == 0 || len(p) == 0 {
			return
		}
		switch {
		case p[0] == 0x00 && (m.command != mysqlComStmtPrepare):
			m.recordOK(p)
		case p[0] == 0x00:
			if len(p) >= 9 {
				m.record("result", "prepared", "statement "+strconv.FormatUint(uint64(binary.LittleEndian.Uint32(p[1:])), 10))
			}
		case p[0] == 0xff:
			m.record("result", "error", mysqlErrorText(p))
		case p[0] == 0xfb:
			m.record("result", "local infile", string(p[1:]))
		case m.command == mysqlComQuery || m.command == mysqlComStmtExecute:
			n, _, ok := mysqlLenenc(p)
			if ok && n > 0 {
				m.columns, m.names, m.rows, m.rowBytes, m.truncated = n, nil, 0, 0, false
				m.state = mysqlColumnDefs
			}
		}
	case mysqlColumnDefs:
		m.names = append(m.names, mysqlColumnName(p))
		if len(m.names) == m.columns {
			m.record("result", "columns", strings.Join(m.names, ", "))
			m.state = mysqlRows
			if !m.deprecateEOF {
				m.state = mysqlColumnsEOF
			}
		}
	case mysqlColumnsEOF:
		m.state = mysqlRows
	case mysqlRows:
		switch {
		case len(p) > 0 && p[0] == 0xff:
			m.record("result", "error", mysqlErrorText(p))
			m.state = mysqlAwaitFirst
		case len(p) > 0 && p[0] == 0xfe && len(p) < mysqlMaxPacket:
			// The result's terminator; another result of the same command
			// (more results) starts over from its first packet.
			m.record("result", "complete", strconv.Itoa(m.rows)+" rows recorded")
			m.state = mysqlAwaitFirst
		default:
			m.recordRow(p, size)
		}
	}
}

// mysqlMaxPacket is the largest payload one MySQL packet carries; a longer
// one continues in the next.
const mysqlMaxPacket = 1<<24 - 1

func (m *mysqlRelay) recordRow(p []byte, size int) {
	if m.rows >= mysqlRecordRows || m.rowBytes >= mysqlRecordResultBytes || p == nil {
		if !m.truncated {
			m.truncated = true
			m.record("result", "truncated", "further rows are not recorded")
		}
		return
	}
	var text string
	if m.command == mysqlComStmtExecute {
		text = "(" + strconv.Itoa(size) + " bytes, binary)"
	} else {
		text = mysqlRowText(p)
	}
	m.rows++
	m.rowBytes += len(text)
	m.record("result", "row", text)
}

// recordOK records an OK: rows affected.
func (m *mysqlRelay) recordOK(p []byte) {
	affected, _, ok := mysqlLenenc(p[1:])
	if !ok {
		return
	}
	m.record("result", "ok", strconv.Itoa(affected)+" rows affected")
}

// mysqlQueryText is a COM_QUERY's statement. With query attributes
// negotiated the statement follows them: a count, a set count (1) and, for
// a nonzero count, a NULL bitmap, the types and names, and the non-NULL
// values in the binary protocol's encoding.
func mysqlQueryText(p []byte, attributes bool) string {
	if attributes {
		count, used, ok := mysqlLenenc(p)
		if !ok || count > 1<<12 {
			return "(unreadable query attributes)"
		}
		p = p[used:]
		if _, used, ok = mysqlLenenc(p); !ok {
			return "(unreadable query attributes)"
		}
		p = p[used:]
		if count > 0 {
			n := count
			bitmap := (n + 7) / 8
			if len(p) < bitmap+1 || p[bitmap] != 1 {
				return "(unreadable query attributes)"
			}
			nulls, rest := p[:bitmap], p[bitmap+1:]
			types := make([]byte, n)
			for i := range types {
				if len(rest) < 2 {
					return "(unreadable query attributes)"
				}
				types[i], rest = rest[0], rest[2:]
				l, used, ok := mysqlLenenc(rest)
				if !ok || len(rest)-used < l {
					return "(unreadable query attributes)"
				}
				rest = rest[used+l:]
			}
			for i, typ := range types {
				if nulls[i/8]&(1<<(i%8)) != 0 {
					continue
				}
				size, ok := mysqlBinaryValueSize(typ, rest)
				if !ok {
					return "(unreadable query attributes)"
				}
				rest = rest[size:]
			}
			p = rest
		}
	}
	return strings.TrimSpace(string(p))
}

// mysqlFixedValueSizes are the binary protocol's fixed-size types: TINY,
// SHORT and YEAR, LONG, INT24 and FLOAT, LONGLONG and DOUBLE, NULL.
var mysqlFixedValueSizes = map[byte]int{0x01: 1, 0x02: 2, 0x0d: 2, 0x03: 4, 0x09: 4, 0x04: 4, 0x08: 8, 0x05: 8, 0x06: 0}

// mysqlBinaryValueSize is how many bytes one binary-protocol value of a
// type takes at the start of b.
func mysqlBinaryValueSize(typ byte, b []byte) (int, bool) {
	if n, ok := mysqlFixedValueSizes[typ]; ok {
		return n, len(b) >= n
	}
	switch typ {
	case 0x07, 0x0a, 0x0b, 0x0c: // TIMESTAMP, DATE, TIME, DATETIME: a length byte
		if len(b) < 1 || len(b) < 1+int(b[0]) {
			return 0, false
		}
		return 1 + int(b[0]), true
	}
	l, used, ok := mysqlLenenc(b) // strings, decimals, blobs, JSON, BIT
	if !ok || len(b)-used < l {
		return 0, false
	}
	return used + l, true
}

// mysqlColumnName is a column definition's name (protocol 4.1: catalog,
// schema, table, original table, name, ...).
func mysqlColumnName(p []byte) string {
	rest := p
	for i := 0; i < 5; i++ {
		n, used, ok := mysqlLenenc(rest)
		if !ok || len(rest)-used < n {
			return "?"
		}
		if i == 4 {
			return string(rest[used : used+n])
		}
		rest = rest[used+n:]
	}
	return "?"
}

// mysqlRowText is a text row's values, each cut at mysqlRecordValueBytes;
// binary values are recorded by their size, NULL as NULL.
func mysqlRowText(p []byte) string {
	var values []string
	for len(p) > 0 {
		if p[0] == 0xfb {
			values = append(values, "NULL")
			p = p[1:]
			continue
		}
		n, used, ok := mysqlLenenc(p)
		if !ok || len(p)-used < n {
			values = append(values, "?")
			break
		}
		v := p[used : used+n]
		switch {
		case !printable(v):
			values = append(values, "<"+strconv.Itoa(len(v))+" bytes>")
		case len(v) > mysqlRecordValueBytes:
			values = append(values, string(v[:mysqlRecordValueBytes])+"...")
		default:
			values = append(values, string(v))
		}
		p = p[used+n:]
	}
	return strings.Join(values, " | ")
}

// mysqlErrorText is an ERR packet's code, state and message.
func mysqlErrorText(p []byte) string {
	if len(p) < 3 {
		return "error"
	}
	code := strconv.Itoa(int(binary.LittleEndian.Uint16(p[1:])))
	msg := string(p[3:])
	if strings.HasPrefix(msg, "#") && len(msg) >= 6 {
		return code + " " + msg[1:6] + ": " + msg[6:]
	}
	return code + ": " + msg
}

// mysqlLenenc reads a length-encoded integer: its value and the bytes it
// took. A value past mysqlMaxLenenc is refused: nothing the relay reads
// whole is that long.
func mysqlLenenc(b []byte) (int, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] {
	case 0xfc:
		if len(b) < 3 {
			return 0, 0, false
		}
		return int(binary.LittleEndian.Uint16(b[1:])), 3, true
	case 0xfd:
		if len(b) < 4 {
			return 0, 0, false
		}
		return int(b[1]) | int(b[2])<<8 | int(b[3])<<16, 4, true
	case 0xfe:
		if len(b) < 9 {
			return 0, 0, false
		}
		v := binary.LittleEndian.Uint64(b[1:])
		if v > mysqlMaxLenenc {
			return 0, 0, false
		}
		return int(v), 9, true // #nosec G115 -- bounded by mysqlMaxLenenc just above (CWE-190)
	case 0xfb, 0xff:
		return 0, 0, false
	}
	return int(b[0]), 1, true
}

// mysqlMaxLenenc bounds a length-encoded value the relay accepts.
const mysqlMaxLenenc = 1 << 30
