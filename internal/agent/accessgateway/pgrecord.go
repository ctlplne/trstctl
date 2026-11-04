// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"encoding/binary"
	"io"
	"strconv"
	"strings"
)

// What a PostgreSQL session's recording keeps of each statement's result.
const (
	pgRecordRows        = 10
	pgRecordValueBytes  = 256
	pgRecordResultBytes = 4 << 10
	// pgParsedMessage is the largest message read whole for recording; a
	// bigger one (a bulk COPY row, a huge result value) is relayed as it
	// streams and recorded by its size.
	pgParsedMessage = 1 << 20
)

// pgRecorder reads a relayed PostgreSQL session as statements and results.
type pgRecorder struct {
	conn      *connRecorder
	rows      int
	rowBytes  int
	truncated bool
}

// relayPostgres copies one direction message by message, handing each
// message to record before it is forwarded, so a recorder that cannot keep up
// holds the session rather than losing what it would have seen.
func relayPostgres(dst io.Writer, src io.Reader, record func(kind byte, body []byte, size int)) error {
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(src, header); err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(header[1:])
		if length < 4 {
			return io.ErrUnexpectedEOF
		}
		size := int(length - 4)
		if size > pgParsedMessage {
			record(header[0], nil, size)
			if _, err := dst.Write(header); err != nil {
				return err
			}
			if _, err := io.CopyN(dst, src, int64(size)); err != nil {
				return err
			}
			continue
		}
		msg := make([]byte, 5+size)
		copy(msg, header)
		if _, err := io.ReadFull(src, msg[5:]); err != nil {
			return err
		}
		record(header[0], msg[5:], size)
		if _, err := dst.Write(msg); err != nil {
			return err
		}
	}
}

// client records what the client sent: queries, prepared statements and
// their bound parameters.
func (p *pgRecorder) client(kind byte, body []byte, size int) {
	switch kind {
	case 'Q':
		if q, _, ok := cutPGString(body); ok {
			p.conn.event("sql", "query", q, 0)
		}
	case 'P':
		name, rest, ok := cutPGString(body)
		query, _, ok2 := cutPGString(rest)
		if ok && ok2 {
			kind := "prepare"
			if name != "" {
				kind += " " + name
			}
			p.conn.event("sql", kind, query, 0)
		}
	case 'B':
		p.conn.event("sql", "bind", pgBindText(body), 0)
	case 'd':
		p.conn.event("sql", "copy data", strconv.Itoa(size)+" bytes", 0)
	case 'X':
		p.conn.event("sql", "terminate", "", 0)
	}
}

// server records what the database answered: column names, the first rows
// of each result up to a bound, command tags and error codes.
func (p *pgRecorder) server(kind byte, body []byte, size int) {
	switch kind {
	case 'T':
		p.rows, p.rowBytes, p.truncated = 0, 0, false
		names := pgColumnNames(body)
		p.conn.event("result", "columns", strings.Join(names, ", "), len(names))
	case 'D':
		if p.rows >= pgRecordRows || p.rowBytes >= pgRecordResultBytes || body == nil {
			if !p.truncated {
				p.truncated = true
				p.conn.event("result", "truncated", "further rows are not recorded", 0)
			}
			return
		}
		text := pgRowText(body)
		p.rows++
		p.rowBytes += len(text)
		p.conn.event("result", "row", text, 0)
	case 'C':
		if tag, _, ok := cutPGString(body); ok {
			p.conn.event("result", "complete", tag, 0)
		}
	case 'E':
		p.conn.event("result", "error", pgErrorText(body), 0)
	case 'd':
		p.conn.event("result", "copy data", strconv.Itoa(size)+" bytes", 0)
	}
}

func pgColumnNames(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(body))
	rest := body[2:]
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name, after, ok := cutPGString(rest)
		if !ok || len(after) < 18 {
			break
		}
		names = append(names, name)
		rest = after[18:]
	}
	return names
}

// pgRowText is a data row's values, each cut at pgRecordValueBytes; binary
// values are recorded by their size.
func pgRowText(body []byte) string {
	values, ok := pgValues(body, 2)
	if !ok {
		return "(unreadable row)"
	}
	return strings.Join(values, " | ")
}

// pgBindText is a bind's parameter values, recorded like row values.
func pgBindText(body []byte) string {
	_, rest, ok := cutPGString(body) // portal
	_, rest, ok2 := cutPGString(rest)
	if !ok || !ok2 || len(rest) < 2 {
		return "(unreadable bind)"
	}
	formats := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < formats*2 {
		return "(unreadable bind)"
	}
	values, ok := pgValues(rest[formats*2:], 2)
	if !ok {
		return "(unreadable bind)"
	}
	return strings.Join(values, " | ")
}

func pgValues(body []byte, countBytes int) ([]string, bool) {
	if len(body) < countBytes {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(body))
	rest := body[countBytes:]
	values := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if len(rest) < 4 {
			return nil, false
		}
		size := int32(binary.BigEndian.Uint32(rest)) // #nosec G115 -- the wire field is a signed length (-1 is NULL) (CWE-190)
		rest = rest[4:]
		if size < 0 {
			values = append(values, "NULL")
			continue
		}
		if int(size) > len(rest) {
			return nil, false
		}
		v := rest[:size]
		rest = rest[size:]
		switch {
		case !printable(v):
			values = append(values, "("+strconv.Itoa(len(v))+" bytes)")
		case len(v) > pgRecordValueBytes:
			values = append(values, string(v[:pgRecordValueBytes])+"…")
		default:
			values = append(values, string(v))
		}
	}
	return values, true
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// pgErrorText is an error's SQLSTATE and message.
func pgErrorText(body []byte) string {
	var code, message string
	for len(body) > 1 && body[0] != 0 {
		field := body[0]
		value, rest, ok := cutPGString(body[1:])
		if !ok {
			break
		}
		switch field {
		case 'C':
			code = value
		case 'M':
			message = value
		}
		body = rest
	}
	return code + " " + message
}
