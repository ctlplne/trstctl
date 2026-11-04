// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
)

// testConnRecorder records one connection; frames closes it and renders its
// statement and result events as "kind: text" lines.
func testConnRecorder(t *testing.T, secrets ...[]byte) (*connRecorder, func() string) {
	t.Helper()
	up := &fakeUploader{}
	rec := newSessionRecorder(context.Background(), up, relay.Job{JobID: 1, Attempt: 1}, time.Now, secrets...)
	conn := rec.connection()
	return conn, func() string {
		conn.close()
		rec.close()
		var events []string
		lines := bufio.NewScanner(bytes.NewReader(bytes.Join(up.chunks, nil)))
		for lines.Scan() {
			var f frame
			if err := json.Unmarshal(lines.Bytes(), &f); err != nil {
				t.Fatal(err)
			}
			if f.Kind != "" {
				events = append(events, f.Kind+": "+f.Text)
			}
		}
		return strings.Join(events, "\n")
	}
}

func mysqlPacket(seq byte, payload ...byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...) // #nosec G115 -- the 3-byte little-endian packet length (CWE-190)
}

func lenencString(s string) []byte { return append([]byte{byte(len(s))}, s...) } // #nosec G115 -- test strings are under 251 bytes (CWE-190)

func columnDef(name string) []byte {
	var p []byte
	for _, part := range []string{"def", "app", "t", "t", name, name} {
		p = append(p, lenencString(part)...)
	}
	return append(p, 0x0c, 0x21, 0, 0xff, 0, 0, 0, 0xfd, 0, 0, 0, 0)
}

func TestMySQLRelayRefusesChangeUserAndForwardsCommands(t *testing.T) {
	query := mysqlPacket(0, append([]byte{mysqlComQuery}, "SELECT CURRENT_USER()"...)...)
	changeUser := mysqlPacket(0, append([]byte{mysqlComChangeUser}, "root\x00"...)...)
	// A LOAD DATA LOCAL file packet starting with the same byte is data, not
	// a command: its sequence number is not 0.
	fileData := mysqlPacket(2, mysqlComChangeUser, 'x')
	big := mysqlPacket(0, append([]byte{mysqlComQuery}, strings.Repeat("x", mysqlParsedPacket+10)...)...)
	var server, client bytes.Buffer
	m := &mysqlRelay{client: &client}
	in := bytes.NewReader(bytes.Join([][]byte{query, changeUser, fileData, big}, nil))
	if err := m.commands(&server, in); err == nil || err.Error() != "EOF" {
		t.Fatalf("relay ended with %v", err)
	}
	if want := bytes.Join([][]byte{query, fileData, big}, nil); !bytes.Equal(server.Bytes(), want) {
		t.Fatalf("forwarded %d bytes, want the query, the file packet and the large query (%d bytes)", server.Len(), len(want))
	}
	refusal := client.Len() - 4
	if !bytes.HasPrefix(client.Bytes(), []byte{byte(refusal), 0, 0, 1, 0xff, 0x15, 0x04}) || !strings.Contains(client.String(), "COM_CHANGE_USER is refused") { // #nosec G115 -- one short ERR packet (CWE-190)
		t.Fatalf("the refusal sent to the client = %q", client.Bytes())
	}
}

func TestMySQLRelayRecordsResults(t *testing.T) {
	rec, frames := testConnRecorder(t)
	var client bytes.Buffer
	m := &mysqlRelay{client: &client, rec: rec, deprecateEOF: true}
	m.command, m.state = mysqlComQuery, mysqlAwaitFirst
	packets := [][]byte{
		mysqlPacket(1, 2),
		mysqlPacket(2, columnDef("current_user")...),
		mysqlPacket(3, columnDef("note")...),
	}
	for i := 0; i < 12; i++ {
		packets = append(packets, mysqlPacket(byte(4+i), append(lenencString("a256@%"), 0xfb)...))
	}
	packets = append(packets, mysqlPacket(16, 0xfe, 0, 0, 2, 0, 0, 0))
	in := bytes.Join(packets, nil)
	if err := m.responses(bytes.NewReader(in)); err == nil || err.Error() != "EOF" {
		t.Fatalf("relay ended with %v", err)
	}
	if !bytes.Equal(client.Bytes(), in) {
		t.Fatal("the result was not forwarded byte for byte")
	}
	m.command, m.state = mysqlComQuery, mysqlAwaitFirst
	errPacket := mysqlPacket(1, append([]byte{0xff, 0x8e, 0x04}, "#42000SELECT command denied to user"...)...)
	if err := m.responses(bytes.NewReader(errPacket)); err == nil {
		t.Fatal("relay ended without EOF")
	}
	text := frames()
	for _, want := range []string{"columns: current_user, note", "row: a256@% | NULL", "truncated: further rows are not recorded",
		"complete: 10 rows recorded", "error: 1166 42000: SELECT command denied to user"} {
		if !strings.Contains(text, want) {
			t.Fatalf("recording lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "row: ") != mysqlRecordRows {
		t.Fatalf("recorded %d rows, want %d:\n%s", strings.Count(text, "row: "), mysqlRecordRows, text)
	}
}

// A COM_QUERY carrying query attributes is recorded by its statement.
func TestMySQLQueryTextSkipsQueryAttributes(t *testing.T) {
	plain := []byte(" SELECT 1")
	if got := mysqlQueryText(plain, false); got != "SELECT 1" {
		t.Fatalf("plain = %q", got)
	}
	none := append([]byte{0x00, 0x01}, "SELECT note FROM app.notes"...)
	if got := mysqlQueryText(none, true); got != "SELECT note FROM app.notes" {
		t.Fatalf("no attributes = %q", got)
	}
	// Two attributes: a string "trace" = "abc" and a NULL long.
	two := []byte{0x02, 0x01, 0x02, 0x01, 0xfd, 0x00}
	two = append(two, lenencString("trace")...)
	two = append(two, 0x03, 0x00)
	two = append(two, lenencString("n")...)
	two = append(two, lenencString("abc")...)
	two = append(two, "SELECT 2"...)
	if got := mysqlQueryText(two, true); got != "SELECT 2" {
		t.Fatalf("with attributes = %q", got)
	}
	if got := mysqlQueryText([]byte{0x05, 0x01, 0x00}, true); got != "(unreadable query attributes)" {
		t.Fatalf("truncated attributes = %q", got)
	}
}

// FuzzMySQLCommandRelay: no client bytes panic the command relay, and no
// COM_CHANGE_USER (a command packet, sequence 0) is ever forwarded.
func FuzzMySQLCommandRelay(f *testing.F) {
	f.Add(mysqlPacket(0, append([]byte{mysqlComQuery}, "SELECT 1"...)...))
	f.Add(mysqlPacket(0, append([]byte{mysqlComChangeUser}, "root\x00"...)...))
	f.Add(append(mysqlPacket(2, mysqlComChangeUser), mysqlPacket(0, mysqlComQuit)...))
	f.Fuzz(func(t *testing.T, in []byte) {
		var server, client bytes.Buffer
		m := &mysqlRelay{client: &client, queryAttributes: len(in)%2 == 0}
		_ = m.commands(&server, bytes.NewReader(in))
		out := server.Bytes()
		for len(out) >= 4 {
			size := int(out[0]) | int(out[1])<<8 | int(out[2])<<16
			if out[3] == 0 && size > 0 && len(out) > 4 && out[4] == mysqlComChangeUser {
				t.Fatalf("a COM_CHANGE_USER was forwarded from %q", in)
			}
			if len(out) < 4+size {
				break
			}
			out = out[4+size:]
		}
	})
}

// FuzzMySQLResponseRelay: no server bytes panic the response relay, and what
// it forwards is exactly what it read.
func FuzzMySQLResponseRelay(f *testing.F) {
	f.Add(mysqlPacket(1, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00))
	f.Add(append(mysqlPacket(1, 1), mysqlPacket(2, columnDef("a")...)...))
	f.Fuzz(func(t *testing.T, in []byte) {
		var client bytes.Buffer
		rec, frames := testConnRecorder(t)
		m := &mysqlRelay{client: &client, rec: rec, deprecateEOF: len(in)%2 == 0}
		m.command = mysqlComQuery
		_ = m.responses(bytes.NewReader(in))
		_ = frames()
		if !bytes.HasPrefix(in, client.Bytes()) {
			t.Fatalf("relayed %q from %q", client.Bytes(), in)
		}
	})
}

// A COM_CHANGE_USER too long to read whole — past the parse bound, or
// spanning packets — is refused like any other, and none of it is forwarded.
func TestMySQLRelayRefusesLongChangeUser(t *testing.T) {
	long := mysqlPacket(0, append([]byte{mysqlComChangeUser}, bytes.Repeat([]byte{'a'}, mysqlParsedPacket+10)...)...)
	full := make([]byte, 4+mysqlMaxPacket)
	full[0], full[1], full[2], full[3], full[4] = 0xff, 0xff, 0xff, 0, mysqlComChangeUser
	continuation := mysqlPacket(1, []byte("rest of the change-user packet")...)
	query := mysqlPacket(0, append([]byte{mysqlComQuery}, "SELECT CURRENT_USER()"...)...)
	var server, client bytes.Buffer
	m := &mysqlRelay{client: &client}
	in := bytes.NewReader(bytes.Join([][]byte{long, full, continuation, query}, nil))
	if err := m.commands(&server, in); err == nil || err.Error() != "EOF" {
		t.Fatalf("relay ended with %v", err)
	}
	if !bytes.Equal(server.Bytes(), query) {
		t.Fatalf("forwarded %d bytes, want only the query", server.Len())
	}
	if strings.Count(client.String(), "COM_CHANGE_USER is refused") != 2 {
		t.Fatalf("refusals sent = %q", client.String())
	}
}
