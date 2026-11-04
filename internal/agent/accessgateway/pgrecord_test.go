// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
)

func pgMsg(kind byte, body []byte) []byte { return pgMessage(kind, body) }

func pgRow(values ...string) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(values))) // #nosec G115 -- test rows are small (CWE-190)
	for _, v := range values {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v))) // #nosec G115 -- test values are small (CWE-190)
		b = append(b, v...)
	}
	return b
}

// A relayed PostgreSQL session passes through byte for byte while its
// statements, bound values, columns, a bounded sample of rows, tags and
// errors are recorded — masked.
func TestPostgresRecordingKeepsStatementsAndBoundedResultsA255(t *testing.T) {
	up := &fakeUploader{}
	rec := newSessionRecorder(context.Background(), up, relay.Job{JobID: 1, Attempt: 1}, time.Now, []byte("injected-Pa55word"))
	conn := rec.connection()
	p := &pgRecorder{conn: conn}

	var client bytes.Buffer
	client.Write(pgMsg('Q', []byte("SELECT name FROM users WHERE token = 'ghp_"+strings.Repeat("a", 36)+"'\x00")))
	bind := append([]byte("\x00stmt1\x00"), 0, 0)
	bind = append(bind, pgRow("injected-Pa55word", "42")...)
	bind = append(bind, 0, 0)
	client.Write(pgMsg('B', bind))
	var relayed bytes.Buffer
	if err := relayPostgres(&relayed, bytes.NewReader(client.Bytes()), p.client); err == nil || !bytes.Equal(relayed.Bytes(), client.Bytes()) {
		t.Fatalf("client messages were not relayed byte for byte (err %v)", err)
	}

	var server bytes.Buffer
	cols := binary.BigEndian.AppendUint16(nil, 1)
	cols = append(cols, "name\x00"...)
	cols = append(cols, make([]byte, 18)...)
	server.Write(pgMsg('T', cols))
	for i := 0; i < 15; i++ {
		server.Write(pgMsg('D', pgRow("row-"+string(rune('a'+i)))))
	}
	server.Write(pgMsg('C', []byte("SELECT 15\x00")))
	server.Write(pgMsg('E', []byte("SERROR\x00C42501\x00Mpermission denied\x00\x00")))
	relayed.Reset()
	_ = relayPostgres(&relayed, bytes.NewReader(server.Bytes()), p.server)
	if !bytes.Equal(relayed.Bytes(), server.Bytes()) {
		t.Fatal("server messages were not relayed byte for byte")
	}
	conn.close()
	rec.close()

	var events []string
	lines := bufio.NewScanner(bytes.NewReader(bytes.Join(up.chunks, nil)))
	for lines.Scan() {
		var f frame
		if err := json.Unmarshal(lines.Bytes(), &f); err != nil {
			t.Fatal(err)
		}
		if f.Event == "sql" || f.Event == "result" {
			events = append(events, f.Kind+": "+f.Text)
		}
	}
	all := strings.Join(events, "\n")
	for _, want := range []string{
		"query: SELECT name FROM users WHERE token = '[masked:github-token]'",
		"bind: [masked:session-credential] | 42",
		"columns: name", "row: row-a", "row: row-j", "truncated: further rows are not recorded",
		"complete: SELECT 15", "error: 42501 permission denied",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("recording lacks %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "row-k") || strings.Contains(all, "Pa55word") || strings.Contains(all, "aaaaaaaa") {
		t.Fatalf("recording kept more than it should:\n%s", all)
	}
}
