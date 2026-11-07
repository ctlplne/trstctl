// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestRecordingSearchReadsWhatAnOperatorSawA275: a search reads SSH exec
// commands, terminal output joined across frames with escape sequences
// removed, SQL statements and results and desktop index entries; never the
// typed-input stream or policy markers; and returns snippets masked.
func TestRecordingSearchReadsWhatAnOperatorSawA275(t *testing.T) {
	out := func(conn, ch int, at int64, text string) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"t": at, "c": conn, "ch": ch, "s": "out", "d": base64.StdEncoding.EncodeToString([]byte(text))})
		return raw
	}
	in := func(text string) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"t": 5, "c": 1, "ch": 0, "s": "in", "d": base64.StdEncoding.EncodeToString([]byte(text))})
		return raw
	}
	event := func(e, kind, v string) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"t": 9, "c": 2, "e": e, "kind": kind, "v": v})
		return raw
	}
	page1 := []json.RawMessage{
		event("request", "exec", "systemctl status nginx"),
		in("sudo-password-typed-at-a-prompt\r"),
		out(1, 0, 10, "\x1b[1;32mroot@lab\x1b[0m:~# echo needle-a"),
		event("policy", "alerted", "11111111-1111-4111-8111-111111111111"),
	}
	page2 := []json.RawMessage{
		out(1, 0, 20, "bc ok\r\n\x1b]0;title\x07typo\x08\x08\x08\x08needle-out\n"),
		event("sql", "query", "SELECT 'needle-sql'"),
		event("result", "row", "needle-row"),
		event("index", "window", "needle-window"),
		event("redis", "command", "GET needle-redis"),
	}
	partial := map[string]*recordingPartialLine{}
	var lines []recordingSearchLine
	collect := func(l recordingSearchLine) bool { lines = append(lines, l); return true }
	if !recordingSearchLines(page1, partial, collect) || !recordingSearchLines(page2, partial, collect) || !flushRecordingLines(partial, collect) {
		t.Fatal("stopped early")
	}
	got := map[string]string{}
	for _, l := range lines {
		got[l.source+"|"+l.text] = l.kind
		if strings.Contains(l.text, "sudo-password") || strings.Contains(l.text, "1111") {
			t.Fatalf("the input stream or a policy marker was read: %+v", l)
		}
	}
	for _, want := range []string{"command|systemctl status nginx", "output|root@lab:~# echo needle-abc ok", "output|needle-out",
		"sql|SELECT 'needle-sql'", "result|needle-row", "index|needle-window", "request|GET needle-redis"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("missing %q in %v", want, got)
		}
	}
	if got["request|GET needle-redis"] != "redis command" {
		t.Fatalf("a protocol request's kind: %v", got)
	}
	long := strings.Repeat("x", 400) + "needle" + strings.Repeat("y", 400) + " AKIAABCDEFGHIJKLMNOP"
	if s := recordingSnippet(long, 400, 6); len([]rune(s)) != recordingSearchSnippet || !strings.Contains(s, "needle") {
		t.Fatalf("a long line's snippet: %q", s)
	}
	if s := recordingSnippet("key AKIAABCDEFGHIJKLMNOP here", 0, 3); strings.Contains(s, "AKIAABCDEFGHIJKLMNOP") || !strings.Contains(s, "[masked:aws-access-key-id]") {
		t.Fatalf("a snippet is masked: %q", s)
	}
}
