// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func resp(args ...string) string {
	return string(append(respArrayHeader(len(args)), func() []byte {
		var b []byte
		for _, a := range args {
			b = append(b, respBulk([]byte(a))...)
		}
		return b
	}()...))
}

func relayCommands(t *testing.T, in string) (string, []redisCommand, error) {
	t.Helper()
	var out bytes.Buffer
	var seen []redisCommand
	err := relayRedisCommands(&out, bufio.NewReader(strings.NewReader(in)), func(c redisCommand) { seen = append(seen, c) })
	return out.String(), seen, err
}

func TestRedisRelayForwardsCommandsAndRefusesLoginChanges(t *testing.T) {
	in := resp("SET", "a256:k", "v") + resp("auth", "default", "hunter2") + resp("GET", "a256:k") +
		resp("RESET") + resp("HELLO", "3") + resp("hello", "3", "auth", "default", "hunter2") + "*0\r\n" + resp("PING")
	out, seen, err := relayCommands(t, in)
	if err == nil || err.Error() != "EOF" {
		t.Fatalf("relay ended with %v", err)
	}
	want := resp("SET", "a256:k", "v") + resp("TRSTCTL-GATEWAY-REFUSED-AUTH") + resp("GET", "a256:k") +
		resp("TRSTCTL-GATEWAY-REFUSED-RESET") + resp("HELLO", "3") + resp("TRSTCTL-GATEWAY-REFUSED-HELLO") + resp("PING")
	if out != want {
		t.Fatalf("forwarded %q\nwant %q", out, want)
	}
	var texts []string
	for _, c := range seen {
		if c.refused != "" {
			texts = append(texts, "refused "+c.refused)
		} else {
			texts = append(texts, c.text.String())
		}
	}
	if got := strings.Join(texts, " | "); got != "SET a256:k v | refused AUTH | GET a256:k | refused RESET | HELLO 3 | refused HELLO | PING" {
		t.Fatalf("recorded %q", got)
	}
	if strings.Contains(strings.Join(texts, " "), "hunter2") {
		t.Fatal("a refused command's arguments were recorded")
	}
}

func TestRedisRelayStreamsLargeCommandsAndRecordsBinaryBySize(t *testing.T) {
	big := strings.Repeat("x", 3<<20)
	binary := "\x00\x01\x02"
	in := resp("SET", "a256:big", big) + resp("SET", "a256:bin", binary)
	out, seen, _ := relayCommands(t, in)
	if out != in {
		t.Fatalf("a large or binary command was not forwarded byte for byte (%d of %d bytes)", len(out), len(in))
	}
	if len(seen) != 2 || !strings.Contains(seen[0].text.String(), "...<3145728 bytes>") || seen[1].text.String() != "SET a256:bin <3 bytes>" {
		t.Fatalf("recorded %q / %q", seen[0].text.String(), seen[1].text.String())
	}
	if len(seen[0].text.String()) > redisRecordTextBytes+32 {
		t.Fatalf("recorded %d bytes of one command", len(seen[0].text.String()))
	}
}

func TestRedisRelayRefusesInlineCommands(t *testing.T) {
	out, _, err := relayCommands(t, "AUTH default hunter2\r\n")
	if !errors.Is(err, errRedisInline) || out != "" {
		t.Fatalf("inline command: forwarded %q, err %v", out, err)
	}
	// A long or binary name is no refused name; it is forwarded.
	long := strings.Repeat("A", 100)
	if out, _, _ := relayCommands(t, resp(long, "x")); out != resp(long, "x") {
		t.Fatalf("forwarded %q", out)
	}
}

func TestRedisReplyRelayCopiesRESP2AndRESP3(t *testing.T) {
	replies := []string{
		"+OK\r\n",
		"-NOPERM this user has no permissions to access one of the keys used as arguments\r\n",
		":42\r\n",
		"$5\r\nhello\r\n",
		"$-1\r\n",
		"*2\r\n$1\r\na\r\n*1\r\n:1\r\n",
		"_\r\n",
		",3.14\r\n",
		"#t\r\n",
		"%1\r\n+key\r\n$3\r\nval\r\n",
		"|1\r\n+ttl\r\n:10\r\n$3\r\nval\r\n",
		">3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$2\r\nhi\r\n",
		"!5\r\nERR x\r\n",
	}
	var out bytes.Buffer
	var kinds, texts []string
	err := relayRedisReplies(&out, bufio.NewReader(strings.NewReader(strings.Join(replies, ""))), func(kind, text string) {
		kinds = append(kinds, kind)
		texts = append(texts, text)
	})
	if err == nil || err.Error() != "EOF" {
		t.Fatalf("relay ended with %v", err)
	}
	if out.String() != strings.Join(replies, "") {
		t.Fatalf("replies were not copied byte for byte: %q", out.String())
	}
	wantKinds := "status error integer bulk bulk array null double boolean map bulk push error"
	if strings.Join(kinds, " ") != wantKinds {
		t.Fatalf("kinds %q, want %q", strings.Join(kinds, " "), wantKinds)
	}
	if texts[3] != "hello" || texts[4] != "(nil)" || texts[5] != "[a [1]]" || texts[9] != "[key val]" || texts[10] != "[ttl 10] val" || texts[11] != "[message ch hi]" {
		t.Fatalf("texts %q", texts)
	}
	if _, err := copyRESPValue(bufio.NewWriter(&bytes.Buffer{}), bufio.NewReader(strings.NewReader(strings.Repeat("*1\r\n", 40)+":1\r\n")), 0, &boundedText{}); err == nil {
		t.Fatal("a reply nested past the bound was relayed")
	}
}

// FuzzRedisCommandRelay: no client bytes panic the relay, and nothing it
// forwards is a command that would change the connection's login — relaying
// its output again refuses nothing.
func FuzzRedisCommandRelay(f *testing.F) {
	for _, seed := range []string{resp("GET", "k"), resp("AUTH", "u", "p"), resp("HELLO", "3", "AUTH", "u", "p"), resp("RESET"),
		"*1\r\n$4\r\nAU", "*2\r\n$-1\r\n", "PING\r\n", resp("hello", "3", "setname", "x")} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var out bytes.Buffer
		_ = relayRedisCommands(&out, bufio.NewReader(bytes.NewReader(in)), func(redisCommand) {})
		_ = relayRedisCommands(&bytes.Buffer{}, bufio.NewReader(bytes.NewReader(out.Bytes())), func(c redisCommand) {
			if c.refused != "" {
				t.Fatalf("the relay forwarded a %s from %q", c.refused, in)
			}
		})
	})
}

// FuzzRedisReplyRelay: no server bytes panic the reply relay, and what it
// forwards is exactly what it read.
func FuzzRedisReplyRelay(f *testing.F) {
	for _, seed := range []string{"+OK\r\n", "$5\r\nhello\r\n", "*2\r\n:1\r\n$-1\r\n", "|1\r\n+a\r\n:1\r\n+OK\r\n", "%1\r\n+k\r\n+v\r\n", "$3\r\nab"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var out bytes.Buffer
		_ = relayRedisReplies(&out, bufio.NewReader(bytes.NewReader(in)), func(string, string) {})
		if !bytes.HasPrefix(in, out.Bytes()) {
			t.Fatalf("relayed %q from %q", out.Bytes(), in)
		}
	})
}
