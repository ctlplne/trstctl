// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestRedisConsoleSplitsCommandsAsRedisCliDoesA259L5: a Redis console's
// command line is split into words as redis-cli splits it, and text it
// cannot send is the console's input error, not a broken connection.
func TestRedisConsoleSplitsCommandsAsRedisCliDoesA259L5(t *testing.T) {
	for line, want := range map[string][]string{
		`SET a256:console "hello world"`: {"SET", "a256:console", "hello world"},
		`SET k "a\"b\\c\x41\n"`:          {"SET", "k", "a\"b\\cA\n"},
		`SET k 'it\'s'`:                  {"SET", "k", "it's"},
		"  GET\tk  ":                     {"GET", "k"},
		`SET k ""`:                       {"SET", "k", ""},
	} {
		got, err := splitRedisCommand(line)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("split %q = %q, %v; want %q", line, got, err, want)
		}
	}
	for _, line := range []string{`GET "unclosed`, `GET "a"b`, "   ", `SET 'k`} {
		if _, err := splitRedisCommand(line); !errors.Is(err, errPAMConsoleInput) {
			t.Fatalf("split %q = %v, want an input error", line, err)
		}
	}
}

// TestRedisConsoleReadsRepliesWholeWithinBoundsA259L5: a reply is read whole,
// so the next one is read in step, and kept to the console's bounds: a long
// string to its cell size, a long array to its rows; nesting too deep and
// RESP3 types end the connection.
func TestRedisConsoleReadsRepliesWholeWithinBoundsA259L5(t *testing.T) {
	long := strings.Repeat("x", pamConsoleMaxCell+904)
	var many strings.Builder
	many.WriteString("*1500\r\n")
	for i := 0; i < 1500; i++ {
		many.WriteString(":7\r\n")
	}
	stream := "*3\r\n$5\r\nhello\r\n$-1\r\n*2\r\n:1\r\n+OK\r\n" +
		"$" + strconv.Itoa(len(long)) + "\r\n" + long + "\r\n" +
		many.String() +
		"-NOPERM this user has no permissions\r\n" +
		"+after\r\n"
	r := bufio.NewReader(strings.NewReader(stream))
	nested, err := readRESP(r, 0)
	if err != nil || len(nested.elems) != 3 || *nested.elems[0].inline() != "hello" || nested.elems[1].inline() != nil ||
		*nested.elems[2].inline() != `["1", "OK"]` {
		t.Fatalf("nested reply = %+v, %v", nested, err)
	}
	bulk, err := readRESP(r, 0)
	if err != nil || !bulk.truncated || len(bulk.text) != pamConsoleMaxCell+len("…") {
		t.Fatalf("long bulk = %d bytes truncated=%v, %v", len(bulk.text), bulk.truncated, err)
	}
	array, err := readRESP(r, 0)
	if err != nil || !array.truncated || len(array.elems) != pamConsoleMaxRows {
		t.Fatalf("long array = %d elements truncated=%v, %v", len(array.elems), array.truncated, err)
	}
	refusal, err := readRESP(r, 0)
	if err != nil || refusal.kind != '-' || refusal.text != "NOPERM this user has no permissions" {
		t.Fatalf("refusal = %+v, %v", refusal, err)
	}
	if after, err := readRESP(r, 0); err != nil || after.text != "after" {
		t.Fatalf("the reply after = %+v, %v", after, err)
	}
	deep := strings.Repeat("*1\r\n", pamRedisMaxDepth+2) + ":1\r\n"
	if _, err := readRESP(bufio.NewReader(strings.NewReader(deep)), 0); err == nil {
		t.Fatal("a reply nested too deeply was read")
	}
	if _, err := readRESP(bufio.NewReader(strings.NewReader("%1\r\n+a\r\n+b\r\n")), 0); err == nil {
		t.Fatal("a RESP3 map was read")
	}
}
