// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestRedisRuleFramesBoundAndPreserveBytes(t *testing.T) {
	raw := []byte("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$16\r\nDEL value canary\r\n")
	reserved, released := 0, 0
	reserve := func(n int) (func(), bool) { reserved += n; return func() { released += n }, true }
	f, err := readRedisRuleFrame(bufio.NewReader(bytes.NewReader(raw)), reserve)
	if err != nil || !bytes.Equal(f.raw, raw) || len(f.args) != 3 || string(f.args[2]) != "DEL value canary" {
		t.Fatalf("valid frame changed: %v %q", err, f.raw)
	}
	retained := f.raw[:cap(f.raw)]
	f.done()
	if reserved != redisRuleFrameBytes || released != reserved || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("frame reservation or wipe lost")
	}
	for _, bad := range []string{"SET key value\r\n", "*0\r\n", "*1025\r\n", "*01\r\n", "*2\r\n$3\r\nDEL\r\n$1048576\r\n", "*1\r\n$3\r\nDE", "*1\r\n$3\r\nDELXX"} {
		before := reserved - released
		f, err := readRedisRuleFrame(bufio.NewReader(bytes.NewReader([]byte(bad))), reserve)
		if err == nil {
			f.done()
			t.Fatal("uninspectable Redis frame accepted")
		}
		if reserved-released != before {
			t.Fatal("failed frame leaked byte reservation")
		}
	}
	if _, err := readRedisRuleFrame(bufio.NewReader(bytes.NewReader(raw)), func(int) (func(), bool) { return nil, false }); !errors.Is(err, errCommandBusy) {
		t.Fatal("full capacity did not reject before allocation")
	}
}

func TestRedisAuthenticationNeverEntersCommandPolicy(t *testing.T) {
	for _, args := range [][][]byte{{[]byte("AUTH"), []byte("user"), []byte("a262-auth-canary")}, {[]byte("HELLO"), []byte("3"), []byte("AUTH"), []byte("user"), []byte("a262-auth-canary")}, {[]byte("RESET")}} {
		var target bytes.Buffer
		err := forwardRedisRuleCommand(context.Background(), &target, &commandConnection{}, redisRuleFrame{args: args, raw: []byte("a262-auth-canary")}, func(redisCommand) {})
		if err != nil || !bytes.Contains(target.Bytes(), []byte("LOGIN_CHANGE")) || bytes.Contains(target.Bytes(), []byte("a262-auth-canary")) {
			t.Fatal("authentication entered policy or upstream forwarding")
		}
	}
}

func FuzzRedisRuleFrame(f *testing.F) {
	for _, raw := range []string{"*2\r\n$3\r\nDEL\r\n$3\r\nkey\r\n", "*3\r\n$4\r\nAUTH\r\n$1\r\nu\r\n$1\r\np\r\n", "*1025\r\n", "*1\r\n$1048577\r\n", "*+1\r\n"} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		reserved := 0
		frame, err := readRedisRuleFrame(bufio.NewReader(bytes.NewReader(raw)), func(n int) (func(), bool) { reserved += n; return func() { reserved -= n }, true })
		if !bytes.Equal(before, raw) {
			t.Fatal("parser changed client bytes")
		}
		if err == nil {
			if len(frame.raw) > redisRuleFrameBytes || len(frame.args) > redisRuleMaxArgs || len(frame.args) < 1 || !bytes.Equal(frame.raw, raw[:len(frame.raw)]) {
				t.Fatal("unbounded or changed frame")
			}
			frame.done()
		}
		if reserved != 0 {
			t.Fatal("frame leaked reservation")
		}
	})
}
