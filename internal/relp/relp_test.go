// SPDX-License-Identifier: BUSL-1.1

package relp_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/relp"
	"trstctl.com/trstctl/internal/relp/relptest"
)

// serve runs receiver behind a loopback listener and returns a client
// connection to it.
func serve(t *testing.T, serve func(net.Conn)) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	return conn
}

// rsp is an answer frame for txnr carrying data.
func rsp(txnr int, data string) string {
	return fmt.Sprintf("%d rsp %d %s\n", txnr, len(data), data)
}

func messages(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("<110>1 2026-11-14T12:00:00.000000Z - trstctl - trstctl-audit - {\"sequence\":%d}", i+1))
	}
	return out
}

// P5-L3: every message is a RELP command the receiver answers. Send opens
// the session with relp_version 0 and the syslog command, numbers its
// commands from 1, and returns only once each message is acknowledged, in
// order; the receiver holds exactly what was sent.
func TestSendIsAcknowledgedMessageByMessageP5L3(t *testing.T) {
	receiver := &relptest.Receiver{}
	sent := messages(3)
	acked, err := relp.Send(serve(t, receiver.Serve), "trstctl", sent)
	if err != nil || acked != 3 {
		t.Fatalf("Send = %d, %v; want 3 acknowledged", acked, err)
	}
	got := receiver.Messages()
	if len(got) != 3 {
		t.Fatalf("the receiver holds %d messages, want 3", len(got))
	}
	for i := range sent {
		if !bytes.Equal(got[i], sent[i]) {
			t.Fatalf("message %d = %q, want %q", i+1, got[i], sent[i])
		}
	}
	if v := receiver.Violations(); len(v) != 0 {
		t.Fatalf("the client broke RELP: %v", v)
	}
}

// P5-L3: a message the receiver refuses ends the send there: the messages
// before it are counted acknowledged, the error names the message and the
// status, and the receiver's own text is never repeated.
func TestSendStopsAtARefusedMessageP5L3(t *testing.T) {
	receiver := &relptest.Receiver{Answer: func(_, n int, _ []byte) int {
		if n == 2 {
			return 500
		}
		return 200
	}}
	acked, err := relp.Send(serve(t, receiver.Serve), "trstctl", messages(3))
	if acked != 1 || !errors.Is(err, relp.ErrRefused) || !strings.Contains(err.Error(), "message 2 of 3 (status 500)") {
		t.Fatalf("Send = %d, %v; want message 2 refused after 1 acknowledged", acked, err)
	}
	if strings.Contains(err.Error(), "relptest") {
		t.Fatalf("the error repeats the receiver's text: %v", err)
	}
}

// P5-L3: a receiver that closes the session (with a serverclose hint, or
// without one) leaves its unanswered messages unacknowledged.
func TestSendEndsWhenTheReceiverClosesP5L3(t *testing.T) {
	receiver := &relptest.Receiver{Answer: func(_, n int, _ []byte) int {
		if n == 2 {
			return 0
		}
		return 200
	}}
	acked, err := relp.Send(serve(t, receiver.Serve), "trstctl", messages(3))
	if acked != 1 || !errors.Is(err, relp.ErrClosed) {
		t.Fatalf("Send = %d, %v; want closed after 1 acknowledged", acked, err)
	}
	silent := serve(t, func(conn net.Conn) { _ = conn.Close() })
	if acked, err := relp.Send(silent, "trstctl", messages(1)); acked != 0 || !errors.Is(err, relp.ErrClosed) {
		t.Fatalf("Send to a receiver that hangs up = %d, %v", acked, err)
	}
}

// P5-L3: at most Window commands are outstanding at once.
func TestSendKeepsAtMostAWindowOutstandingP5L3(t *testing.T) {
	receiver := &relptest.Receiver{Hold: 300 * time.Millisecond}
	acked, err := relp.Send(serve(t, receiver.Serve), "trstctl", messages(relp.Window*2+44))
	if err != nil || acked != relp.Window*2+44 {
		t.Fatalf("Send = %d, %v", acked, err)
	}
	if got := receiver.MaxOutstanding(); got != relp.Window {
		t.Fatalf("at most %d commands were outstanding, want the window of %d", got, relp.Window)
	}
	if v := receiver.Violations(); len(v) != 0 {
		t.Fatalf("the client broke RELP: %v", v)
	}
}

// P5-L3: the session opens only on a 200 that offers a relp_version and the
// syslog command, answered to the open itself; anything else ends it before
// a message is sent.
func TestSendOpensOnlyAnAcceptedSessionP5L3(t *testing.T) {
	for name, tc := range map[string]struct {
		reply string
		want  error
	}{
		"refused":           {rsp(1, "500 no"), relp.ErrRefused},
		"no syslog command": {rsp(1, "200 OK\nrelp_version=0"), relp.ErrProtocol},
		"no version":        {rsp(1, "200 OK\ncommands=syslog"), relp.ErrProtocol},
		"another command":   {rsp(2, "200 OK\nrelp_version=0\ncommands=syslog"), relp.ErrProtocol},
		"not an answer":     {"1 syslog 3 abc\n", relp.ErrProtocol},
		"a long number":     {"1 rsp 1234567890 x\n", relp.ErrProtocol},
		"no trailer":        {"1 rsp 6 200 OKx", relp.ErrProtocol},
		"hangs up":          {"", relp.ErrClosed},
		"serverclose":       {"0 serverclose 0\n", relp.ErrClosed},
	} {
		t.Run(name, func(t *testing.T) {
			conn := serve(t, func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte(tc.reply))
			})
			if acked, err := relp.Send(conn, "trstctl", messages(1)); acked != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("Send = %d, %v; want %v", acked, err, tc.want)
			}
		})
	}
	for name, msgs := range map[string][][]byte{
		"an empty message":    {nil},
		"an oversize message": {bytes.Repeat([]byte("a"), relp.MaxMessage+1)},
	} {
		if _, err := relp.Send(nil, "trstctl", msgs); err == nil {
			t.Fatalf("%s was sent", name)
		}
	}
}
