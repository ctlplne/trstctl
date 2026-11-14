// SPDX-License-Identifier: BUSL-1.1

package email

import (
	"context"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// utf8Relay is a loopback relay that offers SMTPUTF8 or not and records the
// commands it reads.
type utf8Relay struct {
	addr  string
	mu    sync.Mutex
	lines []string
}

func startUTF8Relay(t *testing.T, offersSMTPUTF8 bool) *utf8Relay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	r := &utf8Relay{addr: listener.Addr().String()}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		wire := textproto.NewConn(conn)
		_ = wire.PrintfLine("220 loopback relay")
		for {
			line, err := wire.ReadLine()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.lines = append(r.lines, line)
			r.mu.Unlock()
			switch verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0]); verb {
			case "EHLO":
				if offersSMTPUTF8 {
					_ = wire.PrintfLine("250-loopback\r\n250 SMTPUTF8")
				} else {
					_ = wire.PrintfLine("250 loopback")
				}
			case "DATA":
				_ = wire.PrintfLine("354 go")
				if _, err := wire.ReadDotBytes(); err != nil {
					return
				}
				_ = wire.PrintfLine("250 stored")
			case "QUIT":
				_ = wire.PrintfLine("221 bye")
				return
			default:
				_ = wire.PrintfLine("250 ok")
			}
		}
	}()
	return r
}

func (r *utf8Relay) seen() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

// P15-L4 part 2: a mail to a mailbox with a non-ASCII local part goes only to
// a relay that offers SMTPUTF8, with the SMTPUTF8 parameter (RFC 6531); a
// relay that does not offer it is never handed the address.
func TestRelayTakesAnInternationalAddressOnlyWithSMTPUTF8P15L4(t *testing.T) {
	msg := []byte("From: acme@ca.p15l4.test\r\nTo: ålice@p15l4.test\r\nSubject: ACME: t\r\n\r\nbody\r\n")
	plain := startUTF8Relay(t, false)
	err := NewRelaySender(plain.addr, "", nil).Send(context.Background(), "acme@ca.p15l4.test", []string{"ålice@p15l4.test"}, msg)
	if err == nil || !strings.Contains(err.Error(), "SMTPUTF8") {
		t.Fatalf("a relay without SMTPUTF8 = %v", err)
	}
	if strings.Contains(plain.seen(), "MAIL FROM") || strings.Contains(plain.seen(), "ålice") {
		t.Fatalf("the address reached a relay without SMTPUTF8:\n%s", plain.seen())
	}
	utf8 := startUTF8Relay(t, true)
	if err := NewRelaySender(utf8.addr, "", nil).Send(context.Background(), "acme@ca.p15l4.test", []string{"ålice@p15l4.test"}, msg); err != nil {
		t.Fatal(err)
	}
	if seen := utf8.seen(); !strings.Contains(seen, "MAIL FROM:<acme@ca.p15l4.test> SMTPUTF8") || !strings.Contains(seen, "RCPT TO:<ålice@p15l4.test>") {
		t.Fatalf("the SMTPUTF8 relay read:\n%s", seen)
	}
}
