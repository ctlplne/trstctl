// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// P15-L8: the served reply intake holds each source to its sessions and its
// replies. With the default of four sessions a source, a fifth session from
// one address while four are open is turned away 421 4.7.0 at connect, and
// one of the four ending makes room again; with intake_replies_per_minute 2,
// the source's third reply within the minute is told 451 4.7.1 at DATA,
// before its message is read.
func TestServedReplyIntakeHoldsEachSourceToItsSessionsAndRepliesP15L8(t *testing.T) {
	relay := startP15SMTPRelay(t)
	h := newOperatingServedHarness(t, config.Protocols{
		ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		ACMEEmail: config.ACMEEmail{From: "acme@ca.p15l8.test", Domains: []string{"p15l8.test"},
			Profile: "smime-signing", RelayAddr: relay.addr, SMTPListen: "127.0.0.1:0", IntakeRepliesPerMinute: 2},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go h.srv.serveACMEEmailIntake(ctx, ln, nil)
	addr := ln.Addr().String()
	greet := func() (net.Conn, string) {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("the intake's greeting: %v", err)
		}
		return conn, strings.TrimSpace(line)
	}
	const defaultSessionsPerSource = 4
	held := make([]net.Conn, 0, defaultSessionsPerSource)
	for range defaultSessionsPerSource {
		conn, line := greet()
		if !strings.HasPrefix(line, "220 ") {
			t.Fatalf("a session within the source's four = %q", line)
		}
		held = append(held, conn)
	}
	t.Cleanup(func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	conn, line := greet()
	_ = conn.Close()
	if !strings.HasPrefix(line, "421 4.7.0 ") {
		t.Fatalf("a fifth session from the same address = %q", line)
	}
	if _, err := held[0].Write([]byte("QUIT\r\n")); err != nil {
		t.Fatal(err)
	}
	var c *smtp.Client
	for deadline := time.Now().Add(10 * time.Second); c == nil; {
		if c, err = smtp.Dial(addr); err != nil {
			if !strings.Contains(err.Error(), "4.7.0") || time.Now().After(deadline) {
				t.Fatalf("a session once one of the four ended: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello("mta.p15l8.test"); err != nil {
		t.Fatal(err)
	}
	reply := "From: alice@p15l8.test\r\nTo: acme@ca.p15l8.test\r\nSubject: Re: ACME: not-a-token\r\n\r\nYes.\r\n"
	for i := 1; i <= 3; i++ {
		if err := c.Mail("alice@p15l8.test"); err != nil {
			t.Fatal(err)
		}
		if err := c.Rcpt("acme@ca.p15l8.test"); err != nil {
			t.Fatal(err)
		}
		wc, err := c.Data()
		if i == 3 {
			if err == nil || !strings.HasPrefix(smtpErrorText(err), "451 4.7.1 ") {
				t.Fatalf("the source's third reply within the minute at DATA = %v", err)
			}
			break
		}
		if err != nil {
			t.Fatalf("reply %d of the source's two a minute at DATA: %v", i, err)
		}
		if _, err := wc.Write([]byte(reply)); err != nil {
			t.Fatal(err)
		}
		// The reply is read and judged (this one is not an RFC 8823 reply).
		if err := wc.Close(); err == nil || !strings.HasPrefix(smtpErrorText(err), "550 5.") {
			t.Fatalf("reply %d = %v, want it read and refused on its merits", i, err)
		}
	}
	t.Logf("P15L8_INTAKE_LIMITS_OK fifth=421-4.7.0 third_reply=451-4.7.1")
}

// smtpErrorText is an SMTP client error as the server sent it (net/smtp
// quotes the text after the code).
func smtpErrorText(err error) string {
	return strings.ReplaceAll(err.Error(), `"`, "")
}
