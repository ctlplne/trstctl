// SPDX-License-Identifier: MPL-2.0

package email_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/email"
)

// Exercise the production socket path: a server accepting TCP without sending
// its SMTP greeting must not pin a notification worker past cancellation.
func TestSMTPGreetingHonorsCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- email.New(listener.Addr().String(), "alerts@example.test", []string{"qa@example.test"}).Notify(ctx, notify.Alert{Subject: "stalled greeting"})
	}()
	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("SMTP client never connected")
	}
	defer func() { _ = conn.Close() }()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled SMTP send returned %v", err)
		}
	case <-time.After(time.Second):
		_ = conn.Close() // Release the pre-fix sender; never leak the fault fixture.
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Fatal("SMTP sender stayed blocked after peer closure")
		}
		t.Fatal("SMTP sender ignored cancellation after connecting; a stalled peer pins its worker")
	}
}

func TestSMTPProductionExchangeAndDataDeadline(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(fmt.Sprintf("stall_data_ack=%t", stall), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			bodyReceived := make(chan string, 1)
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				wire := textproto.NewConn(conn)
				_ = wire.PrintfLine("220 local SMTP fixture")
				for _, step := range []struct{ command, reply string }{
					{"EHLO localhost", "250 local"},
					{"MAIL FROM:<alerts@example.test>", "250 sender accepted"},
					{"RCPT TO:<qa@example.test>", "250 recipient accepted"},
					{"DATA", "354 end with dot"},
				} {
					line, err := wire.ReadLine()
					if err != nil || line != step.command {
						serverDone <- fmt.Errorf("SMTP command=%q want=%q err=%v", line, step.command, err)
						return
					}
					_ = wire.PrintfLine("%s", step.reply)
				}
				body, err := io.ReadAll(wire.DotReader())
				if err != nil {
					serverDone <- err
					return
				}
				bodyReceived <- string(body)
				if stall {
					_, err = wire.ReadLine() // The cancelled client must close the socket.
					if err == nil {
						err = errors.New("client proceeded without DATA acceptance")
					} else if errors.Is(err, io.EOF) {
						err = nil
					}
					serverDone <- err
					return
				}
				_ = wire.PrintfLine("250 stored")
				line, err := wire.ReadLine()
				if err == nil && line != "QUIT" {
					err = fmt.Errorf("expected QUIT, got %q", line)
				}
				_ = wire.PrintfLine("221 goodbye")
				serverDone <- err
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			err = email.New(listener.Addr().String(), "alerts@example.test", []string{"qa@example.test"}).Notify(ctx, notify.Alert{Subject: "wire delivery", Detail: "exact marker\n.dot-prefixed line"})
			if stall {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("DATA acknowledgement deadline: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			body := <-bodyReceived
			if !strings.Contains(body, "To: qa@example.test\n") || !strings.Contains(body, "exact marker\n.dot-prefixed line") {
				t.Fatalf("SMTP message lost recipient or dot-stuffed body: %q", body)
			}
		})
	}
}
