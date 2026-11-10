// SPDX-License-Identifier: BUSL-1.1

package email

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"go/parser"
	"go/token"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// P15-L5: the relay sender's PLAIN response — the password — used to go through
// net/smtp's Client.Auth, which base64-encodes it into a command string and its
// writer's buffer, copies nothing could wipe. The exchange now writes the AUTH
// line from a buffer it owns and wipes: a loopback relay receives exactly the
// credentials, and once the send returns the line's buffer is all zeros.
func TestRelaySenderWipesThePlainLineAfterTheSendP15L5(t *testing.T) {
	const username, password = "acme-mail", "relay-secret-p15l5"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan string, 16)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		wire := textproto.NewConn(conn)
		_ = wire.PrintfLine("220 loopback relay")
		expect := func(want string) bool {
			line, err := wire.ReadLine()
			if err != nil || !strings.HasPrefix(line, want) {
				serverErr <- fmt.Errorf("relay read %q (%v), want %q", line, err, want)
				return false
			}
			received <- line
			return true
		}
		if !expect("EHLO localhost") {
			return
		}
		_ = wire.PrintfLine("250-loopback\r\n250 AUTH PLAIN")
		if !expect("AUTH PLAIN ") {
			return
		}
		_ = wire.PrintfLine("235 authenticated")
		for _, step := range []struct{ want, reply string }{
			{"MAIL FROM:<challenge@example.test>", "250 ok"},
			{"RCPT TO:<acme@example.test>", "250 ok"},
			{"DATA", "354 go"},
		} {
			if !expect(step.want) {
				return
			}
			_ = wire.PrintfLine("%s", step.reply)
		}
		if _, err := wire.ReadDotBytes(); err != nil {
			serverErr <- err
			return
		}
		_ = wire.PrintfLine("250 stored")
		if !expect("QUIT") {
			return
		}
		_ = wire.PrintfLine("221 bye")
		serverErr <- nil
	}()

	var sent []byte
	previous := plainLineWritten
	t.Cleanup(func() { plainLineWritten = previous })
	plainLineWritten = func(line []byte) { sent = line }

	secretPassword := []byte(password)
	if err := NewRelaySender(listener.Addr().String(), username, secretPassword).Send(context.Background(),
		"challenge@example.test", []string{"acme@example.test"}, []byte("Subject: challenge\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("send through the loopback relay: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	close(received) // the relay sent its result last, so it sends nothing more
	var auth string
	for line := range received {
		if strings.HasPrefix(line, "AUTH PLAIN ") {
			auth = strings.TrimPrefix(line, "AUTH PLAIN ")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil || string(decoded) != "\x00"+username+"\x00"+password {
		t.Fatalf("the relay received PLAIN %q (%v); want the configured credentials", decoded, err)
	}
	if len(sent) == 0 {
		t.Fatal("the AUTH line was not seen")
	}
	if !bytes.Equal(sent, make([]byte, len(sent))) {
		t.Fatalf("the AUTH line's buffer still holds %d nonzero bytes after the send", len(bytes.Trim(sent, "\x00")))
	}
	if string(secretPassword) != password {
		t.Fatal("the sender changed the caller's password bytes; the caller owns and wipes them")
	}
}

// P15-L5: nothing in the email channel hands a password to net/smtp; the
// exchange it drives is its own (smtp_session.go).
func TestEmailChannelDoesNotUseNetSMTPP15L5(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file) // #nosec G304 -- this package's own source files (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == "net/smtp" {
				t.Fatalf("%s imports net/smtp; its Client.Auth keeps the PLAIN password in copies nothing can wipe", file)
			}
		}
	}
}
