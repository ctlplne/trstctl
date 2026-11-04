// SPDX-License-Identifier: BUSL-1.1

// Package redissignin signs the access gateway in to a Redis target as one
// session's ACL user (A256). It reads the session's credential URL
// (redis://user:password@host:port/db, or rediss:// for TLS), connects, sends
// AUTH and, for a database other than 0, SELECT, and returns the connection
// for the gateway to relay a stock client's commands over. It is a sign-in,
// not a client library: it sends nothing else, and the agent binary links no
// Redis driver. TLS is verified: the server's certificate must chain to the
// system roots and name the URL's host.
package redissignin

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// maxReplyLine bounds a sign-in reply the gateway reads.
const maxReplyLine = 512

// Target is a parsed session credential. Password is byte-backed; Wipe
// clears it.
type Target struct {
	// Address is host:port; Host is its host, the name TLS verifies.
	Address, Host, User string
	Password            []byte
	DB                  int
	TLS                 bool
}

// Wipe clears the password.
func (t *Target) Wipe() { secret.Wipe(t.Password) }

// Options shape one sign-in.
type Options struct {
	// Dial reaches the target; nil uses a plain dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// ParseURL reads a session credential: redis:// or rediss://, a user and a
// password (percent-encoded), host:port and an optional database number.
func ParseURL(credential []byte) (*Target, error) {
	t := &Target{}
	rest, ok := bytes.CutPrefix(credential, []byte("rediss://"))
	if ok {
		t.TLS = true
	} else if rest, ok = bytes.CutPrefix(credential, []byte("redis://")); !ok {
		return nil, errors.New("redissignin: the credential is not a redis:// or rediss:// URL")
	}
	at := bytes.LastIndexByte(rest, '@')
	if at <= 0 {
		return nil, errors.New("redissignin: the credential names no user")
	}
	userinfo, hostpart := rest[:at], rest[at+1:]
	colon := bytes.IndexByte(userinfo, ':')
	if colon <= 0 {
		return nil, errors.New("redissignin: the credential has no user and password")
	}
	user, ok := percentDecode(userinfo[:colon])
	if !ok || len(user) == 0 {
		return nil, errors.New("redissignin: the credential's user is not percent-encoded")
	}
	t.User = string(user)
	password, ok := percentDecode(userinfo[colon+1:])
	if !ok || len(password) == 0 {
		secret.Wipe(password)
		return nil, errors.New("redissignin: the credential's password is not percent-encoded")
	}
	t.Password = password
	address, db, _ := strings.Cut(string(hostpart), "/")
	host, port, err := net.SplitHostPort(address)
	if n, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
		t.Wipe()
		return nil, errors.New("redissignin: the credential's address is not host:port")
	}
	t.Address, t.Host = address, host
	if db != "" {
		n, err := strconv.Atoi(db)
		if err != nil || n < 0 || n > 1<<16 {
			t.Wipe()
			return nil, errors.New("redissignin: the credential's database is not a number")
		}
		t.DB = n
	}
	return t, nil
}

// SignIn connects as the credential's user and returns the connection, ready
// for commands. A refused sign-in closes it.
func SignIn(ctx context.Context, credential []byte, opts Options) (net.Conn, error) {
	target, err := ParseURL(credential)
	if err != nil {
		return nil, err
	}
	defer target.Wipe()
	dial := opts.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", target.Address)
	if err != nil {
		return nil, fmt.Errorf("redissignin: dial: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if target.TLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: target.Host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("redissignin: the server's TLS certificate does not verify: %w", err)
		}
		conn = tlsConn
	}
	if err := signIn(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func signIn(conn net.Conn, target *Target) error {
	auth := command([]byte("AUTH"), []byte(target.User), target.Password)
	_, err := conn.Write(auth)
	secret.Wipe(auth)
	if err != nil {
		return err
	}
	if err := expectOK(conn, "AUTH"); err != nil {
		return err
	}
	if target.DB == 0 {
		return nil
	}
	if _, err := conn.Write(command([]byte("SELECT"), []byte(strconv.Itoa(target.DB)))); err != nil {
		return err
	}
	return expectOK(conn, "SELECT")
}

// command encodes one RESP command: an array of bulk strings, in one
// allocation of its exact size so no copy of a password is left behind.
func command(args ...[]byte) []byte {
	size := 1 + len(strconv.Itoa(len(args))) + 2
	for _, a := range args {
		size += 1 + len(strconv.Itoa(len(a))) + 2 + len(a) + 2
	}
	out := make([]byte, 0, size)
	out = append(out, '*')
	out = strconv.AppendInt(out, int64(len(args)), 10)
	out = append(out, "\r\n"...)
	for _, a := range args {
		out = append(out, '$')
		out = strconv.AppendInt(out, int64(len(a)), 10)
		out = append(out, "\r\n"...)
		out = append(out, a...)
		out = append(out, "\r\n"...)
	}
	return out
}

// expectOK reads one simple reply byte by byte, so nothing after it is
// consumed: the connection is handed on exactly at the next reply.
func expectOK(conn net.Conn, what string) error {
	line := make([]byte, 0, 64)
	b := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, b); err != nil {
			return fmt.Errorf("redissignin: %s: %w", what, err)
		}
		if b[0] == '\n' && len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
			break
		}
		if len(line) >= maxReplyLine {
			return fmt.Errorf("redissignin: %s: the reply is too long", what)
		}
		line = append(line, b[0])
	}
	switch {
	case string(line) == "+OK":
		return nil
	case len(line) > 0 && line[0] == '-':
		return fmt.Errorf("redissignin: the server refused %s: %s", what, printable(line[1:]))
	default:
		return fmt.Errorf("redissignin: the server answered %s with something else", what)
	}
}

func printable(b []byte) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, string(b))
}

func percentDecode(value []byte) ([]byte, bool) {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			out = append(out, value[i])
			continue
		}
		if i+2 >= len(value) {
			secret.Wipe(out)
			return nil, false
		}
		hi, ok1 := unhex(value[i+1])
		lo, ok2 := unhex(value[i+2])
		if !ok1 || !ok2 {
			secret.Wipe(out)
			return nil, false
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, true
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
