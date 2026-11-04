// SPDX-License-Identifier: BUSL-1.1

package redissignin

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseURLReadsTheProviderCredential(t *testing.T) {
	target, err := ParseURL([]byte("rediss://trstctl_lease_7:p%40ss%3Aw%2Frd@cache.internal:6380/3"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	if target.User != "trstctl_lease_7" || string(target.Password) != "p@ss:w/rd" || target.Address != "cache.internal:6380" ||
		target.Host != "cache.internal" || target.DB != 3 || !target.TLS {
		t.Fatalf("target = %+v", target)
	}
	plain, err := ParseURL([]byte("redis://u:p@127.0.0.1:6379"))
	if err != nil || plain.TLS || plain.DB != 0 {
		t.Fatalf("plain = %+v %v", plain, err)
	}
	for _, bad := range []string{"https://u:p@h:1/0", "redis://h:6379/0", "redis://:p@h:1/0", "redis://u:@h:1/0", "redis://u:%zz@h:1/0",
		"redis://u:p@h/0", "redis://u:p@h:0/0", "redis://u:p@h:1/x", "redis://u:p@h:1/-1", "redis://u:p%4@h:1"} {
		if _, err := ParseURL([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// fakeRedis answers one connection's sign-in: AUTH with the expected user and
// password, then SELECT when asked; it reports what it was sent.
func fakeRedis(t *testing.T, user, password string, refuse bool) (string, chan []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	seen := make(chan []string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		for {
			args, err := readCommand(r)
			if err != nil || len(args) == 0 {
				close(seen)
				return
			}
			seen <- args
			switch {
			case strings.EqualFold(args[0], "AUTH") && !refuse && len(args) == 3 && args[1] == user && args[2] == password:
				_, _ = io.WriteString(conn, "+OK\r\n")
			case strings.EqualFold(args[0], "AUTH"):
				_, _ = io.WriteString(conn, "-WRONGPASS invalid username-password pair or user is disabled.\r\n")
			case strings.EqualFold(args[0], "SELECT"):
				_, _ = io.WriteString(conn, "+OK\r\n")
			default:
				_, _ = io.WriteString(conn, "$4\r\npong\r\n")
			}
		}
	}()
	return ln.Addr().String(), seen
}

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
	args := make([]string, 0, n)
	for range n {
		head, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, _ := strconv.Atoi(strings.TrimSpace(head[1:]))
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

func TestSignInAuthenticatesSelectsAndHandsOverAtTheNextReply(t *testing.T) {
	addr, seen := fakeRedis(t, "trstctl_lease_7", "p@ss:w/rd", false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := SignIn(ctx, []byte("redis://trstctl_lease_7:p%40ss%3Aw%2Frd@"+addr+"/2"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if got := <-seen; strings.Join(got, " ") != "AUTH trstctl_lease_7 p@ss:w/rd" {
		t.Fatalf("first command = %q", got)
	}
	if got := <-seen; strings.Join(got, " ") != "SELECT 2" {
		t.Fatalf("second command = %q", got)
	}
	// The connection is the client's from here: the next reply is whole.
	if _, err := conn.Write(command([]byte("PING"))); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("$4\r\npong\r\n"))
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "$4\r\npong\r\n" {
		t.Fatalf("reply = %q %v", reply, err)
	}
}

func TestSignInRefusedClosesWithoutTheServersCredentialEcho(t *testing.T) {
	addr, _ := fakeRedis(t, "u", "right", true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := SignIn(ctx, []byte("redis://u:wrong@"+addr+"/0"), Options{})
	if err == nil || !strings.Contains(err.Error(), "refused AUTH") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("err = %v", err)
	}
}

func TestSignInVerifiesTLS(t *testing.T) {
	// A plaintext server cannot complete a verified TLS handshake.
	addr, _ := fakeRedis(t, "u", "p", false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := SignIn(ctx, []byte("rediss://u:p@"+addr+"/0"), Options{}); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("err = %v", err)
	}
}
