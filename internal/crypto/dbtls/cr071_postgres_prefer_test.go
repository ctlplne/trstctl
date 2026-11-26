// SPDX-License-Identifier: BUSL-1.1

package dbtls

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// A refusal on one socket must not authorize plaintext on another socket.
// The second peer offers TLS, as an impostor could after a first connection
// was refused by a different backend or a concurrent attempt.
func TestCR071PostgresPreferRequiresRefusalOnFallbackConnection(t *testing.T) {
	firstClient, firstServer := net.Pipe()
	secondClient, secondServer := net.Pipe()
	t.Cleanup(func() {
		_ = firstClient.Close()
		_ = firstServer.Close()
		_ = secondClient.Close()
		_ = secondServer.Close()
	})
	for _, conn := range []net.Conn{firstClient, firstServer, secondClient, secondServer} {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	}
	clients := []net.Conn{firstClient, secondClient}
	dial := PostgresPreferDial(func(context.Context, string, string) (net.Conn, error) {
		conn := clients[0]
		clients = clients[1:]
		return conn, nil
	})
	first, err := dial(t.Context(), "tcp", "127.0.0.1:5432")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		request := make([]byte, 8)
		_, _ = io.ReadFull(firstServer, request)
		_, _ = firstServer.Write([]byte{'N'})
	}()
	if _, err := first.Write(postgresSSLRequest); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 1)
	if _, err := io.ReadFull(first, response); err != nil || response[0] != 'N' {
		t.Fatalf("first server did not refuse TLS: %q, %v", response, err)
	}
	second, err := dial(t.Context(), "tcp", "127.0.0.1:5432")
	if err != nil {
		t.Fatal(err)
	}
	firstBytes := make(chan []byte, 1)
	go func() {
		request := make([]byte, 8)
		_, _ = io.ReadFull(secondServer, request)
		firstBytes <- request
		_, _ = secondServer.Write([]byte{'S'})
	}()
	// A PostgreSQL StartupMessage begins with its length, then protocol 3.0.
	startup := []byte{0, 0, 0, 8, 0, 3, 0, 0}
	if _, err := second.Write(startup); err == nil {
		t.Fatal("plaintext startup was accepted by a TLS-capable fallback peer")
	}
	if got := <-firstBytes; !bytes.Equal(got, postgresSSLRequest) {
		t.Fatalf("fallback sent startup before probing TLS: %x", got)
	}
}

func TestCR071PostgresPreferAllowsSameConnectionExplicitRefusal(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	dial := PostgresPreferDial(func(context.Context, string, string) (net.Conn, error) { return client, nil })
	conn, err := dial(t.Context(), "tcp", "127.0.0.1:5432")
	if err != nil {
		t.Fatal(err)
	}
	firstBytes := make(chan []byte, 1)
	go func() {
		probe := make([]byte, 8)
		_, _ = io.ReadFull(server, probe)
		_, _ = server.Write([]byte{'N'})
		startup := make([]byte, 8)
		_, _ = io.ReadFull(server, startup)
		firstBytes <- append(probe, startup...)
	}()
	startup := []byte{0, 0, 0, 8, 0, 3, 0, 0}
	if n, err := conn.Write(startup); err != nil || n != len(startup) {
		t.Fatalf("explicit TLS refusal must allow plaintext fallback: n=%d err=%v", n, err)
	}
	got := <-firstBytes
	if !bytes.Equal(got[:8], postgresSSLRequest) || !bytes.Equal(got[8:], startup) {
		t.Fatalf("fallback exchange = %x, want SSLRequest then startup", got)
	}
}
