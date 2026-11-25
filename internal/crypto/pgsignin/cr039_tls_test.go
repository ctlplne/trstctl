// SPDX-License-Identifier: BUSL-1.1

package pgsignin

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// A server that declines TLS must never receive PostgreSQL's startup packet:
// the next authentication challenge can ask for the session's raw password.
func TestCR039PostgresRefusesTLSlessServerBeforeStartup(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	startupSeen := make(chan bool, 1)
	go func() {
		defer close(startupSeen)
		request := make([]byte, 8)
		if _, err := io.ReadFull(server, request); err != nil || binary.BigEndian.Uint32(request[4:]) != sslRequestCode {
			startupSeen <- true
			return
		}
		if _, err := server.Write([]byte{'N'}); err != nil {
			startupSeen <- true
			return
		}
		_ = server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		var next [8]byte
		n, _ := server.Read(next[:])
		startupSeen <- n != 0
	}()
	_, err := SignIn(ctx, []byte("host=db.private.test port=5432 user=fixture password=fixture-secret dbname=orders"),
		Options{Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }})
	if <-startupSeen || err == nil || !strings.Contains(strings.ToLower(err.Error()), "tls") {
		t.Fatalf("TLSless database reached startup: err=%v", err)
	}
}
