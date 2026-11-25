// SPDX-License-Identifier: BUSL-1.1

package redissignin

import (
	"context"
	"io"
	"net"
	"testing"
)

type observedRedisConn struct {
	net.Conn
	writes [][]byte
}

func (c *observedRedisConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (*observedRedisConn) Read([]byte) (int, error) { return 0, io.EOF }
func (*observedRedisConn) Close() error             { return nil }

// A stale plaintext job must be refused before dialing, even if its provider
// used the old explicit private-IP plaintext option.
func TestCR039RedisPlaintextJobNeverDialsOrSendsAUTH(t *testing.T) {
	wire := &observedRedisConn{}
	dials := 0
	_, err := SignIn(context.Background(), []byte("redis://fixture:fixture-secret@127.0.0.1:6379/0"),
		Options{Dial: func(context.Context, string, string) (net.Conn, error) { dials++; return wire, nil }})
	if err == nil || dials != 0 || len(wire.writes) != 0 {
		t.Fatalf("plaintext Redis job reached upstream: dials=%d writes=%d err=%v", dials, len(wire.writes), err)
	}
}
