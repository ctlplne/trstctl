// SPDX-License-Identifier: BUSL-1.1

package mongosignin

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

type observedMongoConn struct {
	net.Conn
	writes [][]byte
}

func (c *observedMongoConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (*observedMongoConn) Read([]byte) (int, error) { return 0, io.EOF }
func (*observedMongoConn) Close() error             { return nil }

// An omitted tls=true must not let an on-path database endpoint receive the
// SCRAM first message before the gateway authenticates its certificate.
func TestCR039MongoDefaultSignInNeverSendsSCRAMOnPlaintext(t *testing.T) {
	wire := &observedMongoConn{}
	_, err := SignIn(context.Background(), []byte("mongodb://fixture:fixture-secret@db.private.test:27017/orders?authSource=orders"),
		Options{Dial: func(context.Context, string, string) (net.Conn, error) { return wire, nil }})
	if err == nil || bytes.Contains(bytes.Join(wire.writes, nil), []byte("saslStart")) {
		t.Fatalf("default MongoDB sign-in sent SCRAM before verifying TLS: writes=%d err=%v", len(wire.writes), err)
	}
}
