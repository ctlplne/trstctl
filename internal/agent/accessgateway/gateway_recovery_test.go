// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"net"
	"testing"
	"time"
)

type failingGatewayConn struct {
	net.Conn
	closed bool
}

func (*failingGatewayConn) SetDeadline(time.Time) error { panic("handler failure") }
func (c *failingGatewayConn) Close() error {
	c.closed = true
	return nil
}

func TestGatewayServeContainsHandlerFailure(t *testing.T) {
	conn := &failingGatewayConn{}
	logged := false
	g := &Gateway{cfg: Config{Logf: func(string, ...any) { logged = true }}}
	g.serve(context.Background(), conn)
	if !conn.closed || !logged {
		t.Fatalf("connection containment: closed=%v logged=%v", conn.closed, logged)
	}
}
