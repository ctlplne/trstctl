package tlsprobe

import (
	"crypto/tls"
	"net"
)

func probe(conn net.Conn) { _ = tls.Client(conn, &tls.Config{}) }
