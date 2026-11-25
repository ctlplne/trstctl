package trust

import (
	"crypto/tls"
	"net"
)

func client(conn net.Conn) { _ = tls.Client(conn, &tls.Config{}) }
