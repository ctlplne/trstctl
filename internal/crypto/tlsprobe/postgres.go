// SPDX-License-Identifier: MPL-2.0

package tlsprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// postgresSSLRequestCode is the PostgreSQL protocol's SSLRequest code
// (1234 in the high 16 bits, 5679 in the low 16 bits).
const postgresSSLRequestCode = 80877103

// PostgresSSLRequest negotiates TLS with a PostgreSQL listener, which expects
// the 8-byte SSLRequest startup message and answers with a single byte: 'S'
// (proceed with TLS) or 'N' (TLS not offered). A generic ClientHello sent first
// is rejected by the server, so without this negotiation the listener looks like
// a failed probe even though it serves a certificate.
func PostgresSSLRequest(ctx context.Context, conn net.Conn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("postgres sslrequest: set deadline: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	var msg [8]byte
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], postgresSSLRequestCode)
	if _, err := conn.Write(msg[:]); err != nil {
		return fmt.Errorf("postgres sslrequest: write: %w", err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("postgres sslrequest: read reply: %w", err)
	}
	switch reply[0] {
	case 'S':
		return nil
	case 'N':
		return errors.New("postgres sslrequest: server does not offer TLS")
	default:
		return fmt.Errorf("postgres sslrequest: unexpected reply byte %#x", reply[0])
	}
}
