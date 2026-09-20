// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	maxMySQLGreeting      = 4096
	mysqlClientProtocol41 = 1 << 9
	mysqlClientSSL        = 1 << 11
	mysqlSecureConnection = 1 << 15
	mysqlClientPluginAuth = 1 << 19
)

// MySQLSSLRequest reads MySQL's public protocol-10 greeting and requests TLS
// before Probe sends its ClientHello. It sends no username, password, or SQL.
// A missing TLS capability is an error; this never falls back to plaintext.
func MySQLSSLRequest(ctx context.Context, conn net.Conn) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("mysql sslrequest: set deadline: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	request, err := mysqlSSLRequestPacket(conn)
	if err != nil {
		return fmt.Errorf("mysql sslrequest: %w", err)
	}
	n, err := conn.Write(request)
	if err == nil && n != len(request) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("mysql sslrequest: write: %w", err)
	}
	return nil
}

// mysqlSSLRequestPacket bounds both the allocation and the bytes consumed from
// the unauthenticated peer. It reads one greeting, never an authentication packet.
func mysqlSSLRequestPacket(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read greeting header: %w", err)
	}
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if header[3] != 0 || size == 0 || size > maxMySQLGreeting {
		return nil, errors.New("invalid greeting length or sequence")
	}
	greeting := make([]byte, size)
	if _, err := io.ReadFull(r, greeting); err != nil {
		return nil, fmt.Errorf("read greeting: %w", err)
	}
	if greeting[0] == 0xff {
		// Do not reflect server-controlled error text into operator evidence.
		return nil, errors.New("server refused the connection before TLS")
	}
	if greeting[0] != 10 {
		return nil, errors.New("server does not offer a protocol-10 greeting")
	}
	versionEnd := bytes.IndexByte(greeting[1:], 0)
	if versionEnd <= 0 {
		return nil, errors.New("invalid server version in greeting")
	}
	// After the terminated version: connection ID (4), scramble (8), filler
	// (1), capabilities (2), charset (1), status (2), capabilities (2), auth
	// length (1), reserved (10). Authentication data after that is irrelevant.
	rest := greeting[versionEnd+2:]
	if len(rest) < 31 || rest[12] != 0 {
		return nil, errors.New("truncated or malformed protocol-10 greeting")
	}
	capabilities := uint32(binary.LittleEndian.Uint16(rest[13:15])) |
		uint32(binary.LittleEndian.Uint16(rest[18:20]))<<16
	if capabilities&mysqlClientProtocol41 == 0 {
		return nil, errors.New("server does not offer protocol 4.1")
	}
	if capabilities&mysqlClientSSL == 0 {
		return nil, errors.New("server does not offer TLS")
	}
	// Advertise only supported, shared capabilities. The request stops before
	// the username field; authentication belongs to actual application clients.
	flags := uint32(mysqlClientProtocol41|mysqlClientSSL) |
		(capabilities & (mysqlSecureConnection | mysqlClientPluginAuth))
	request := make([]byte, 36)
	request[0], request[3] = 32, 1 // payload length and next packet sequence
	binary.LittleEndian.PutUint32(request[4:8], flags)
	binary.LittleEndian.PutUint32(request[8:12], 1<<24)
	request[12] = rest[15]
	return request, nil
}
