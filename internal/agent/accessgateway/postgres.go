// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"trstctl.com/trstctl/internal/crypto/pgsignin"
)

// PostgreSQL startup codes a client may open with.
const (
	pgProtocol3      = 196608
	pgSSLRequest     = 80877103
	pgGSSEncRequest  = 80877104
	pgCancelRequest  = 80877102
	pgMaxStartupSize = 10 << 10
)

// servePostgres answers a stock PostgreSQL client itself and signs in
// upstream as the session's login: the client's own startup carries no
// credential (the admitted tunnel is its authentication), the gateway signs in
// upstream with the session's DSN, then hands the client the upstream
// session's parameters, key data and readiness and relays the protocol both
// ways until either side closes or the deadline passes. The client never
// receives the DSN.
func servePostgres(ctx context.Context, client net.Conn, dsn []byte, deadline time.Time, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	params, err := readClientStartup(client)
	if err != nil {
		return err
	}
	runtime := make([][2]string, 0, len(params))
	database := ""
	for _, p := range params {
		if p[0] == "database" {
			database = p[1]
		}
		if pgsignin.RuntimeParameter(p[0]) {
			runtime = append(runtime, p)
		}
	}
	signInCtx, cancel := context.WithDeadline(ctx, earliest(deadline, time.Now().Add(30*time.Second)))
	defer cancel()
	upstream, err := pgsignin.SignIn(signInCtx, dsn, pgsignin.Options{Dial: dial, Database: database, Runtime: runtime})
	if err != nil {
		_ = refusePostgres(client, "the upstream database refused the session's login")
		return err
	}
	server := upstream.Conn
	defer func() { _ = server.Close() }()
	_ = server.SetDeadline(deadline)
	ready := pgMessage('R', binary.BigEndian.AppendUint32(nil, 0))
	for _, p := range upstream.Parameters {
		ready = append(ready, pgMessage('S', append(append(append([]byte(p[0]), 0), p[1]...), 0))...)
	}
	ready = append(ready, pgMessage('K', binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, upstream.ProcessID), upstream.SecretKey))...)
	ready = append(ready, pgMessage('Z', []byte{upstream.TxStatus})...)
	if _, err := client.Write(ready); err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	if rec == nil {
		go func() { _, _ = io.Copy(server, client); _ = server.Close(); done <- struct{}{} }()
		go func() { _, _ = io.Copy(client, server); _ = client.Close(); done <- struct{}{} }()
	} else {
		// Recorded: relayed message by message, each seen before it is
		// forwarded (A255).
		p := &pgRecorder{conn: rec}
		go func() { _ = relayPostgres(server, client, p.client); _ = server.Close(); done <- struct{}{} }()
		go func() { _ = relayPostgres(client, server, p.server); _ = client.Close(); done <- struct{}{} }()
	}
	<-done
	return nil
}

// readClientStartup reads the client's startup, declining TLS and GSS
// encryption (the client's hop is its trstctl CLI's loopback listener; the
// tunnel to the gateway is already TLS), and returns its parameters.
func readClientStartup(client net.Conn) ([][2]string, error) {
	for {
		header := make([]byte, 8)
		if _, err := io.ReadFull(client, header); err != nil {
			return nil, fmt.Errorf("read client startup: %w", err)
		}
		length := binary.BigEndian.Uint32(header)
		if length < 8 || length > pgMaxStartupSize {
			return nil, errors.New("client startup is out of bounds")
		}
		body := make([]byte, length-8)
		if _, err := io.ReadFull(client, body); err != nil {
			return nil, fmt.Errorf("read client startup: %w", err)
		}
		switch code := binary.BigEndian.Uint32(header[4:]); code {
		case pgSSLRequest, pgGSSEncRequest:
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, err
			}
		case pgCancelRequest:
			return nil, errors.New("cancel requests are not relayed")
		case pgProtocol3:
			var params [][2]string
			for len(body) > 1 {
				name, rest, ok := cutPGString(body)
				value, rest2, ok2 := cutPGString(rest)
				if !ok || !ok2 {
					return nil, errors.New("malformed client startup")
				}
				params = append(params, [2]string{name, value})
				body = rest2
			}
			return params, nil
		default:
			return nil, fmt.Errorf("unsupported client protocol %d", code)
		}
	}
}

// refusePostgres tells the client why, in PostgreSQL's own error shape, and
// never with the upstream's text (it can name the login).
func refusePostgres(client net.Conn, message string) error {
	body := []byte("SFATAL\x00VFATAL\x00C28000\x00Mtrstctl gateway: " + message + "\x00\x00")
	_, err := client.Write(pgMessage('E', body))
	return err
}

func pgMessage(kind byte, body []byte) []byte {
	msg := append([]byte{kind}, binary.BigEndian.AppendUint32(nil, uint32(len(body)+4))...) // #nosec G115 -- gateway-built messages are small (CWE-190)
	return append(msg, body...)
}

func cutPGString(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
