// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const mysqlCommandQueue = 16

type mysqlCommandFrame struct {
	header  [4]byte
	payload []byte
	release func()
}

func (f mysqlCommandFrame) done() {
	secret.Wipe(f.payload)
	if f.release != nil {
		f.release()
	}
}

// relayMySQLCommands gates only the post-authentication command phase. The
// ordinary response relay stays byte-for-byte; a refused query is replaced by
// fixed invalid SQL in the same wire order, so pipeline responses cannot overtake.
func relayMySQLCommands(parent context.Context, client, server net.Conn, m *mysqlRelay, c *commandConnection) error {
	ctx, cancel := context.WithCancelCause(parent)
	frames := make(chan mysqlCommandFrame, mysqlCommandQueue)
	backendDone := make(chan struct{})
	go func() { defer close(backendDone); err := m.responses(server); cancel(err) }()
	go func() { <-ctx.Done(); _ = server.Close(); _ = client.Close() }()
	go readMySQLCommandFrames(ctx, cancel, client, c, frames)
	defer func() {
		cancel(context.Canceled)
		_ = client.Close()
		_ = server.Close()
		for f := range frames {
			f.done()
		}
		<-backendDone
	}()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case f, ok := <-frames:
			if !ok {
				return context.Cause(ctx)
			}
			err := forwardMySQLCommand(ctx, server, m, c, f)
			f.done()
			if err != nil {
				return err
			}
		}
	}
}

func readMySQLCommandFrames(ctx context.Context, cancel context.CancelCauseFunc, client net.Conn, c *commandConnection, out chan<- mysqlCommandFrame) {
	defer close(out)
	for {
		var f mysqlCommandFrame
		if _, err := io.ReadFull(client, f.header[:]); err != nil {
			cancel(err)
			return
		}
		size, valid := mysqlGuardedFrameSize(f.header)
		if !valid {
			cancel(errors.New("accessgateway: MySQL guarded frame exceeds its inspection bound"))
			return
		}
		release, ok := c.reserveFrame(size + 4)
		if !ok {
			cancel(errCommandBusy)
			return
		}
		f.release = release
		f.payload = make([]byte, size)
		if _, err := io.ReadFull(client, f.payload); err != nil {
			f.done()
			cancel(err)
			return
		}
		select {
		case out <- f:
		case <-ctx.Done():
			f.done()
			return
		default:
			f.done()
			cancel(errCommandBusy)
			return
		}
	}
}

// mysqlRuleQuery excludes the query-attribute envelope. Attribute values are
// unsupported in this first MySQL rule path and cannot be mistaken for SQL.
func mysqlRuleQuery(payload []byte, attributes bool) ([]byte, bool) {
	if !attributes {
		return payload, true
	}
	count, n, ok := mysqlLenenc(payload)
	if !ok || count != 0 {
		return nil, false
	}
	payload = payload[n:]
	sets, n, ok := mysqlLenenc(payload)
	if !ok || sets != 1 {
		return nil, false
	}
	return payload[n:], true
}

func forwardMySQLCommand(ctx context.Context, server io.Writer, m *mysqlRelay, c *commandConnection, f mysqlCommandFrame) error {
	// A client credential switch is authentication, never command-policy input.
	if f.payload[0] == mysqlComChangeUser {
		return errors.New("accessgateway: login changes are refused")
	}
	phase := "control"
	operations := []string{}
	message := f.payload
	if f.header[3] == 0 {
		switch f.payload[0] {
		case mysqlComQuery:
			sql, ok := mysqlRuleQuery(f.payload[1:], m.queryAttributes)
			if ok {
				var err error
				operations, err = accessrules.MySQLRuleOperations(sql)
				message = sql
				phase = "query"
				if err != nil {
					phase = "uninspectable"
				} else if accessrules.UnsupportedMySQLControl(operations) {
					phase = "control"
				}
			} else {
				phase = "uninspectable"
			}
		case mysqlComInitDB:
			phase = "query"
			operations = []string{"USE"}
		case mysqlComQuit, 0x0e:
			// QUIT and PING contain no statement or hidden execution payload.
			if len(f.payload) == 1 {
				phase = "query"
			}
		}
	}
	result, err := c.evaluate(ctx, phase, operations, message, "")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	allowed := err == nil && (result.decision.ID == "" || result.durable && accessrules.Permits(result.decision.Status))
	if allowed && result.decision.ReviewExpiresAt != nil && !time.Now().Before(*result.decision.ReviewExpiresAt) {
		allowed = false
	}
	payload := f.payload
	if !allowed {
		m.record("sql", "refused", "trstctl_command_refused: gateway command guardrail")
		// A no-response control cannot be replaced with an error response without
		// corrupting the next command's packet sequence; end that stream instead.
		if f.header[3] != 0 || payload[0] == 0x18 || payload[0] == 0x19 {
			return errors.New("accessgateway: trstctl_command_refused")
		}
		payload = append([]byte{mysqlComQuery}, []byte("trstctl_command_refused")...)
		if m.queryAttributes {
			payload = append([]byte{mysqlComQuery, 0, 1}, []byte("trstctl_command_refused")...)
		}
	} else {
		m.recordCommand(payload)
	}
	m.mu.Lock()
	m.command, m.state = payload[0], mysqlAwaitFirst
	m.mu.Unlock()
	header := f.header
	binary.LittleEndian.PutUint16(header[:2], uint16(len(payload)&0xffff)) // #nosec G115 -- bounded 24-bit packet length (CWE-190)
	header[2] = byte(len(payload) >> 16)                                   // #nosec G115 -- high byte of bounded 24-bit packet length (CWE-190)
	if _, err := server.Write(header[:]); err != nil {
		return err
	}
	_, err = server.Write(payload)
	return err
}

func mysqlGuardedFrameSize(header [4]byte) (int, bool) {
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	return size, size >= 1 && size <= accessrules.MaxStatementBytes+1
}
