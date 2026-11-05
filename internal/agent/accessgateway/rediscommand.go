// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const redisRuleFrameBytes = 1 << 20
const redisRuleMaxArgs = 1024
const redisRuleQueue = 16

type redisRuleFrame struct {
	raw     []byte
	args    [][]byte
	release func()
}

func (f redisRuleFrame) done() {
	if f.raw != nil {
		secret.Wipe(f.raw[:cap(f.raw)])
	}
	if f.release != nil {
		f.release()
	}
}

// readRedisRuleFrame accepts canonical RESP arrays of bulk strings. The full
// frame reservation precedes allocation. No oversized value streams past a guard.
func readRedisRuleFrame(src *bufio.Reader, reserve func(int) (func(), bool)) (redisRuleFrame, error) {
	var f redisRuleFrame
	lead, err := src.ReadByte()
	if err != nil {
		return f, err
	}
	if lead != '*' {
		return f, errRedisInline
	}
	n, err := redisRuleNumber(src)
	if err != nil || n < 1 || n > redisRuleMaxArgs {
		return f, accessrules.ErrUninspectable
	}
	release, ok := reserve(redisRuleFrameBytes)
	if !ok {
		return f, errCommandBusy
	}
	f.release = release
	f.raw = make([]byte, 0, redisRuleFrameBytes)
	f.args = make([][]byte, 0, n)
	f.raw = append(f.raw, respArrayHeader(n)...)
	fail := func(err error) (redisRuleFrame, error) { f.done(); return redisRuleFrame{}, err }
	for range n {
		lead, err = src.ReadByte()
		if err != nil {
			return fail(err)
		}
		if lead != '$' {
			return fail(accessrules.ErrUninspectable)
		}
		size, err := redisRuleNumber(src)
		if err != nil || size < 0 || size > redisRuleFrameBytes {
			return fail(accessrules.ErrUninspectable)
		}
		header := respBulkHeader(size)
		if len(f.raw)+len(header)+size+2 > redisRuleFrameBytes {
			return fail(accessrules.ErrUninspectable)
		}
		f.raw = append(f.raw, header...)
		start := len(f.raw)
		f.raw = f.raw[:start+size+2]
		if _, err := io.ReadFull(src, f.raw[start:]); err != nil {
			return fail(err)
		}
		if !bytes.Equal(f.raw[start+size:], []byte("\r\n")) {
			return fail(accessrules.ErrUninspectable)
		}
		f.args = append(f.args, f.raw[start:start+size])
	}
	if len(f.args[0]) < 1 || len(f.args[0]) > redisNameBytes {
		return fail(accessrules.ErrUninspectable)
	}
	return f, nil
}

func redisRuleNumber(src *bufio.Reader) (int, error) {
	var raw [24]byte
	for i := 0; i < len(raw); i++ {
		c, err := src.ReadByte()
		if err != nil {
			return 0, err
		}
		if c == '\r' {
			end, err := src.ReadByte()
			if err != nil {
				return 0, err
			}
			if end != '\n' || i == 0 {
				return 0, accessrules.ErrUninspectable
			}
			digits := raw[:i]
			n, err := strconv.Atoi(string(digits))
			if err != nil || n < 0 || strconv.Itoa(n) != string(digits) {
				return 0, accessrules.ErrUninspectable
			}
			return n, nil
		}
		if c < '0' || c > '9' {
			return 0, accessrules.ErrUninspectable
		}
		raw[i] = c
	}
	return 0, accessrules.ErrUninspectable
}

func relayRedisRuleCommands(parent context.Context, client, server net.Conn, c *commandConnection, rec *connRecorder, record func(redisCommand)) error {
	ctx, cancel := context.WithCancelCause(parent)
	frames := make(chan redisRuleFrame, redisRuleQueue)
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		var err error
		if rec == nil {
			_, err = io.Copy(client, server)
		} else {
			err = relayRedisReplies(client, bufio.NewReaderSize(server, 32<<10), func(kind, text string) { rec.event("result", kind, text, 0) })
		}
		cancel(err)
	}()
	go func() { <-ctx.Done(); _ = server.Close(); _ = client.SetReadDeadline(time.Now()) }()
	go func() {
		defer close(frames)
		reader := bufio.NewReaderSize(client, 32<<10)
		for {
			frame, err := readRedisRuleFrame(reader, c.reserveFrame)
			if err != nil {
				cancel(err)
				return
			}
			select {
			case frames <- frame:
			case <-ctx.Done():
				frame.done()
				return
			default:
				frame.done()
				cancel(errCommandBusy)
				return
			}
		}
	}()
	defer func() {
		cancel(context.Canceled)
		if errors.Is(context.Cause(ctx), errCommandBusy) {
			_ = client.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(client, "-BUSY trstctl command input capacity is full\r\n")
		}
		_ = client.Close()
		_ = server.Close()
		for frame := range frames {
			frame.done()
		}
		<-backendDone
	}()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case frame, ok := <-frames:
			if !ok {
				return context.Cause(ctx)
			}
			err := forwardRedisRuleCommand(ctx, server, c, frame, record)
			frame.done()
			if err != nil {
				return err
			}
		}
	}
}

func redisRuleAuthentication(args [][]byte) bool {
	if len(args) == 0 {
		return false
	}
	if bytes.EqualFold(args[0], []byte("AUTH")) || bytes.EqualFold(args[0], []byte("RESET")) {
		return true
	}
	if bytes.EqualFold(args[0], []byte("HELLO")) {
		for _, arg := range args[1:] {
			if bytes.EqualFold(arg, []byte("AUTH")) {
				return true
			}
		}
	}
	return false
}

func forwardRedisRuleCommand(ctx context.Context, server io.Writer, c *commandConnection, frame redisRuleFrame, record func(redisCommand)) error {
	// Authentication requests never enter the command matcher or source RPC.
	if redisRuleAuthentication(frame.args) {
		return refuseRedis(server, "LOGIN_CHANGE", record)
	}
	phase := "command"
	operations := []string{}
	operation := accessrules.RedisOperation(frame.args[0])
	if operation != "" {
		operations = append(operations, operation)
	} else {
		safe := bytes.EqualFold(frame.args[0], []byte("PING")) || bytes.EqualFold(frame.args[0], []byte("QUIT"))
		if bytes.EqualFold(frame.args[0], []byte("HELLO")) {
			safe = len(frame.args) == 2 && (bytes.Equal(frame.args[1], []byte("2")) || bytes.Equal(frame.args[1], []byte("3")))
		}
		if !safe {
			phase = "control"
		}
	}
	result, err := c.evaluate(ctx, phase, operations, frame.raw, "")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	allowed := err == nil && (result.decision.ID == "" || result.durable && result.decision.Status == accessrules.StatusAuthorized)
	if allowed && result.decision.ReviewExpiresAt != nil && !time.Now().Before(*result.decision.ReviewExpiresAt) {
		allowed = false
	}
	if !allowed {
		if err := refuseRedis(server, "COMMAND_POLICY", record); err != nil {
			return err
		}
		if redisRuleTransaction(frame.args[0]) {
			return errors.New("accessgateway: Redis transactions are unsupported in ruled sessions")
		}
		return nil
	}
	var event redisCommand
	for _, arg := range frame.args {
		event.text.addArg(arg, len(arg))
	}
	record(event)
	_, err = server.Write(frame.raw)
	return err
}

func redisRuleTransaction(name []byte) bool {
	for _, op := range []string{"MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH"} {
		if bytes.EqualFold(name, []byte(op)) {
			return true
		}
	}
	return false
}
