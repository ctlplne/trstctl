// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/crypto/mongosignin"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const mongoRuleMaxMessage = 1 << 20
const mongoRuleQueue = 16

type mongoRuleFrame struct {
	raw     []byte
	release func()
}

func (f mongoRuleFrame) done() {
	secret.Wipe(f.raw)
	if f.release != nil {
		f.release()
	}
}

func mongoRuleLength(header [16]byte) (int, bool) {
	length := binary.LittleEndian.Uint32(header[:])
	if length < 21 || length > mongoRuleMaxMessage {
		return 0, false
	}
	return int(length), true
}

func readMongoRuleFrame(src io.Reader, reserve func(int) (func(), bool)) (mongoRuleFrame, error) {
	var header [16]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		return mongoRuleFrame{}, err
	}
	length, ok := mongoRuleLength(header)
	if !ok {
		return mongoRuleFrame{}, errMongoMessage
	}
	op := binary.LittleEndian.Uint32(header[12:])
	if op != uint32(mongosignin.OpMsg) && op != uint32(mongosignin.OpQuery) {
		return mongoRuleFrame{}, errMongoMessage
	}
	release, ok := reserve(length)
	if !ok {
		return mongoRuleFrame{}, errCommandBusy
	}
	frame := mongoRuleFrame{raw: make([]byte, length), release: release}
	copy(frame.raw, header[:])
	if _, err := io.ReadFull(src, frame.raw[16:]); err != nil {
		frame.done()
		return mongoRuleFrame{}, err
	}
	return frame, nil
}

func relayMongoRuleCommands(parent context.Context, client, server net.Conn, m *mongoRelay, c *commandConnection) error {
	ctx, cancel := context.WithCancelCause(parent)
	frames := make(chan mongoRuleFrame, mongoRuleQueue)
	backendDone := make(chan struct{})
	go func() { defer close(backendDone); err := m.replies(server); cancel(err) }()
	go func() { <-ctx.Done(); _ = server.Close(); _ = client.Close() }()
	go func() {
		defer close(frames)
		for {
			frame, err := readMongoRuleFrame(client, c.reserveFrame)
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
			err := forwardMongoRuleCommand(ctx, server, m, c, frame)
			frame.done()
			if err != nil {
				return err
			}
		}
	}
}

func forwardMongoRuleCommand(ctx context.Context, server io.Writer, m *mongoRelay, c *commandConnection, frame mongoRuleFrame) error {
	requestID := int32(binary.LittleEndian.Uint32(frame.raw[4:])) // #nosec G115 -- request ID's two's-complement bits (CWE-190)
	op := binary.LittleEndian.Uint32(frame.raw[12:])
	body := frame.raw[16:]
	if op == uint32(mongosignin.OpQuery) {
		// Legacy traffic is restricted to the existing sanitized hello handshake.
		stripped, err := m.legacyHandshake(body)
		if err != nil {
			return err
		}
		defer secret.Wipe(stripped)
		raw := append(mongosignin.MessageHeader(16+len(stripped), requestID, 0, mongosignin.OpQuery), stripped...)
		defer secret.Wipe(raw)
		_, err = server.Write(raw)
		return err
	}
	flags, doc, rest, err := opMsgSections(body)
	if err != nil {
		return err
	}
	defer secret.Wipe(rest)
	name, elems, err := commandName(doc)
	if err != nil {
		return err
	}
	if mongoRefused[strings.ToLower(name)] {
		m.record("mongo", "refused", "LOGIN_CHANGE")
		if flags&mongosignin.FlagMoreToCome != 0 {
			return errors.New("accessgateway: MongoDB login change refused")
		}
		return m.refuse(requestID, "LOGIN_CHANGE")
	}
	if isHandshake(name) {
		if flags&mongosignin.FlagMoreToCome != 0 || len(rest) != 0 {
			return errMongoMessage
		}
		stripped, changed := stripHandshake(doc, elems)
		if changed {
			defer secret.Wipe(stripped)
		}
		// Keep only the known optional exhaust flag; remove speculative auth,
		// compression offers and any checksum covering the old handshake bytes.
		rewritten := binary.LittleEndian.AppendUint32(nil, flags&(1<<16))
		rewritten = append(append(rewritten, 0), stripped...)
		defer secret.Wipe(rewritten)
		raw := append(mongosignin.MessageHeader(16+len(rewritten), requestID, 0, mongosignin.OpMsg), rewritten...)
		defer secret.Wipe(raw)
		m.record("mongo", "command", mongoRender(stripped))
		_, err := server.Write(raw)
		return err
	}
	phase := "document"
	operations := []string{}
	operation := accessrules.MongoOperation([]byte(name))
	if operation == "" {
		phase = "control"
	} else {
		operations = append(operations, operation)
	}
	closeAfter := false
	// Transactions and opaque flag modes are unsupported in this guarded path.
	if flags&^mongosignin.FlagMoreToCome != 0 {
		phase = "control"
		closeAfter = flags&mongosignin.FlagMoreToCome != 0
	}
	for _, e := range elems {
		if e.Key == "autocommit" || e.Key == "startTransaction" {
			phase = "control"
			closeAfter = true
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
		m.record("mongo", "refused", "TRSTCTL_COMMAND_REFUSED")
		if flags&mongosignin.FlagMoreToCome == 0 {
			if err := m.refuse(requestID, "TRSTCTL_COMMAND_REFUSED"); err != nil {
				return err
			}
		}
		if closeAfter {
			return errors.New("accessgateway: unsupported MongoDB guarded execution mode")
		}
		return nil
	}
	m.record("mongo", "command", mongoRender(doc))
	_, err = server.Write(frame.raw)
	return err
}
