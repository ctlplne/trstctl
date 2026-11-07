// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const pgCommandMaxFrame = accessrules.MaxStatementBytes + 8192
const pgCommandQueue = 64
const pgCommandCache = 128

type pgCommandFrame struct {
	raw     []byte
	err     error
	release func()
}

func (f pgCommandFrame) done() {
	secret.Wipe(f.raw)
	if f.release != nil {
		f.release()
	}
}

type pgCommandAck struct {
	kind   byte
	failed bool
}
type pgCommandWait struct {
	kinds       string
	stopOnError bool
	failed      bool
	done        chan pgCommandAck
}
type pgCommandState struct {
	mu      sync.Mutex
	failed  bool
	waiting *pgCommandWait
}

func (s *pgCommandState) begin(kinds string, stopOnError, allowFailed bool) (<-chan pgCommandAck, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed && !allowFailed {
		return nil, false
	}
	wait := &pgCommandWait{kinds: kinds, stopOnError: stopOnError, done: make(chan pgCommandAck, 1)}
	s.waiting = wait
	return wait.done, true
}
func (s *pgCommandState) backend(kind byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == 'E' {
		s.failed = true
		if s.waiting != nil {
			s.waiting.failed = true
		}
	}
	if kind == 'Z' {
		s.failed = false
	}
	wait := s.waiting
	if wait != nil && (strings.ContainsRune(wait.kinds, rune(kind)) || kind == 'E' && wait.stopOnError) {
		wait.done <- pgCommandAck{kind: kind, failed: wait.failed}
		s.waiting = nil
	}
}
func (s *pgCommandState) isFailed() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.failed }

type pgPreparedCommand struct {
	operations []string
	digest     string
}
type pgCommandPortal struct {
	command   pgPreparedCommand
	completed bool
	started   bool
	expiresAt *time.Time
}

type pgCommandRelay struct {
	ctx               context.Context
	cancel            context.CancelCauseFunc
	guard             *commandConnection
	client, server    net.Conn
	rec               *pgRecorder
	state             pgCommandState
	clientMu          sync.Mutex
	statements        map[string]pgPreparedCommand
	portals           map[string]pgCommandPortal
	copyMode          byte
	copyPortal        string
	lastAuthorization *time.Time
}

// relayPostgresCommands runs after both authentication exchanges. One bounded
// reader notices a disconnect while a decision is pending; it never accumulates
// an unbounded pipeline. State changes wait for real backend acknowledgments.
func relayPostgresCommands(parent context.Context, client, server net.Conn, guard *commandConnection, rec *connRecorder) error {
	ctx, cancel := context.WithCancelCause(parent)
	p := &pgCommandRelay{ctx: ctx, cancel: cancel, guard: guard, client: client, server: server, statements: map[string]pgPreparedCommand{}, portals: map[string]pgCommandPortal{}}
	if rec != nil {
		p.rec = &pgRecorder{conn: rec}
	}
	frames := make(chan pgCommandFrame, pgCommandQueue)
	backendDone := make(chan struct{})
	go func() { defer close(backendDone); err := p.backend(); cancel(err) }()
	go func() { <-ctx.Done(); _ = server.Close() }()
	go p.readFrames(frames)
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
			if errors.Is(context.Cause(ctx), errCommandBusy) {
				p.fatal("TRSTCTL_POLICY_CAPACITY_FULL: command input queue is full")
			}
			return context.Cause(ctx)
		case f, ok := <-frames:
			if !ok {
				return nil
			}
			err := p.frontend(f)
			f.done()
			if err != nil {
				return err
			}
		}
	}
}

func (p *pgCommandRelay) readFrames(out chan<- pgCommandFrame) {
	defer close(out)
	for {
		var header [5]byte
		if _, err := io.ReadFull(p.client, header[:]); err != nil {
			p.cancel(err)
			return
		}
		length := binary.BigEndian.Uint32(header[1:])
		// Authentication messages never reach the command classifier, even when a
		// client sends an unsolicited password after its admitted startup.
		allowed := bytes.IndexByte([]byte("QPBECDFHSXdcf"), header[0]) >= 0
		if length < 4 || length-4 > pgCommandMaxFrame || !allowed {
			select {
			case out <- pgCommandFrame{raw: bytes.Clone(header[:]), err: accessrules.ErrUninspectable}:
			case <-p.ctx.Done():
			}
			return
		}
		size := int(length - 4)
		release, ok := p.guard.reserveFrame(size + 5)
		if !ok {
			select {
			case out <- pgCommandFrame{raw: bytes.Clone(header[:]), err: errCommandBusy}:
			case <-p.ctx.Done():
			}
			return
		}
		raw := make([]byte, 5+size)
		copy(raw, header[:])
		if _, err := io.ReadFull(p.client, raw[5:]); err != nil {
			secret.Wipe(raw)
			release()
			p.cancel(err)
			return
		}
		f := pgCommandFrame{raw: raw, release: release}
		select {
		case out <- f:
		case <-p.ctx.Done():
			f.done()
			return
		default:
			f.done()
			p.cancel(errCommandBusy)
			return
		}
	}
}

func (p *pgCommandRelay) writeClient(raw []byte) error {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()
	_, err := p.client.Write(raw)
	return err
}
func (p *pgCommandRelay) fatal(message string) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()
	_ = refusePostgres(p.client, message)
}

func (p *pgCommandRelay) backend() error {
	var header [5]byte
	for {
		if _, err := io.ReadFull(p.server, header[:]); err != nil {
			return err
		}
		length := binary.BigEndian.Uint32(header[1:])
		if length < 4 {
			return io.ErrUnexpectedEOF
		}
		size := int64(length - 4)
		if size > pgParsedMessage {
			if p.rec != nil {
				p.rec.server(header[0], nil, int(size))
			}
			p.clientMu.Lock()
			_, err := p.client.Write(header[:])
			if err == nil {
				_, err = io.CopyN(p.client, p.server, size)
			}
			p.clientMu.Unlock()
			if err != nil {
				return err
			}
		} else {
			raw := make([]byte, 5+int(size))
			copy(raw, header[:])
			if _, err := io.ReadFull(p.server, raw[5:]); err != nil {
				return err
			}
			if p.rec != nil {
				p.rec.server(header[0], raw[5:], int(size))
			}
			if err := p.writeClient(raw); err != nil {
				return err
			}
		}
		p.state.backend(header[0])
	}
}

func (p *pgCommandRelay) forward(raw []byte, kinds string, stopOnError, allowFailed bool) (pgCommandAck, error) {
	if p.ctx.Err() != nil {
		return pgCommandAck{}, p.ctx.Err()
	}
	if kinds == "" {
		_, err := p.server.Write(raw)
		return pgCommandAck{}, err
	}
	done, ok := p.state.begin(kinds, stopOnError, allowFailed)
	if !ok {
		return pgCommandAck{failed: true}, nil
	}
	if _, err := p.server.Write(raw); err != nil {
		return pgCommandAck{}, err
	}
	// Parse/Bind/Close may be buffered until a later Sync. Flush avoids waiting
	// for an acknowledgment while that Sync is still in our frontend queue.
	if _, err := p.server.Write(pgMessage('H', nil)); err != nil {
		return pgCommandAck{}, err
	}
	select {
	case ack := <-done:
		return ack, nil
	case <-p.ctx.Done():
		return pgCommandAck{}, p.ctx.Err()
	}
}

func (p *pgCommandRelay) recordClient(raw []byte) {
	if p.rec != nil {
		p.rec.client(raw[0], raw[5:], len(raw)-5)
	}
}
func (p *pgCommandRelay) check(phase string, operations []string, raw []byte, parent string) (bool, string, error) {
	p.lastAuthorization = nil
	check, err := p.guard.evaluate(p.ctx, phase, operations, raw, parent)
	if check.decision.ID == "" && err == nil {
		return false, "", nil
	}
	if p.ctx.Err() != nil {
		return true, "", p.ctx.Err()
	}
	if err == nil && accessrules.Permits(check.decision.Status) {
		// An authorized command runs before its review deadline; an alerted
		// one (A275) has none. The recording marks which it was.
		p.lastAuthorization = check.decision.ReviewExpiresAt
		if p.rec != nil {
			p.rec.conn.event("policy", check.decision.Status, check.decision.ID, 0)
		}
		return false, "", nil
	}
	marker := "TRSTCTL_POLICY_BLOCKED_" + strings.ReplaceAll(check.decision.ID, "-", "_")
	if err != nil {
		marker = "TRSTCTL_POLICY_AUDIT_UNAVAILABLE_" + strings.ReplaceAll(check.decision.ID, "-", "_")
		p.guard.gateway.cfg.Logf("accessgateway: session %s action %s refused; durable decision unavailable", p.guard.sessionID, check.decision.ID)
	}
	if p.rec != nil {
		p.rec.conn.event("policy", "blocked", marker, 0)
	}
	return true, marker, nil
}

func (p *pgCommandRelay) refuse(raw []byte, phase string, operations []string, parent string, simple bool) error {
	blocked, marker, err := p.check(phase, operations, raw, parent)
	if err != nil {
		return err
	}
	if !blocked {
		return errors.New("accessgateway: missing guarded refusal")
	}
	return p.reject(marker, simple)
}

func (p *pgCommandRelay) reject(marker string, simple bool) error {
	query := append([]byte(marker), 0)
	if simple {
		_, err := p.forward(pgMessage('Q', query), "ZG", false, false)
		return err
	}
	name := []byte("__trstctl_refused_" + strings.ReplaceAll(p.guard.connectionID, "-", "_") + "_" + strings.ReplaceAll(marker, "-", "_"))
	body := append(append(append(name, 0), query...), 0, 0)
	_, err := p.forward(pgMessage('P', body), "1", true, false)
	return err
}

func (p *pgCommandRelay) frontend(f pgCommandFrame) error {
	if p.ctx.Err() != nil {
		return p.ctx.Err()
	}
	if f.err != nil {
		_, id, _ := p.check("uninspectable", nil, f.raw, "")
		if errors.Is(f.err, errCommandBusy) {
			p.fatal("TRSTCTL_POLICY_CAPACITY_FULL: command buffer is full")
		} else {
			p.fatal("TRSTCTL_POLICY_UNINSPECTABLE: guarded client frame refused " + id)
		}
		return f.err
	}
	raw := f.raw
	kind := raw[0]
	body := raw[5:]
	if p.state.isFailed() && kind != 'S' && kind != 'H' && kind != 'X' {
		return nil
	}
	switch kind {
	case 'Q':
		query, rest, ok := pgCommandString(body, accessrules.MaxStatementBytes)
		if !ok || len(rest) != 0 {
			return p.refuse(raw, "uninspectable", nil, "", true)
		}
		operations, err := accessrules.PostgresRuleOperations(query)
		if err != nil {
			return p.refuse(raw, "uninspectable", nil, "", true)
		}
		phase := "query"
		if accessrules.UnsupportedPostgresControl(operations) {
			phase = "control"
		}
		if phase == "control" || len(accessrules.Match(p.guard.policy, operations)) > 0 {
			blocked, marker, err := p.check(phase, operations, raw, "")
			if err != nil {
				return err
			}
			if blocked {
				return p.reject(marker, true)
			}
		}
		p.recordClient(raw)
		ack, err := p.forward(raw, "ZG", false, false)
		if ack.kind == 'G' {
			p.copyMode = 'Q'
		}
		return err
	case 'P':
		name, after, ok := pgCommandString(body, 256)
		query, types, ok2 := pgCommandString(after, accessrules.MaxStatementBytes)
		if !ok || !ok2 || len(types) < 2 || len(types) != 2+4*int(binary.BigEndian.Uint16(types)) {
			return p.refuse(raw, "uninspectable", nil, "", false)
		}
		key := crypto.SHA256Hex(name)
		operations, err := accessrules.PostgresRuleOperations(query)
		if err != nil || accessrules.UnsupportedPostgresControl(operations) {
			return p.refuse(raw, "uninspectable", nil, "", false)
		}
		if _, exists := p.statements[key]; !exists && len(p.statements) >= pgCommandCache {
			return p.refuse(raw, "uninspectable", nil, "", false)
		}
		p.recordClient(raw)
		ack, err := p.forward(raw, "1", true, false)
		if err != nil {
			return err
		}
		if !ack.failed {
			p.statements[key] = pgPreparedCommand{operations: operations, digest: crypto.SHA256Hex(raw)}
		} else if len(name) == 0 {
			delete(p.statements, key)
		}
		return nil
	case 'B':
		portal, statement, ok := pgCommandBind(body)
		if !ok {
			return p.refuse(raw, "uninspectable", nil, "", false)
		}
		command, exists := p.statements[crypto.SHA256Hex(statement)]
		if !exists {
			return p.refuse(raw, "control", nil, "", false)
		}
		key := crypto.SHA256Hex(portal)
		if _, exists := p.portals[key]; !exists && len(p.portals) >= pgCommandCache {
			return p.refuse(raw, "uninspectable", nil, "", false)
		}
		p.lastAuthorization = nil
		if len(accessrules.Match(p.guard.policy, command.operations)) > 0 {
			blocked, marker, err := p.check("bind", command.operations, raw, command.digest)
			if err != nil {
				return err
			}
			if blocked {
				return p.reject(marker, false)
			}
		}
		p.recordClient(raw)
		ack, err := p.forward(raw, "2", true, false)
		if err != nil {
			return err
		}
		if !ack.failed {
			p.portals[key] = pgCommandPortal{command: command, expiresAt: p.lastAuthorization}
		} else if len(portal) == 0 {
			delete(p.portals, key)
		}
		return nil
	case 'E':
		portal, rest, ok := pgCommandString(body, 256)
		if !ok || len(rest) != 4 {
			return p.refuse(raw, "uninspectable", nil, "", false)
		}
		key := crypto.SHA256Hex(portal)
		entry, exists := p.portals[key]
		if !exists || entry.completed || (!entry.started && entry.expiresAt != nil && !time.Now().Before(*entry.expiresAt)) {
			return p.refuse(raw, "control", nil, "", false)
		}
		p.recordClient(raw)
		ack, err := p.forward(raw, "CsG", true, false)
		if err != nil {
			return err
		}
		if ack.failed {
			delete(p.portals, key)
		} else if ack.kind == 'C' {
			entry.started = true
			entry.completed = true
			p.portals[key] = entry
		} else if ack.kind == 'G' {
			entry.started = true
			p.portals[key] = entry
			p.copyMode = 'E'
			p.copyPortal = key
		}
		if ack.kind == 's' {
			entry.started = true
			p.portals[key] = entry
		}
		return nil
	case 'C':
		if len(body) < 1 || body[0] != 'S' && body[0] != 'P' {
			return p.refuse(raw, "uninspectable", nil, "", false)
		}
		name, rest, ok := pgCommandString(body[1:], 256)
		if !ok || len(rest) != 0 {
			return p.refuse(raw, "uninspectable", nil, "", false)
		}
		p.recordClient(raw)
		ack, err := p.forward(raw, "3", true, false)
		if err != nil {
			return err
		}
		if !ack.failed {
			if body[0] == 'S' {
				delete(p.statements, crypto.SHA256Hex(name))
			} else {
				delete(p.portals, crypto.SHA256Hex(name))
			}
		}
		return nil
	case 'S':
		p.recordClient(raw)
		_, err := p.forward(raw, "Z", false, true)
		return err
	case 'c', 'f':
		p.recordClient(raw)
		if p.copyMode == 0 {
			_, err := p.forward(raw, "", false, false)
			return err
		}
		mode, portal := p.copyMode, p.copyPortal
		p.copyMode = 0
		p.copyPortal = ""
		kinds := "C"
		if mode == 'Q' {
			kinds = "Z"
		}
		ack, err := p.forward(raw, kinds, mode != 'Q', false)
		if portal != "" {
			entry := p.portals[portal]
			entry.completed = true
			p.portals[portal] = entry
			if ack.failed {
				delete(p.portals, portal)
			}
		}
		return err
	case 'F':
		return p.refuse(raw, "control", nil, "", true)
	case 'D', 'H', 'd', 'X':
		p.recordClient(raw)
		_, err := p.forward(raw, "", false, false)
		return err
	default:
		return p.refuse(raw, "uninspectable", nil, "", false)
	}
}

func pgCommandString(raw []byte, max int) ([]byte, []byte, bool) {
	end := bytes.IndexByte(raw, 0)
	if end < 0 || end > max {
		return nil, nil, false
	}
	return raw[:end], raw[end+1:], true
}

// pgCommandBind validates framing without decoding or copying parameter values.
func pgCommandBind(raw []byte) ([]byte, []byte, bool) {
	portal, rest, ok := pgCommandString(raw, 256)
	statement, rest, ok2 := pgCommandString(rest, 256)
	if !ok || !ok2 || len(rest) < 2 {
		return nil, nil, false
	}
	formats := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if formats > 1024 || len(rest) < 2*formats+2 {
		return nil, nil, false
	}
	rest = rest[2*formats:]
	count := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if count > 1024 || formats > 1 && formats != count {
		return nil, nil, false
	}
	for range count {
		if len(rest) < 4 {
			return nil, nil, false
		}
		size := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if size == ^uint32(0) {
			continue
		}
		if int64(size) > int64(len(rest)) {
			return nil, nil, false
		}
		rest = rest[size:]
	}
	if len(rest) < 2 {
		return nil, nil, false
	}
	results := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if results > 1024 || len(rest) != 2*results {
		return nil, nil, false
	}
	return portal, statement, true
}
