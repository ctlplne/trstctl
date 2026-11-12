// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/crypto/mongosignin"
)

// What a MongoDB session's relay reads whole, and its recording keeps.
const (
	// mongoMaxMessage is MongoDB's own largest message (48 MB).
	mongoMaxMessage     = 48_000_000
	mongoRecordValue    = 256
	mongoRecordText     = 4 << 10
	mongoRecordMaxDepth = 8
)

// mongoRefused are the commands that would change who the connection is
// signed in as; the gateway answers them itself and never forwards them.
var mongoRefused = map[string]bool{"saslstart": true, "saslcontinue": true, "authenticate": true, "logout": true}

// mongoHandshakeStrip are the handshake fields the gateway removes before
// forwarding: a client's own sign-in riding on the handshake, and a
// compression offer (the gateway reads every message, so none is
// compressed).
var mongoHandshakeStrip = map[string]bool{"speculativeAuthenticate": true, "compression": true}

var errMongoMessage = errors.New("accessgateway: the MongoDB client sent a message the gateway does not relay")

// serveMongo signs in upstream as the session's user and relays a stock
// MongoDB client's messages (A256). The client sends no credential: the
// admitted tunnel is its authentication. saslStart, saslContinue,
// authenticate and logout would change who the connection is signed in as,
// so the gateway answers them with an error itself; a handshake's
// speculative sign-in and compression offer are removed; compressed and
// legacy messages end the connection. The client never receives the
// credential.
func serveMongo(ctx context.Context, client net.Conn, credential []byte, deadline time.Time, dial func(context.Context, string, string) (net.Conn, error), trust upstreamTrust, rec *connRecorder, guards ...*commandConnection) error {
	signInCtx, cancel := context.WithDeadline(ctx, earliest(deadline, time.Now().Add(30*time.Second)))
	defer cancel()
	server, err := mongosignin.SignIn(signInCtx, credential, mongosignin.Options{Dial: dial, RootCAPEM: trust.caPEM, ServerName: trust.serverName})
	if err != nil {
		return err
	}
	defer func() { _ = server.Close() }()
	_ = server.SetDeadline(deadline)
	relay := &mongoRelay{client: client, rec: rec}
	if len(guards) > 0 && guards[0] != nil {
		return relayMongoRuleCommands(ctx, client, server, relay, guards[0])
	}
	var relayErr error
	done := make(chan struct{}, 2)
	go func() { relayErr = relay.requests(server, client); _ = server.Close(); done <- struct{}{} }()
	go func() { _ = relay.replies(server); _ = client.Close(); done <- struct{}{} }()
	<-done
	<-done
	if errors.Is(relayErr, errMongoMessage) {
		return relayErr
	}
	return nil
}

// mongoRelay relays one signed-in connection.
type mongoRelay struct {
	client io.Writer
	rec    *connRecorder
	// clientMu serializes writes to the client: the reply relay's and a
	// refusal the gateway answers itself.
	clientMu sync.Mutex
	ids      atomic.Int32
}

// readMongoMessage reads one wire message: its header fields and body.
func readMongoMessage(src io.Reader) (requestID, responseTo, opCode int32, body []byte, err error) {
	var header [16]byte
	if _, err = io.ReadFull(src, header[:]); err != nil {
		return
	}
	length := int(binary.LittleEndian.Uint32(header[:]))
	if length < 16 || length > mongoMaxMessage {
		err = errors.New("accessgateway: a MongoDB message length is out of bounds")
		return
	}
	requestID = int32(binary.LittleEndian.Uint32(header[4:]))  // #nosec G115 -- a request id is its two's-complement bits (CWE-190)
	responseTo = int32(binary.LittleEndian.Uint32(header[8:])) // #nosec G115 -- a request id is its two's-complement bits (CWE-190)
	opCode = int32(binary.LittleEndian.Uint32(header[12:]))    // #nosec G115 -- an op code is a small constant (CWE-190)
	body = make([]byte, length-16)
	_, err = io.ReadFull(src, body)
	return
}

func mongoMessage(requestID, responseTo, opCode int32, body []byte) []byte {
	return append(mongosignin.MessageHeader(16+len(body), requestID, responseTo, opCode), body...)
}

// opMsgSections splits an OP_MSG body: its flags, its body document and the
// rest (document sequences), without a checksum.
func opMsgSections(body []byte) (flags uint32, doc, rest []byte, err error) {
	if len(body) < 5 {
		return 0, nil, nil, errors.New("accessgateway: an OP_MSG is short")
	}
	flags = binary.LittleEndian.Uint32(body)
	sections := body[4:]
	if flags&mongosignin.FlagChecksumPresent != 0 {
		if len(sections) < 4 {
			return 0, nil, nil, errors.New("accessgateway: an OP_MSG checksum is missing")
		}
		sections = sections[:len(sections)-4]
	}
	for len(sections) > 0 {
		kind := sections[0]
		if len(sections) < 5 {
			return 0, nil, nil, errors.New("accessgateway: an OP_MSG section is short")
		}
		size := int(binary.LittleEndian.Uint32(sections[1:]))
		if size < 4 || size > len(sections)-1 {
			return 0, nil, nil, errors.New("accessgateway: an OP_MSG section runs past its message")
		}
		switch kind {
		case 0:
			if doc != nil {
				return 0, nil, nil, errors.New("accessgateway: an OP_MSG has two body sections")
			}
			doc = sections[1 : 1+size]
		case 1:
			rest = append(rest, sections[:1+size]...)
		default:
			return 0, nil, nil, errors.New("accessgateway: an OP_MSG section has an unknown kind")
		}
		sections = sections[1+size:]
	}
	if doc == nil {
		return 0, nil, nil, errors.New("accessgateway: an OP_MSG has no body section")
	}
	return flags, doc, rest, nil
}

// commandName is a command document's first key.
func commandName(doc []byte) (string, []mongosignin.Element, error) {
	elems, err := mongosignin.Elements(doc)
	if err != nil {
		return "", nil, err
	}
	if len(elems) == 0 {
		return "", nil, errors.New("accessgateway: an empty MongoDB command")
	}
	return elems[0].Key, elems, nil
}

// stripHandshake rebuilds a handshake document without the fields the
// gateway removes; it reports whether anything was removed.
func stripHandshake(doc []byte, elems []mongosignin.Element) ([]byte, bool) {
	out := make([]byte, 4, len(doc))
	removed := false
	for _, e := range elems {
		if mongoHandshakeStrip[e.Key] {
			removed = true
			continue
		}
		out = append(out, e.Raw...)
	}
	if !removed {
		return doc, false
	}
	out = append(out, 0)
	binary.LittleEndian.PutUint32(out, uint32(len(out))) // #nosec G115 -- bounded by the message it came from (CWE-190)
	return out, true
}

func isHandshake(name string) bool {
	switch strings.ToLower(name) {
	case "hello", "ismaster":
		return true
	}
	return false
}

// requests forwards the client's messages, reading each command first.
func (m *mongoRelay) requests(server io.Writer, client io.Reader) error {
	for {
		requestID, responseTo, opCode, body, err := readMongoMessage(client)
		if err != nil {
			return err
		}
		switch opCode {
		case mongosignin.OpMsg:
			flags, doc, rest, err := opMsgSections(body)
			if err != nil {
				return err
			}
			name, elems, err := commandName(doc)
			if err != nil {
				return err
			}
			if mongoRefused[strings.ToLower(name)] {
				m.record("mongo", "refused", name)
				if flags&mongosignin.FlagMoreToCome != 0 {
					continue // the client expects no reply
				}
				if err := m.refuse(requestID, name); err != nil {
					return err
				}
				continue
			}
			if isHandshake(name) {
				if stripped, changed := stripHandshake(doc, elems); changed {
					// The rebuilt message carries no checksum: the one it
					// had covered the removed fields.
					flags &^= mongosignin.FlagChecksumPresent
					body = binary.LittleEndian.AppendUint32(nil, flags)
					body = append(append(append(body, 0), stripped...), rest...)
					doc = stripped
				}
			}
			m.record("mongo", "command", mongoRender(doc))
			if _, err := server.Write(mongoMessage(requestID, responseTo, opCode, body)); err != nil {
				return err
			}
		case mongosignin.OpQuery:
			// Only a driver's first handshake still arrives as OP_QUERY: a
			// hello or isMaster on a $cmd collection.
			stripped, err := m.legacyHandshake(body)
			if err != nil {
				return err
			}
			if _, err := server.Write(mongoMessage(requestID, responseTo, opCode, stripped)); err != nil {
				return err
			}
		default:
			// OP_COMPRESSED (never negotiated here) and the removed legacy
			// operations.
			return errMongoMessage
		}
	}
}

// legacyHandshake reads an OP_QUERY handshake and returns its body without
// the fields the gateway removes; anything else is refused.
func (m *mongoRelay) legacyHandshake(body []byte) ([]byte, error) {
	if len(body) < 4 {
		return nil, errMongoMessage
	}
	nameEnd := -1
	for i := 4; i < len(body); i++ {
		if body[i] == 0 {
			nameEnd = i
			break
		}
	}
	if nameEnd < 0 || len(body) < nameEnd+1+8+5 || !strings.HasSuffix(string(body[4:nameEnd]), ".$cmd") {
		return nil, errMongoMessage
	}
	queryStart := nameEnd + 1 + 8
	size := int(binary.LittleEndian.Uint32(body[queryStart:]))
	if size < 5 || queryStart+size > len(body) {
		return nil, errMongoMessage
	}
	doc := body[queryStart : queryStart+size]
	name, elems, err := commandName(doc)
	if err != nil || !isHandshake(name) {
		return nil, errMongoMessage
	}
	stripped, _ := stripHandshake(doc, elems)
	m.record("mongo", "command", mongoRender(stripped))
	out := append(append([]byte(nil), body[:queryStart]...), stripped...)
	return append(out, body[queryStart+size:]...), nil
}

// refuse answers a refused command as the server would refuse it.
func (m *mongoRelay) refuse(requestID int32, name string) error {
	doc := mongosignin.Encode([]mongosignin.E{{Key: "ok", Value: float64(0)},
		{Key: "errmsg", Value: name + " is refused: the access gateway signs in as the session's user"},
		{Key: "code", Value: int32(13)}, {Key: "codeName", Value: "Unauthorized"}})
	body := append([]byte{0, 0, 0, 0, 0}, doc...)
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	_, err := m.client.Write(mongoMessage(-m.ids.Add(1), requestID, mongosignin.OpMsg, body))
	return err
}

// replies forwards the server's messages to the client, recording each.
func (m *mongoRelay) replies(server io.Reader) error {
	for {
		requestID, responseTo, opCode, body, err := readMongoMessage(server)
		if err != nil {
			return err
		}
		switch opCode {
		case mongosignin.OpMsg:
			if _, doc, _, err := opMsgSections(body); err == nil {
				m.record("result", "reply", mongoRender(doc))
			}
		case mongosignin.OpReply:
			m.record("result", "reply", "(handshake reply)")
		}
		m.clientMu.Lock()
		_, err = m.client.Write(mongoMessage(requestID, responseTo, opCode, body))
		m.clientMu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (m *mongoRelay) record(name, kind, text string) {
	if m.rec != nil {
		m.rec.event(name, kind, text, 0)
	}
}

// mongoRender renders a document as compact text under mongoRecordText,
// each value cut at mongoRecordValue, binary values by their size.
func mongoRender(doc []byte) string {
	var b strings.Builder
	renderMongoDoc(&b, doc, false, 0)
	if b.Len() > mongoRecordText {
		return b.String()[:mongoRecordText] + "[truncated]"
	}
	return b.String()
}

func renderMongoDoc(b *strings.Builder, doc []byte, array bool, depth int) {
	elems, err := mongosignin.Elements(doc)
	if err != nil || depth > mongoRecordMaxDepth {
		b.WriteString("?")
		return
	}
	open, closing := "{", "}"
	if array {
		open, closing = "[", "]"
	}
	b.WriteString(open)
	for i, e := range elems {
		if b.Len() > mongoRecordText {
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		if !array {
			b.WriteString(e.Key + ": ")
		}
		renderMongoValue(b, e, depth)
	}
	b.WriteString(closing)
}

func renderMongoValue(b *strings.Builder, e mongosignin.Element, depth int) {
	switch e.Type {
	case mongosignin.TypeString:
		s, _ := e.Text()
		if len(s) > mongoRecordValue {
			s = s[:mongoRecordValue] + "...<" + strconv.Itoa(len(s)) + " bytes>"
		}
		b.WriteString(strconv.Quote(s))
	case mongosignin.TypeDouble:
		f, _ := e.Number()
		if f == math.Trunc(f) && math.Abs(f) < 1e15 {
			b.WriteString(strconv.FormatFloat(f, 'f', 1, 64))
		} else {
			b.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
		}
	case mongosignin.TypeInt32, mongosignin.TypeInt64:
		f, _ := e.Number()
		b.WriteString(strconv.FormatInt(int64(f), 10))
	case mongosignin.TypeBool:
		b.WriteString(strconv.FormatBool(e.Bool()))
	case mongosignin.TypeNull:
		b.WriteString("null")
	case mongosignin.TypeDocument:
		renderMongoDoc(b, e.Value, false, depth+1)
	case mongosignin.TypeArray:
		renderMongoDoc(b, e.Value, true, depth+1)
	case mongosignin.TypeObjectID:
		b.WriteString("ObjectId(" + hex.EncodeToString(e.Value) + ")")
	case mongosignin.TypeDateTime:
		ms := int64(binary.LittleEndian.Uint64(e.Value)) // #nosec G115 -- a BSON datetime's two's-complement bits (CWE-190)
		b.WriteString("Date(" + time.UnixMilli(ms).UTC().Format(time.RFC3339Nano) + ")")
	case mongosignin.TypeBinary:
		data, _ := e.Binary()
		b.WriteString("<" + strconv.Itoa(len(data)) + " bytes>")
	default:
		b.WriteString("<type 0x" + strconv.FormatUint(uint64(e.Type), 16) + ">")
	}
}
