// SPDX-License-Identifier: BUSL-1.1

package slackapp

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

// A277: Slack's Socket Mode. trstctl opens the connection — an outbound
// WebSocket to the URL apps.connections.open returns for the app-level token
// — and Slack delivers slash commands and button presses over it, so no
// inbound endpoint is exposed. Each envelope is acknowledged by its id. The
// upgrade runs through the client's own guarded HTTP transport; the framing
// is RFC 6455's, client side.

const (
	// maxSocketMessage bounds one Socket Mode message.
	maxSocketMessage = 1 << 20
	opContinuation   = 0x0
	opText           = 0x1
	opBinary         = 0x2
	opClose          = 0x8
	opPing           = 0x9
	opPong           = 0xA
)

// ErrSocketClosed is a connection Slack (or the network) closed.
var ErrSocketClosed = errors.New("slackapp: socket mode connection closed")

// SocketEnvelope is one Socket Mode message: hello, disconnect, or a
// delivery (slash_commands, interactive, events_api) to acknowledge.
type SocketEnvelope struct {
	EnvelopeID             string          `json:"envelope_id,omitempty"`
	Type                   string          `json:"type"`
	Payload                json.RawMessage `json:"payload,omitempty"`
	Reason                 string          `json:"reason,omitempty"`
	AcceptsResponsePayload bool            `json:"accepts_response_payload,omitempty"`
}

// OpenSocket asks Slack for a Socket Mode URL with the app-level token
// (apps.connections.open).
func (c Client) OpenSocket(ctx context.Context, appToken []byte) (string, error) {
	var out struct {
		OK    bool   `json:"ok"`
		URL   string `json:"url"`
		Error string `json:"error"`
	}
	if err := c.call(ctx, appToken, http.MethodPost, "apps.connections.open", nil, &out); err != nil {
		return "", err
	}
	if !out.OK || out.URL == "" {
		return "", fmt.Errorf("%w: apps.connections.open: %s", ErrRefused, out.Error)
	}
	return out.URL, nil
}

// SocketConn is an open Socket Mode connection.
type SocketConn struct {
	rw io.ReadWriteCloser
	br *bufio.Reader
	mu sync.Mutex // serializes writes
}

// DialSocket upgrades to a WebSocket at a wss:// (or, for a stand-in, ws://)
// URL through the client's HTTP transport, checking the server's accept
// value.
func (c Client) DialSocket(ctx context.Context, wsURL string) (*SocketConn, error) {
	if c.Doer == nil {
		return nil, errors.New("slackapp: no HTTP client")
	}
	target := wsURL
	switch {
	case strings.HasPrefix(target, "wss://"):
		target = "https://" + strings.TrimPrefix(target, "wss://")
	case strings.HasPrefix(target, "ws://"):
		target = "http://" + strings.TrimPrefix(target, "ws://")
	default:
		return nil, errors.New("slackapp: a socket mode URL is wss://")
	}
	nonce, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	resp, err := c.Doer.Do(req)
	if err != nil {
		return nil, err
	}
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if resp.StatusCode != http.StatusSwitchingProtocols || !ok || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != crypto.WebSocketAccept(key) {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: the socket mode upgrade was refused (HTTP %d)", ErrRefused, resp.StatusCode)
	}
	return &SocketConn{rw: rw, br: bufio.NewReader(rw)}, nil
}

// Close closes the connection.
func (s *SocketConn) Close() error {
	_ = s.write(opClose, nil)
	return s.rw.Close()
}

// Next reads the next envelope, answering pings and Slack's close.
func (s *SocketConn) Next() (SocketEnvelope, error) {
	var message []byte
	for {
		fin, op, payload, err := s.readFrame()
		if err != nil {
			return SocketEnvelope{}, err
		}
		switch op {
		case opPing:
			if err := s.write(opPong, payload); err != nil {
				return SocketEnvelope{}, err
			}
			continue
		case opPong:
			continue
		case opClose:
			_ = s.write(opClose, nil)
			return SocketEnvelope{}, ErrSocketClosed
		case opText, opBinary, opContinuation:
			if len(message)+len(payload) > maxSocketMessage {
				return SocketEnvelope{}, errors.New("slackapp: a socket mode message exceeds its bound")
			}
			message = append(message, payload...)
		default:
			return SocketEnvelope{}, errors.New("slackapp: an unknown websocket frame")
		}
		if !fin {
			continue
		}
		var env SocketEnvelope
		if err := json.Unmarshal(message, &env); err != nil {
			return SocketEnvelope{}, errors.New("slackapp: a socket mode message is not an envelope")
		}
		return env, nil
	}
}

// Ack acknowledges an envelope; a slash command's acknowledgement can carry
// the reply.
func (s *SocketConn) Ack(envelopeID string, payload any) error {
	body := map[string]any{"envelope_id": envelopeID}
	if payload != nil {
		body["payload"] = payload
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return s.write(opText, raw)
}

func (s *SocketConn) readFrame() (bool, byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(s.br, head[:]); err != nil {
		return false, 0, nil, ErrSocketClosed
	}
	fin, op := head[0]&0x80 != 0, head[0]&0x0F
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(s.br, ext[:]); err != nil {
			return false, 0, nil, ErrSocketClosed
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(s.br, ext[:]); err != nil {
			return false, 0, nil, ErrSocketClosed
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > maxSocketMessage {
		return false, 0, nil, errors.New("slackapp: a websocket frame exceeds its bound")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(s.br, mask[:]); err != nil {
			return false, 0, nil, ErrSocketClosed
		}
	}
	payload := make([]byte, int(length)) // #nosec G115 -- bounded by maxSocketMessage above (CWE-190)
	if _, err := io.ReadFull(s.br, payload); err != nil {
		return false, 0, nil, ErrSocketClosed
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, op, payload, nil
}

// write sends one final frame, masked as a client must.
func (s *SocketConn) write(op byte, payload []byte) error {
	mask, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	frame := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		frame = append(frame, 0x80|byte(n))
	case n <= 0xFFFF:
		frame = append(frame, 0x80|126)
		frame = binary.BigEndian.AppendUint16(frame, uint16(n)) // #nosec G115 -- n <= 0xFFFF here (CWE-190)
	default:
		frame = append(frame, 0x80|127)
		frame = binary.BigEndian.AppendUint64(frame, uint64(n)) // #nosec G115 -- a length is non-negative (CWE-190)
	}
	frame = append(frame, mask...)
	start := len(frame)
	frame = append(frame, payload...)
	for i := range payload {
		frame[start+i] ^= mask[i%4]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.rw.Write(frame)
	return err
}

// PostResponse posts a reply to an interaction's response_url (ephemeral to
// the person who pressed).
func (c Client) PostResponse(ctx context.Context, responseURL, text string) error {
	raw, err := json.Marshal(map[string]any{"response_type": "ephemeral", "replace_original": false, "text": text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURL, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = c.do(req)
	return err
}
