// SPDX-License-Identifier: BUSL-1.1

// Package rdp isolates upstream desktop authentication in a bounded native child.
// Its wire carries pixels and input, never an RDP credential to an operator.
package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// MaxPixels bounds a single uncompressed BGRX framebuffer.
const MaxPixels = 1280 * 1024 * 4

var errProtocol = errors.New("rdp: invalid desktop packet")

// ErrClipboardRefused is the operator's clipboard under a reviewed policy that
// keeps it from the target (A269).
var ErrClipboardRefused = errors.New("rdp: clipboard to the target is not allowed")

// MaxClipboard bounds clipboard text in either direction (A269).
const MaxClipboard = 65536

// Target is public, reviewed desktop routing. TLSOnly is for explicitly configured
// xrdp installations; Windows targets use network-level authentication by default.
type Target struct {
	Address           string
	Username          string
	Domain            string
	CertificateSHA256 string
	Width             uint16
	Height            uint16
	TLSOnly           bool
	// ClipboardToTarget and ClipboardFromTarget are the reviewed clipboard
	// policy (A269); with neither, the clipboard channel is never loaded.
	ClipboardToTarget   bool
	ClipboardFromTarget bool
}

// Validate accepts bounded routing and an exact DER certificate SHA-256 pin.
func (t Target) Validate() error {
	host, port, err := net.SplitHostPort(t.Address)
	p, e := strconv.ParseUint(port, 10, 16)
	pin, pe := hex.DecodeString(t.CertificateSHA256)
	if err != nil || e != nil || p == 0 || len(host) == 0 || len(host) > 255 || strings.ContainsAny(host, "\x00\r\n/\\") || pe != nil || len(pin) != 32 || t.Width < 320 || t.Width > 1280 || t.Height < 200 || t.Height > 1024 {
		return errors.New("rdp: invalid route, certificate pin or desktop dimensions")
	}
	for _, s := range []string{t.Username, t.Domain} {
		if len(s) > 128 || strings.ContainsAny(s, "\x00\r\n") {
			return errors.New("rdp: invalid account name")
		}
	}
	if t.Username == "" {
		return errors.New("rdp: account name is required")
	}
	return nil
}

// Stream is one upstream attempt. A ready packet means RDP connected; TLS-only
// servers may still display an authentication error instead of a desktop.
// One reader and concurrent Input/Close calls are supported.
type Stream struct {
	pid      int
	input    io.WriteCloser
	output   io.ReadCloser
	stop     func() error
	toTarget bool
	mu       sync.Mutex
	once     sync.Once
	closeErr error
}

// Start executes the explicitly installed helper. The password is copied into a
// locked request, erased immediately after private pipe delivery, and never used
// in argv, environment, logs or an error. Call Close to kill and reap the child.
func Start(ctx context.Context, helper string, target Target, password []byte) (*Stream, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if len(password) == 0 || len(password) > 1024 {
		return nil, errors.New("rdp: invalid password length")
	}
	for _, b := range password {
		if b == 0 {
			return nil, errors.New("rdp: password contains NUL")
		}
	}
	return startNative(ctx, helper, target, password)
}

func request(t Target, password []byte) (*secret.Buffer, error) {
	host, port, _ := net.SplitHostPort(t.Address)
	p, _ := strconv.ParseUint(port, 10, 16)
	fields := [][]byte{[]byte(host), []byte(t.Username), []byte(t.Domain), []byte(t.CertificateSHA256), password}
	size := 15
	for _, f := range fields {
		size += 2 + len(f)
	}
	b, err := secret.New(size)
	if err != nil {
		return nil, err
	}
	wire := b.Bytes()
	copy(wire, "TRDP0001")
	binary.BigEndian.PutUint16(wire[8:10], uint16(p))
	binary.BigEndian.PutUint16(wire[10:12], t.Width)
	binary.BigEndian.PutUint16(wire[12:14], t.Height)
	if t.TLSOnly {
		wire[14] |= 1
	}
	if t.ClipboardToTarget {
		wire[14] |= 2
	}
	if t.ClipboardFromTarget {
		wire[14] |= 4
	}
	at := 15
	for _, f := range fields {
		if len(f) > 65535 {
			b.Destroy()
			return nil, errors.New("rdp: private request field too large")
		}
		wire[at] = byte((len(f) >> 8) & 255)
		wire[at+1] = byte(len(f) & 255)
		at += 2
		copy(wire[at:], f)
		at += len(f)
	}
	return b, nil
}

// Packet is a transport-ready notice (1), a full BGRX framebuffer (2) or the
// target's clipboard text (4, UTF-8, only under a policy that lets it out).
// Pixel content is personal data, not a text transcript with regex masking.
type Packet struct {
	Kind          byte
	Width, Height uint16
	Pixels        []byte
	Text          []byte
}

// DecodePacket validates one bounded native frame. It does not retain data on error.
func DecodePacket(raw []byte) (Packet, error) {
	if len(raw) >= 2 && raw[0] == 4 {
		if len(raw)-1 > MaxClipboard {
			return Packet{}, errProtocol
		}
		return Packet{Kind: 4, Text: raw[1:]}, nil
	}
	if len(raw) < 5 || len(raw) > MaxPixels+5 || (raw[0] != 1 && raw[0] != 2) {
		return Packet{}, errProtocol
	}
	w, h := binary.BigEndian.Uint16(raw[1:3]), binary.BigEndian.Uint16(raw[3:5])
	if w < 320 || w > 1280 || h < 200 || h > 1024 {
		return Packet{}, errProtocol
	}
	size := 5
	if raw[0] == 2 {
		size += int(w) * int(h) * 4
	}
	if len(raw) != size {
		return Packet{}, errProtocol
	}
	return Packet{Kind: raw[0], Width: w, Height: h, Pixels: raw[5:]}, nil
}

// ReadPacket reads exactly one bounded message. Native diagnostic output is never
// passed to callers; a fixed failure packet contains no text from the server.
func (s *Stream) ReadPacket() (Packet, error) {
	var head [4]byte
	if _, err := io.ReadFull(s.output, head[:]); err != nil {
		return Packet{}, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n < 1 || n > MaxPixels+5 {
		return Packet{}, errProtocol
	}
	raw := make([]byte, int(n))
	if _, err := io.ReadFull(s.output, raw); err != nil {
		return Packet{}, err
	}
	if raw[0] == 3 {
		if len(raw) == 2 && raw[1] >= 70 && raw[1] <= 73 {
			return Packet{}, fmt.Errorf("rdp: upstream connection failed (code %d)", raw[1])
		}
		return Packet{}, errors.New("rdp: upstream connection failed")
	}
	return DecodePacket(raw)
}

// Input sends only keyboard (3), Unicode keyboard (4), or pointer (5) messages.
// Clipboard, drive, printer and arbitrary channel messages have no wire form.
func (s *Stream) Input(kind byte, flags, a, b uint16) error {
	switch kind {
	case 3:
		if flags & ^uint16(0x8100) != 0 || a > 255 || b != 0 {
			return errProtocol
		}
	case 4:
		if flags & ^uint16(0x8000) != 0 || b != 0 || (a >= 0xd800 && a <= 0xdfff) {
			return errProtocol
		}
	case 5:
		if a >= 1280 || b >= 1024 || flags & ^uint16(0xfbff) != 0 {
			return errProtocol
		}
	default:
		return errProtocol
	}
	var wire [7]byte
	wire[0] = kind
	binary.BigEndian.PutUint16(wire[1:3], flags)
	binary.BigEndian.PutUint16(wire[3:5], a)
	binary.BigEndian.PutUint16(wire[5:7], b)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.input.Write(wire[:])
	return err
}

// Clipboard offers the operator's text (UTF-8) to the target's clipboard when
// the reviewed policy sends it there (A269); otherwise ErrClipboardRefused.
func (s *Stream) Clipboard(text []byte) error {
	if !s.toTarget {
		return ErrClipboardRefused
	}
	if len(text) == 0 || len(text) > MaxClipboard || bytes.IndexByte(text, 0) >= 0 {
		return errProtocol
	}
	n := uint32(len(text)) // #nosec G115 -- len(text) is at most MaxClipboard (CWE-190)
	wire := make([]byte, 7+len(text))
	defer secret.Wipe(wire)
	wire[0] = 6
	binary.BigEndian.PutUint16(wire[1:3], uint16(n>>16))
	binary.BigEndian.PutUint16(wire[3:5], uint16(n&0xffff))
	copy(wire[7:], text)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.input.Write(wire)
	return err
}

// Close ends the private process and waits for its address space to disappear.
func (s *Stream) Close() error {
	s.once.Do(func() { _ = s.input.Close(); _ = s.output.Close(); s.closeErr = s.stop() })
	return s.closeErr
}
