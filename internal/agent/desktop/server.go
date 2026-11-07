// SPDX-License-Identifier: BUSL-1.1

// Package desktop renders an upstream desktop over an already authenticated
// gateway connection. RFB is anonymous inside that ticket/mTLS tunnel; never
// expose this renderer as an unauthenticated public listener.
package desktop

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/rdp"
	"trstctl.com/trstctl/internal/crypto/secret"
)

var (
	ErrProtocol  = errors.New("desktop: invalid RFB message")
	ErrClipboard = errors.New("desktop: clipboard transfer is disabled")
	// maxClientCutText bounds one viewer clipboard message the renderer reads
	// in order to refuse it.
	maxClientCutText uint32 = 1 << 20
	ErrCapacity             = errors.New("desktop: input or update queue capacity exceeded")
	ErrDeadline             = errors.New("desktop: a session deadline is required")
)

// Backend carries only pixels and input after upstream credential injection.
type Backend interface {
	ReadPacket() (rdp.Packet, error)
	Input(kind byte, flags, a, b uint16) error
	Close() error
}

// Record accepts each full framebuffer before it can be sent to a viewer. It
// must backpressure or fail; it must not discard evidence or retain Pixels.
type Record func(context.Context, rdp.Packet) error

// Event is one entry of a desktop session's index (A269): what happened —
// never pixels, keystrokes or clipboard content.
type Event struct {
	Kind   string
	Detail string
}

// Events receives each session event as it happens; an error ends the session.
type Events func(context.Context, Event) error

// clipboardBackend is a backend that can offer the operator's clipboard to the
// target under its reviewed policy (A269).
type clipboardBackend interface {
	Clipboard(text []byte) error
}

type pixelFormat struct{ bits, endian byte }
type updateRequest struct {
	x, y, w, h  uint16
	incremental bool
}
type viewerState struct {
	mu            sync.Mutex
	format        pixelFormat
	width, height uint16
}

// Serve renders one desktop on an admitted tunnel, closing and reaping the
// backend before returning. The caller must supply a session-bounded context.
// Clipboard and arbitrary channels have no upstream forwarding path.
func Serve(ctx context.Context, conn net.Conn, backend Backend, record Record) error {
	return ServeEvents(ctx, conn, backend, record, nil)
}

// ServeEvents is Serve with the session's index events (A269).
func ServeEvents(ctx context.Context, conn net.Conn, backend Backend, record Record, events Events) error {
	_, bounded := ctx.Deadline()
	ctx, cancel := context.WithCancel(ctx)
	var once sync.Once
	done := make(chan struct{})
	stop := func() { once.Do(func() { cancel(); close(done); _ = conn.Close(); _ = backend.Close() }) }
	defer stop()
	if !bounded {
		return ErrDeadline
	}
	timer := time.AfterFunc(15*time.Second, stop)
	defer timer.Stop()
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	ready, err := backend.ReadPacket()
	if err != nil {
		return err
	}
	if ready.Kind != 1 || ready.Width < 320 || ready.Width > 1280 || ready.Height < 200 || ready.Height > 1024 || len(ready.Pixels) != 0 {
		return ErrProtocol
	}
	state := &viewerState{width: ready.Width, height: ready.Height, format: pixelFormat{bits: 32}}
	if err = handshake(conn, state); err != nil {
		return err
	}
	timer.Stop()
	frames := make(chan rdp.Packet, 1)
	requests := make(chan updateRequest, 4)
	failures := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	defer func() {
		stop()
		workers.Wait()
		for {
			select {
			case p := <-frames:
				secret.Wipe(p.Pixels)
				secret.Wipe(p.Text)
			default:
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		err := readViewer(ctx, conn, state, backend, requests, events)
		failures <- err
		stop()
	}()
	go func() {
		defer workers.Done()
		for {
			p, e := backend.ReadPacket()
			if e != nil {
				failures <- e
				stop()
				return
			}
			select {
			case frames <- p:
			case <-done:
				secret.Wipe(p.Pixels)
				secret.Wipe(p.Text)
				return
			case <-ctx.Done():
				secret.Wipe(p.Pixels)
				secret.Wipe(p.Text)
				return
			}
		}
	}()
	var current rdp.Packet
	defer func() { secret.Wipe(current.Pixels) }()
	var pending *updateRequest
	var revision, sent uint64
	for {
		var requestQueue <-chan updateRequest
		if pending == nil {
			requestQueue = requests
		}
		select {
		case <-ctx.Done():
			select {
			case failure := <-failures:
				return failure
			default:
				return ctx.Err()
			}
		case err = <-failures:
			return err
		case req := <-requestQueue:
			pending = &req
		case p := <-frames:
			if p.Kind == 4 {
				// The target's clipboard, already limited by the reviewed policy
				// in the native helper: hand it to the viewer and index its length.
				n := len(p.Text)
				deadline := time.Now().Add(30 * time.Second)
				if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
					deadline = d
				}
				err = conn.SetWriteDeadline(deadline)
				if err == nil {
					err = writeCutText(conn, p.Text)
				}
				secret.Wipe(p.Text)
				if err != nil {
					return err
				}
				if events != nil {
					if err = events(ctx, Event{Kind: "clipboard_from_target", Detail: fmt.Sprintf("from_target %d bytes", n)}); err != nil {
						return err
					}
				}
				continue
			}
			if p.Kind != 2 || p.Width != ready.Width || p.Height != ready.Height || len(p.Pixels) != int(p.Width)*int(p.Height)*4 {
				secret.Wipe(p.Pixels)
				return ErrProtocol
			}
			if record != nil {
				if err = record(ctx, p); err != nil {
					secret.Wipe(p.Pixels)
					return err
				}
			}
			secret.Wipe(current.Pixels)
			current = p
			revision++
		}
		if pending != nil && current.Kind == 2 && (!pending.incremental || revision != sent) {
			state.mu.Lock()
			format := state.format
			state.mu.Unlock()
			deadline := time.Now().Add(30 * time.Second)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			if err = conn.SetWriteDeadline(deadline); err != nil {
				return err
			}
			if err = writeUpdate(conn, current, *pending, format); err != nil {
				return err
			}
			pending = nil
			sent = revision
		}
	}
}

func handshake(conn net.Conn, state *viewerState) error {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	if err := writeAll(conn, []byte("RFB 003.008\n")); err != nil {
		return err
	}
	var version [12]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return err
	}
	if string(version[:]) != "RFB 003.008\n" {
		return ErrProtocol
	}
	if err := writeAll(conn, []byte{1, 1}); err != nil {
		return err
	}
	var choice [1]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return err
	}
	if choice[0] != 1 {
		return ErrProtocol
	}
	if err := writeAll(conn, []byte{0, 0, 0, 0}); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return err
	}
	if choice[0] > 1 {
		return ErrProtocol
	}
	const desktopName = "trstctl approved desktop"
	name := []byte(desktopName)
	var init [24]byte
	binary.BigEndian.PutUint16(init[0:2], state.width)
	binary.BigEndian.PutUint16(init[2:4], state.height)
	copy(init[4:20], []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0})
	binary.BigEndian.PutUint32(init[20:24], uint32(len(desktopName)))
	if err := writeAll(conn, init[:]); err != nil {
		return err
	}
	if err := writeAll(conn, name); err != nil {
		return err
	}
	return conn.SetDeadline(time.Time{})
}

func readViewer(ctx context.Context, conn net.Conn, state *viewerState, backend Backend, requests chan<- updateRequest, events Events) error {
	var buttons byte
	messages := 0
	window := time.Now()
	for {
		var kind [1]byte
		if _, err := io.ReadFull(conn, kind[:]); err != nil {
			return err
		}
		if time.Since(window) >= time.Second {
			messages = 0
			window = time.Now()
		}
		messages++
		if messages > 4096 {
			return ErrCapacity
		}
		switch kind[0] {
		case 0:
			var raw [19]byte
			if _, err := io.ReadFull(conn, raw[:]); err != nil {
				return err
			}
			f, err := decodePixelFormat(raw[3:])
			if err != nil {
				return err
			}
			state.mu.Lock()
			state.format = f
			state.mu.Unlock()
		case 2:
			var head [3]byte
			if _, err := io.ReadFull(conn, head[:]); err != nil {
				return err
			}
			n := binary.BigEndian.Uint16(head[1:3])
			if n > 128 {
				return ErrCapacity
			}
			var encodings [512]byte
			if _, err := io.ReadFull(conn, encodings[:int(n)*4]); err != nil {
				return err
			}
			// RFB requires every viewer to understand Raw, even when omitted from this
			// preference list. Other encodings and extension channels are not enabled.
		case 3:
			var raw [9]byte
			if _, err := io.ReadFull(conn, raw[:]); err != nil {
				return err
			}
			req, err := decodeRequest(raw[:], state.width, state.height)
			if err != nil {
				return err
			}
			select {
			case requests <- req:
			default:
				return ErrCapacity
			}
		case 4:
			var raw [7]byte
			if _, err := io.ReadFull(conn, raw[:]); err != nil {
				return err
			}
			if raw[0] > 1 {
				return ErrProtocol
			}
			k, f, code, err := keyInput(binary.BigEndian.Uint32(raw[3:7]), raw[0] == 1)
			if err != nil {
				return err
			}
			if err = backend.Input(k, f, code, 0); err != nil {
				return err
			}
		case 5:
			var raw [5]byte
			if _, err := io.ReadFull(conn, raw[:]); err != nil {
				return err
			}
			x, y := binary.BigEndian.Uint16(raw[1:3]), binary.BigEndian.Uint16(raw[3:5])
			if raw[0]&0xe0 != 0 || x >= state.width || y >= state.height {
				return ErrProtocol
			}
			if err := backend.Input(5, 0x0800, x, y); err != nil {
				return err
			}
			for i, flag := range []uint16{0x1000, 0x4000, 0x2000} {
				mask := byte(1 << i)
				if (buttons^raw[0])&mask != 0 {
					if raw[0]&mask != 0 {
						flag |= 0x8000
					}
					if err := backend.Input(5, flag, x, y); err != nil {
						return err
					}
				}
			}
			if raw[0]&8 != 0 && buttons&8 == 0 {
				if err := backend.Input(5, 0x0278, x, y); err != nil {
					return err
				}
			}
			if raw[0]&16 != 0 && buttons&16 == 0 {
				if err := backend.Input(5, 0x0388, x, y); err != nil {
					return err
				}
			}
			buttons = raw[0]
		case 6:
			// A viewer's clipboard reaches the target only under a reviewed
			// policy that sends it there; otherwise its text is read only to
			// refuse it and wiped. Either way the index records the length,
			// never the content, and the session continues.
			n, text, err := readClientCutText(conn)
			if err != nil {
				return err
			}
			kind := "clipboard_refused"
			if cb, ok := backend.(clipboardBackend); ok && len(text) > 0 {
				utf8 := latin1ToUTF8(text)
				err = cb.Clipboard(utf8)
				secret.Wipe(utf8)
				switch {
				case err == nil:
					kind = "clipboard_to_target"
				case !errors.Is(err, rdp.ErrClipboardRefused):
					secret.Wipe(text)
					return err
				}
			}
			secret.Wipe(text)
			if events != nil {
				if err := events(ctx, Event{Kind: kind, Detail: fmt.Sprintf("to_target %d bytes", n)}); err != nil {
					return err
				}
			}
		default:
			return ErrProtocol
		}
	}
}

func decodePixelFormat(raw []byte) (pixelFormat, error) {
	if len(raw) != 16 || raw[2] > 1 || raw[3] != 1 {
		return pixelFormat{}, ErrProtocol
	}
	r, g, b := binary.BigEndian.Uint16(raw[4:6]), binary.BigEndian.Uint16(raw[6:8]), binary.BigEndian.Uint16(raw[8:10])
	if raw[0] == 32 && raw[1] == 24 && r == 255 && g == 255 && b == 255 && raw[10] == 16 && raw[11] == 8 && raw[12] == 0 {
		return pixelFormat{32, raw[2]}, nil
	}
	if raw[0] == 16 && raw[1] == 16 && r == 31 && g == 63 && b == 31 && raw[10] == 11 && raw[11] == 5 && raw[12] == 0 {
		return pixelFormat{16, raw[2]}, nil
	}
	return pixelFormat{}, ErrProtocol
}
func decodeRequest(raw []byte, width, height uint16) (updateRequest, error) {
	if len(raw) != 9 || raw[0] > 1 {
		return updateRequest{}, ErrProtocol
	}
	req := updateRequest{binary.BigEndian.Uint16(raw[1:3]), binary.BigEndian.Uint16(raw[3:5]), binary.BigEndian.Uint16(raw[5:7]), binary.BigEndian.Uint16(raw[7:9]), raw[0] == 1}
	if req.w == 0 || req.h == 0 || uint32(req.x)+uint32(req.w) > uint32(width) || uint32(req.y)+uint32(req.h) > uint32(height) {
		return updateRequest{}, ErrProtocol
	}
	return req, nil
}
func keyInput(key uint32, down bool) (byte, uint16, uint16, error) {
	var flags uint16
	if !down {
		flags = 0x8000
	}
	if key >= 32 && key <= 255 {
		return 4, flags, uint16(key & 255), nil
	}
	if key >= 0x01000100 && key <= 0x0100ffff {
		code := uint16(key & 65535)
		if code >= 0xd800 && code <= 0xdfff {
			return 0, 0, 0, ErrProtocol
		}
		return 4, flags, code, nil
	}
	scans := map[uint32]uint16{0xff08: 0x0e, 0xff09: 0x0f, 0xff0d: 0x1c, 0xff1b: 1, 0xff50: 0x147, 0xff51: 0x14b, 0xff52: 0x148, 0xff53: 0x14d, 0xff54: 0x150, 0xff55: 0x149, 0xff56: 0x151, 0xff57: 0x14f, 0xff63: 0x152, 0xffff: 0x153, 0xffe5: 0x3a, 0xff7f: 0x45, 0xff14: 0x46, 0xfe20: 0x0f, 0xffe1: 0x2a, 0xffe2: 0x36, 0xffe3: 0x1d, 0xffe4: 0x11d, 0xffe9: 0x38, 0xffea: 0x138, 0xffeb: 0x15b, 0xffec: 0x15c, 0xffbe: 0x3b, 0xffbf: 0x3c, 0xffc0: 0x3d, 0xffc1: 0x3e, 0xffc2: 0x3f, 0xffc3: 0x40, 0xffc4: 0x41, 0xffc5: 0x42, 0xffc6: 0x43, 0xffc7: 0x44, 0xffc8: 0x57, 0xffc9: 0x58}
	scan, ok := scans[key]
	if !ok {
		return 0, 0, 0, ErrProtocol
	}
	flags |= scan & 0x100
	return 3, flags, scan & 255, nil
}
func writeUpdate(w io.Writer, p rdp.Packet, req updateRequest, format pixelFormat) error {
	var header [16]byte
	header[3] = 1
	binary.BigEndian.PutUint16(header[4:6], req.x)
	binary.BigEndian.PutUint16(header[6:8], req.y)
	binary.BigEndian.PutUint16(header[8:10], req.w)
	binary.BigEndian.PutUint16(header[10:12], req.h)
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	var row [1280 * 4]byte
	bytesPerPixel := int(format.bits / 8)
	for y := int(req.y); y < int(req.y)+int(req.h); y++ {
		start := (y*int(p.Width) + int(req.x)) * 4
		for x := 0; x < int(req.w); x++ {
			in := p.Pixels[start+x*4 : start+x*4+4]
			out := row[x*bytesPerPixel : (x+1)*bytesPerPixel]
			if format.bits == 32 {
				value := uint32(in[2])<<16 | uint32(in[1])<<8 | uint32(in[0])
				if format.endian == 0 {
					binary.LittleEndian.PutUint32(out, value)
				} else {
					binary.BigEndian.PutUint32(out, value)
				}
			} else {
				value := (uint16(in[2])>>3)<<11 | (uint16(in[1])>>2)<<5 | uint16(in[0])>>3
				if format.endian == 0 {
					binary.LittleEndian.PutUint16(out, value)
				} else {
					binary.BigEndian.PutUint16(out, value)
				}
			}
		}
		if err := writeAll(w, row[:int(req.w)*bytesPerPixel]); err != nil {
			return err
		}
	}
	return nil
}
func writeAll(w io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

// readClientCutText reads one ClientCutText body (RFB 7.5.6). Text within
// the clipboard bound is returned for the caller to forward or refuse and
// wipe; longer text is read only to wipe it.
func readClientCutText(conn net.Conn) (uint32, []byte, error) {
	var head [7]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[3:7])
	if n > maxClientCutText {
		return 0, nil, ErrCapacity
	}
	if n <= rdp.MaxClipboard {
		text := make([]byte, n)
		if _, err := io.ReadFull(conn, text); err != nil {
			secret.Wipe(text)
			return 0, nil, err
		}
		return n, text, nil
	}
	const chunk = 4096
	var buf [chunk]byte
	defer secret.Wipe(buf[:])
	for left := n; left > 0; {
		k, err := io.ReadFull(conn, buf[:min(left, chunk)])
		secret.Wipe(buf[:k])
		if err != nil {
			return 0, nil, err
		}
		left -= uint32(k) // #nosec G115 -- k is at most chunk (4096) (CWE-190)
	}
	return n, nil, nil
}

// latin1ToUTF8 converts RFB clipboard text (ISO 8859-1) to UTF-8, dropping NUL.
func latin1ToUTF8(text []byte) []byte {
	out := make([]byte, 0, 2*len(text))
	for _, b := range text {
		switch {
		case b == 0:
		case b < 0x80:
			out = append(out, b)
		default:
			out = append(out, 0xc0|b>>6, 0x80|b&0x3f)
		}
	}
	return out
}

// utf8ToLatin1 converts the target's clipboard text to RFB's ISO 8859-1;
// characters outside it become '?'.
func utf8ToLatin1(text []byte) []byte {
	out := make([]byte, 0, len(text))
	for _, r := range string(text) {
		if r > 0xff {
			r = '?'
		}
		out = append(out, byte(r))
	}
	return out
}

// writeCutText sends the target's clipboard text to the viewer (RFB 7.6.4).
func writeCutText(w io.Writer, text []byte) error {
	latin := utf8ToLatin1(text)
	defer secret.Wipe(latin)
	head := []byte{3, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(head[4:8], uint32(len(latin))) // #nosec G115 -- the target's text is bounded by rdp.MaxClipboard (CWE-190)
	if err := writeAll(w, head); err != nil {
		return err
	}
	return writeAll(w, latin)
}
