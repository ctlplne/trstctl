// SPDX-License-Identifier: BUSL-1.1

package desktop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/rdp"
)

func TestDesktopProtocolBoundsAndPixelConversion(t *testing.T) {
	pf32 := []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}
	pf16 := []byte{16, 16, 1, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0}
	for _, raw := range [][]byte{pf32, pf16} {
		if _, e := decodePixelFormat(raw); e != nil {
			t.Fatal(e)
		}
	}
	for _, raw := range [][]byte{nil, pf32[:15], {8, 8, 0, 1, 0, 7, 0, 7, 0, 3, 0, 3, 6, 0, 0, 0}} {
		if _, e := decodePixelFormat(raw); e == nil {
			t.Fatal("unsupported pixel format accepted")
		}
	}
	if _, e := decodeRequest([]byte{0, 255, 255, 0, 0, 0, 2, 0, 1}, 800, 600); e == nil {
		t.Fatal("overflow rectangle accepted")
	}
	if _, e := decodeRequest([]byte{0, 0, 0, 0, 0, 0, 0, 0, 1}, 800, 600); e == nil {
		t.Fatal("empty rectangle accepted")
	}
	if k, f, c, e := keyInput(0xff51, false); e != nil || k != 3 || f != 0x8100 || c != 0x4b {
		t.Fatal("extended key translation failed")
	}
	if _, _, _, e := keyInput(0x0100d800, true); e == nil {
		t.Fatal("unpaired Unicode surrogate accepted")
	}
	p := rdp.Packet{Kind: 2, Width: 1, Height: 1, Pixels: []byte{128, 0, 0, 255}}
	var out bytes.Buffer
	if e := writeUpdate(&out, p, updateRequest{w: 1, h: 1}, pixelFormat{32, 0}); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out.Bytes()[16:], []byte{128, 0, 0, 0}) {
		t.Fatal("32-bit color order changed")
	}
	out.Reset()
	if e := writeUpdate(&out, p, updateRequest{w: 1, h: 1}, pixelFormat{16, 1}); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out.Bytes()[16:], []byte{0, 16}) {
		t.Fatal("RGB565 endian conversion changed")
	}
}

// A269: a viewer's clipboard is refused without ending the session: its text
// never reaches the target, the refusal is indexed without its content, and
// the next input still flows.
func TestDesktopClipboardRefusedAtRenderer(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	backend := &fixtureBackend{packets: make(chan rdp.Packet, 1), done: make(chan struct{})}
	backend.packets <- rdp.Packet{Kind: 1, Width: 320, Height: 200}
	indexed := make(chan Event, 2)
	result := make(chan error, 1)
	go func() {
		result <- ServeEvents(testContext(t), server, backend, nil, func(_ context.Context, e Event) error { indexed <- e; return nil })
	}()
	viewerHandshake(t, client)
	text := []byte("secret-from-the-operator")
	if len(text) != 24 {
		t.Fatal("fixture length")
	}
	cut := append([]byte{6, 0, 0, 0, 0, 0, 0, 24}, text...)
	if _, e := client.Write(cut); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-indexed:
		if e.Kind != "clipboard_refused" || e.Detail != "to_target 24 bytes" || strings.Contains(e.Detail, "secret") {
			t.Fatalf("clipboard refusal indexed as %+v", e)
		}
	case e := <-result:
		t.Fatalf("a clipboard attempt ended the desktop: %v", e)
	case <-time.After(time.Second):
		t.Fatal("clipboard refusal was not indexed")
	}
	if backend.inputs.Load() != 0 {
		t.Fatal("clipboard attempt reached upstream input")
	}
	// The session continues: a pointer event still reaches the target.
	if _, e := client.Write([]byte{5, 0, 0, 10, 0, 10}); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for backend.inputs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if backend.inputs.Load() == 0 {
		t.Fatal("input after a refused clipboard did not reach the target")
	}
	// A clipboard message beyond the bound ends the session.
	if _, e := client.Write([]byte{6, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff}); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-result:
		if !errors.Is(e, ErrCapacity) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("an oversized clipboard message did not end the desktop")
	}
}

func TestDesktopRecordingBackpressureCancelsOnClientClose(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	backend := &fixtureBackend{packets: make(chan rdp.Packet, 2), done: make(chan struct{})}
	backend.packets <- rdp.Packet{Kind: 1, Width: 320, Height: 200}
	backend.packets <- rdp.Packet{Kind: 2, Width: 320, Height: 200, Pixels: make([]byte, 320*200*4)}
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- Serve(testContext(t), server, backend, func(ctx context.Context, _ rdp.Packet) error { close(entered); <-ctx.Done(); return ctx.Err() })
	}()
	viewerHandshake(t, client)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("record callback not reached")
	}
	_ = client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var unseen [1]byte
	if n, e := client.Read(unseen[:]); n != 0 || e == nil {
		t.Fatal("viewer received pixels before recording accepted them")
	}
	_ = client.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("record backpressure stranded the session")
	}
	select {
	case <-backend.done:
	default:
		t.Fatal("upstream survived client closure")
	}
}

type fuzzConn struct{ *bytes.Reader }

func (*fuzzConn) Write(raw []byte) (int, error)    { return len(raw), nil }
func (*fuzzConn) Close() error                     { return nil }
func (*fuzzConn) LocalAddr() net.Addr              { return nil }
func (*fuzzConn) RemoteAddr() net.Addr             { return nil }
func (*fuzzConn) SetDeadline(time.Time) error      { return nil }
func (*fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (*fuzzConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzRFBViewer(f *testing.F) {
	f.Add([]byte{4, 1, 0, 0, 0, 0, 0, 'a'})
	f.Add([]byte{3, 0, 0, 0, 0, 0, 1, 64, 0, 200})
	f.Add([]byte{6})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		if len(raw) >= 16 {
			format, e := decodePixelFormat(raw[:16])
			if e == nil && format.bits != 16 && format.bits != 32 {
				t.Fatal("unsupported decoded pixel size")
			}
		}
		if len(raw) >= 9 {
			req, e := decodeRequest(raw[:9], 800, 600)
			if e == nil && (req.w == 0 || req.h == 0 || uint32(req.x)+uint32(req.w) > 800 || uint32(req.y)+uint32(req.h) > 600) {
				t.Fatal("decoded rectangle outside screen")
			}
		}
		if len(raw) >= 4 {
			_, _, _, _ = keyInput(binary.BigEndian.Uint32(raw[:4]), true)
		}
		backend := &fixtureBackend{done: make(chan struct{})}
		requests := make(chan updateRequest, 4)
		e := readViewer(context.Background(), &fuzzConn{bytes.NewReader(raw)}, &viewerState{width: 800, height: 600}, backend, requests, nil)
		if !errors.Is(e, io.EOF) && !errors.Is(e, io.ErrUnexpectedEOF) && !errors.Is(e, ErrProtocol) && !errors.Is(e, ErrClipboard) && !errors.Is(e, ErrCapacity) {
			t.Fatalf("unexpected viewer decoder error: %v", e)
		}
	})
}

func TestDesktopInputAndUpdateQueueRejectFast(t *testing.T) {
	backend := &fixtureBackend{done: make(chan struct{})}
	message := []byte{3, 0, 0, 0, 0, 0, 1, 64, 0, 200}
	e := readViewer(context.Background(), &fuzzConn{bytes.NewReader(bytes.Repeat(message, 5))}, &viewerState{width: 320, height: 200}, backend, make(chan updateRequest, 4), nil)
	if !errors.Is(e, ErrCapacity) {
		t.Fatal("full update queue did not refuse fast")
	}
	key := []byte{4, 1, 0, 0, 0, 0, 0, 'a'}
	e = readViewer(context.Background(), &fuzzConn{bytes.NewReader(bytes.Repeat(key, 4097))}, &viewerState{width: 320, height: 200}, backend, make(chan updateRequest, 4), nil)
	if !errors.Is(e, ErrCapacity) || backend.inputs.Load() != 4096 {
		t.Fatal("input flood was not bounded")
	}
}
