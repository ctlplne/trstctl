// SPDX-License-Identifier: BUSL-1.1
package desktop

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/rdp"
)

// clipboardFixture is a backend whose reviewed policy sends the operator's
// clipboard to the target (A269); it keeps what it was offered.
type clipboardFixture struct {
	*fixtureBackend
	mu      sync.Mutex
	offered [][]byte
}

func (b *clipboardFixture) Clipboard(text []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.offered = append(b.offered, append([]byte(nil), text...))
	return nil
}

// A269: under a policy that allows it, the viewer's clipboard (RFB Latin-1)
// reaches the target as UTF-8 and the target's text reaches the viewer as
// Latin-1; the index records each direction's length, never the text.
func TestDesktopClipboardForwardedUnderPolicy(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	backend := &clipboardFixture{fixtureBackend: &fixtureBackend{packets: make(chan rdp.Packet, 2), done: make(chan struct{})}}
	backend.packets <- rdp.Packet{Kind: 1, Width: 320, Height: 200}
	indexed := make(chan Event, 4)
	go func() {
		_ = ServeEvents(testContext(t), server, backend, nil, func(_ context.Context, e Event) error { indexed <- e; return nil })
	}()
	viewerHandshake(t, client)
	if _, e := client.Write([]byte{6, 0, 0, 0, 0, 0, 0, 4, 'c', 'a', 'f', 0xe9}); e != nil {
		t.Fatal(e)
	}
	if e := <-indexed; e.Kind != "clipboard_to_target" || e.Detail != "to_target 4 bytes" {
		t.Fatalf("to-target clipboard indexed as %+v", e)
	}
	backend.mu.Lock()
	offered := backend.offered
	backend.mu.Unlock()
	if len(offered) != 1 || string(offered[0]) != "café" {
		t.Fatalf("the target was offered %q", offered)
	}
	backend.packets <- rdp.Packet{Kind: 4, Text: []byte("größer ✓")}
	var head [8]byte
	if _, e := io.ReadFull(client, head[:]); e != nil {
		t.Fatal(e)
	}
	n := binary.BigEndian.Uint32(head[4:8])
	text := make([]byte, n)
	if _, e := io.ReadFull(client, text); e != nil {
		t.Fatal(e)
	}
	if head[0] != 3 || !bytes.Equal(text, []byte{'g', 'r', 0xf6, 0xdf, 'e', 'r', ' ', '?'}) {
		t.Fatalf("the viewer got ServerCutText %d %q", head[0], text)
	}
	if e := <-indexed; e.Kind != "clipboard_from_target" || e.Detail != "from_target 12 bytes" {
		t.Fatalf("from-target clipboard indexed as %+v", e)
	}
}
