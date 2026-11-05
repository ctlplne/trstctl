// SPDX-License-Identifier: BUSL-1.1

package desktop

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/rdp"
)

type fixtureBackend struct {
	inputs  atomic.Int64
	packets chan rdp.Packet
	done    chan struct{}
}

func (b *fixtureBackend) ReadPacket() (rdp.Packet, error) {
	select {
	case p := <-b.packets:
		return p, nil
	case <-b.done:
		return rdp.Packet{}, io.EOF
	}
}
func (b *fixtureBackend) Input(byte, uint16, uint16, uint16) error { b.inputs.Add(1); return nil }
func (b *fixtureBackend) Close() error {
	select {
	case <-b.done:
	default:
		close(b.done)
	}
	return nil
}
func TestDesktopRFBHandshakeAndFramebuffer(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	backend := &fixtureBackend{packets: make(chan rdp.Packet, 2), done: make(chan struct{})}
	backend.packets <- rdp.Packet{Kind: 1, Width: 320, Height: 200}
	pixels := make([]byte, 320*200*4)
	for i := 0; i < len(pixels); i += 4 {
		pixels[i] = 128
	}
	backend.packets <- rdp.Packet{Kind: 2, Width: 320, Height: 200, Pixels: pixels}
	result := make(chan error, 1)
	go func() { result <- Serve(testContext(t), server, backend, nil) }()
	viewerHandshake(t, client)
	if _, e := client.Write([]byte{3, 0, 0, 0, 0, 0, 1, 64, 0, 200}); e != nil {
		t.Fatal(e)
	}
	var update [16]byte
	if _, e := io.ReadFull(client, update[:]); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(pixels))
	if _, e := io.ReadFull(client, got); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, pixels) {
		t.Fatal("framebuffer changed")
	}
	_ = client.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("renderer did not end")
	}
}

func viewerHandshake(t *testing.T, client net.Conn) {
	t.Helper()
	var version [12]byte
	if _, e := io.ReadFull(client, version[:]); e != nil {
		t.Fatal(e)
	}
	if string(version[:]) != "RFB 003.008\n" {
		t.Fatal("wrong RFB version")
	}
	if _, e := client.Write(version[:]); e != nil {
		t.Fatal(e)
	}
	var security [2]byte
	if _, e := io.ReadFull(client, security[:]); e != nil || security != [2]byte{1, 1} {
		t.Fatal("wrong tunnel security")
	}
	if _, e := client.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	var status [4]byte
	if _, e := io.ReadFull(client, status[:]); e != nil || status != [4]byte{} {
		t.Fatal("RFB security failed")
	}
	if _, e := client.Write([]byte{0}); e != nil {
		t.Fatal(e)
	}
	var init [24]byte
	if _, e := io.ReadFull(client, init[:]); e != nil {
		t.Fatal(e)
	}
	nameLen := int(init[20])<<24 | int(init[21])<<16 | int(init[22])<<8 | int(init[23])
	if nameLen > 128 {
		t.Fatal("unbounded desktop name")
	}
	name := make([]byte, nameLen)
	if _, e := io.ReadFull(client, name); e != nil {
		t.Fatal(e)
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestDesktopRequiresSessionDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	backend := &fixtureBackend{done: make(chan struct{})}
	if e := Serve(context.Background(), server, backend, nil); e != ErrDeadline {
		t.Fatal("unbounded desktop session accepted")
	}
	select {
	case <-backend.done:
	default:
		t.Fatal("invalid desktop did not release backend")
	}
}
