// SPDX-License-Identifier: BUSL-1.1

package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestDesktopBoundsAndRequest(t *testing.T) {
	target := Target{Address: "localhost:3389", Username: "account", CertificateSHA256: strings.Repeat("ab", 32), Width: 800, Height: 600, TLSOnly: true}
	if err := target.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*Target){func(t *Target) { t.Address = "x:0" }, func(t *Target) { t.Width = 65535 }, func(t *Target) { t.Height = 1025 }, func(t *Target) { t.CertificateSHA256 = strings.Repeat("zz", 32) }, func(t *Target) { t.Username = "bad\x00name" }} {
		bad := target
		alter(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid desktop accepted")
		}
	}
	password := []byte("byte-only-private-value")
	defer secret.Wipe(password)
	b, err := request(target, password)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	raw := b.Bytes()
	if !bytes.HasPrefix(raw, []byte("TRDP0001")) || binary.BigEndian.Uint16(raw[8:10]) != 3389 || raw[14] != 1 || !bytes.HasSuffix(raw, password) {
		t.Fatal("incorrect private request")
	}
	if _, err = Start(context.Background(), "/absent", target, []byte{0}); err == nil {
		t.Fatal("NUL password accepted")
	}
	if _, err = Start(context.Background(), "/absent", target, bytes.Repeat([]byte{'p'}, 1025)); err == nil {
		t.Fatal("oversized password accepted")
	}
}

func TestDesktopPacketsAndInputs(t *testing.T) {
	ready := []byte{1, 3, 32, 2, 88}
	if p, e := DecodePacket(ready); e != nil || p.Width != 800 || p.Height != 600 || len(p.Pixels) != 0 {
		t.Fatal("ready packet invalid")
	}
	frame := append([]byte{2, 3, 32, 2, 88}, make([]byte, 800*600*4)...)
	if p, e := DecodePacket(frame); e != nil || len(p.Pixels) != 800*600*4 {
		t.Fatal("frame packet invalid")
	}
	for _, raw := range [][]byte{nil, ready[:4], append(append([]byte{}, ready...), 0), frame[:len(frame)-1], {2, 255, 255, 255, 255}, {3, 0, 0, 0, 0}} {
		if _, e := DecodePacket(raw); e == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	var wire bytes.Buffer
	s := &Stream{input: writeCloser{&wire}}
	for _, input := range []struct {
		kind        byte
		flags, a, b uint16
	}{{3, 0, 30, 0}, {3, 0x8100, 75, 0}, {4, 0, 'x', 0}, {5, 0x9000, 799, 599}} {
		if e := s.Input(input.kind, input.flags, input.a, input.b); e != nil {
			t.Fatal(e)
		}
	}
	for _, input := range []struct {
		kind        byte
		flags, a, b uint16
	}{{6, 0, 0, 0}, {3, 1, 30, 0}, {3, 0, 256, 0}, {4, 0, 0xd800, 0}, {5, 0x0400, 0, 0}, {5, 0, 1280, 0}, {5, 0, 0, 1024}} {
		if s.Input(input.kind, input.flags, input.a, input.b) == nil {
			t.Fatal("invalid input accepted")
		}
	}
	for _, raw := range [][]byte{{0xff, 0xff, 0xff, 0xff}, {0, 0, 0, 0}, {0, 0, 0, 1, 3}} {
		s.output = io.NopCloser(bytes.NewReader(raw))
		if _, e := s.ReadPacket(); e == nil {
			t.Fatal("invalid packet header accepted")
		}
	}
}

type writeCloser struct{ io.Writer }

func (writeCloser) Close() error { return nil }

func FuzzPacket(f *testing.F) {
	f.Add([]byte{1, 3, 32, 2, 88})
	f.Add([]byte{2, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, e := DecodePacket(raw)
		if e == nil {
			if p.Kind == 2 && len(p.Pixels) != int(p.Width)*int(p.Height)*4 {
				t.Fatal("unbounded framebuffer")
			}
			if p.Kind == 1 && len(p.Pixels) != 0 {
				t.Fatal("ready has pixels")
			}
		}
	})
}

// A269: the reviewed clipboard policy is two request flags beside TLS-only;
// the target's clipboard is a bounded text packet; the operator's text is
// refused without a to-target policy and framed exactly with one.
func TestDesktopClipboardPolicyWireA269(t *testing.T) {
	base := Target{Address: "127.0.0.1:3389", Username: "u", CertificateSHA256: strings.Repeat("ab", 32), Width: 800, Height: 600}
	for _, tc := range []struct {
		target Target
		flags  byte
	}{
		{base, 0},
		{Target{Address: base.Address, Username: "u", CertificateSHA256: base.CertificateSHA256, Width: 800, Height: 600, TLSOnly: true, ClipboardToTarget: true}, 3},
		{Target{Address: base.Address, Username: "u", CertificateSHA256: base.CertificateSHA256, Width: 800, Height: 600, ClipboardFromTarget: true}, 4},
	} {
		b, err := request(tc.target, []byte("pw"))
		if err != nil {
			t.Fatal(err)
		}
		if got := b.Bytes()[14]; got != tc.flags {
			t.Errorf("flags = %d, want %d", got, tc.flags)
		}
		b.Destroy()
	}
	if p, err := DecodePacket(append([]byte{4}, []byte("from the target")...)); err != nil || p.Kind != 4 || string(p.Text) != "from the target" {
		t.Fatalf("text packet = %+v %v", p, err)
	}
	if _, err := DecodePacket(append([]byte{4}, make([]byte, MaxClipboard+1)...)); err == nil {
		t.Fatal("an over-bound clipboard packet decoded")
	}
	refused := &Stream{}
	if err := refused.Clipboard([]byte("x")); !errors.Is(err, ErrClipboardRefused) {
		t.Fatal("clipboard reached the helper without a to-target policy", err)
	}
	var wire bytes.Buffer
	allowed := &Stream{toTarget: true, input: nopWriteCloser{&wire}}
	if err := allowed.Clipboard([]byte("café")); err != nil {
		t.Fatal(err)
	}
	if got := wire.Bytes(); !bytes.Equal(got[:7], []byte{6, 0, 0, 0, 5, 0, 0}) || string(got[7:]) != "café" {
		t.Fatalf("clipboard input frame = %x", got)
	}
	for _, bad := range [][]byte{nil, []byte("a\x00b"), make([]byte, MaxClipboard+1)} {
		if err := allowed.Clipboard(bad); err == nil {
			t.Fatalf("clipboard input %d bytes accepted", len(bad))
		}
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
