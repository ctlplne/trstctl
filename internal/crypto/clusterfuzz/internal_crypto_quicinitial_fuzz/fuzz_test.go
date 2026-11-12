// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto/quicinitial"
)

// FuzzQUICInitialOpen drives arbitrary datagrams through the QUIC Initial
// reader (X1-L4): a datagram seen on a mirrored interface is untrusted input,
// so the reader must fail closed, never panic, never change the datagram,
// and never return frames with an error.
func FuzzQUICInitialOpen(f *testing.F) {
	f.Add([]byte{0xc3, 0, 0, 0, 1, 8, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0, 0, 0x40, 0x14}, []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}, false)
	f.Add([]byte{0xf0, 0, 0, 0, 1, 0, 0}, []byte{1}, true)
	f.Add([]byte{0xd3, 0x6b, 0x33, 0x43, 0xcf, 1, 0xaa, 0, 0, 0x01}, []byte{0xaa}, false)

	f.Fuzz(func(t *testing.T, datagram, dcid []byte, fromServer bool) {
		before := bytes.Clone(datagram)
		h, frames, err := quicinitial.Open(datagram, dcid, fromServer)
		if !bytes.Equal(before, datagram) {
			t.Fatal("Open changed the datagram")
		}
		if err != nil {
			if frames != nil {
				t.Fatalf("an error with %d bytes of frames", len(frames))
			}
			return
		}
		if h.Length <= 0 || h.Length > len(datagram) {
			t.Fatalf("an opened packet of length %d in a %d-byte datagram", h.Length, len(datagram))
		}
	})
}
