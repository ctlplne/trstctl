// SPDX-License-Identifier: BUSL-1.1

package quicinitial

import (
	"encoding/hex"
	"errors"
	"testing"
)

// The Initial keys of RFC 9001 Appendix A.1 (QUIC v1) and RFC 9369 Appendix
// A.1 (QUIC v2), for the client's Destination Connection ID 0x8394c8f03e515708.
func TestInitialKeysMatchTheRFCVectorsX1L4(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	for _, tc := range []struct {
		name        string
		version     uint32
		server      bool
		key, iv, hp string
	}{
		{"v1 client", Version1, false, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{"v1 server", Version1, true, "cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314"},
		{"v2 client", Version2, false, "8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"},
		{"v2 server", Version2, true, "82db637861d55e1d011f19ea71d5d2a7", "dd13c276499c0249d3310652", "edf6d05c83121201b436e16877593c3a"},
	} {
		key, iv, hp, err := initialKeys(tc.version, dcid, tc.server)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(key) != tc.key || hex.EncodeToString(iv) != tc.iv || hex.EncodeToString(hp) != tc.hp {
			t.Fatalf("%s: key %x iv %x hp %x", tc.name, key, iv, hp)
		}
	}
}

// A packet that is not a long-header Initial of a known version, or that the
// keys do not open, is refused; a datagram's bytes are never changed.
func TestOpenRefusesWhatItCannotReadX1L4(t *testing.T) {
	if _, _, err := Open([]byte{0x40, 1, 2, 3, 4, 5, 6, 7}, []byte{1}, false); !errors.Is(err, ErrNotInitial) {
		t.Fatalf("a short-header packet: %v", err)
	}
	if _, _, err := Open([]byte{0xc0, 0, 0, 0, 0, 0, 0, 0}, []byte{1}, false); !errors.Is(err, ErrNotInitial) {
		t.Fatalf("version negotiation: %v", err)
	}
	// An Initial header with a 20-byte body of zeros: it parses, but no key opens it.
	packet := append([]byte{0xc3, 0, 0, 0, 1, 1, 0xaa, 0, 0, 20}, make([]byte, 20)...)
	before := append([]byte(nil), packet...)
	if _, _, err := Open(packet, []byte{0xaa}, false); err == nil {
		t.Fatal("garbage opened")
	}
	if string(before) != string(packet) {
		t.Fatal("Open changed the datagram")
	}
}
