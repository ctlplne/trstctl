// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// runBPF interprets the instructions portFilterProgram emits.
func runBPF(t *testing.T, prog []bpfInsn, pkt []byte) uint32 {
	t.Helper()
	var a, x uint32
	load := func(off uint32, size int) (uint32, bool) {
		if int(off)+size > len(pkt) {
			return 0, false
		}
		if size == 1 {
			return uint32(pkt[off]), true
		}
		return uint32(binary.BigEndian.Uint16(pkt[off:])), true
	}
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		var ok bool
		switch in.Code {
		case bpfLdHAbs:
			if a, ok = load(in.K, 2); !ok {
				return 0
			}
		case bpfLdBAbs:
			if a, ok = load(in.K, 1); !ok {
				return 0
			}
		case bpfLdHInd:
			if a, ok = load(x+in.K, 2); !ok {
				return 0
			}
		case bpfLdxBMsh:
			b, ok := load(in.K, 1)
			if !ok {
				return 0
			}
			x = 4 * (b & 0x0f)
		case bpfJeqK:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfJsetK:
			if a&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("unexpected opcode %#x", in.Code)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func TestPortFilterKeepsOnlyWatchedTCP(t *testing.T) {
	prog := portFilterProgram([]uint16{443, 22, 389}, 2048)
	client := netip.MustParseAddrPort("10.0.0.7:51000")
	for _, tc := range []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"to 443", frame(client, netip.MustParseAddrPort("10.0.0.5:443"), 1, syn, nil), 2048},
		{"from 22", frame(netip.MustParseAddrPort("10.0.0.5:22"), client, 1, ack, []byte("SSH-2.0-x\r\n")), 2048},
		{"to 389", frame(client, netip.MustParseAddrPort("10.0.0.5:389"), 1, ack, []byte{0x30}), 2048},
		{"to 5432", frame(client, netip.MustParseAddrPort("10.0.0.5:5432"), 1, syn, nil), 0},
	} {
		if got := runBPF(t, prog, tc.pkt); got != tc.want {
			t.Errorf("%s: filter returned %d, want %d", tc.name, got, tc.want)
		}
	}
	udp := frame(client, netip.MustParseAddrPort("10.0.0.5:443"), 1, syn, nil)
	udp[14+9] = 17
	if got := runBPF(t, prog, udp); got != 0 {
		t.Errorf("UDP to 443 kept: %d", got)
	}
	fragment := frame(client, netip.MustParseAddrPort("10.0.0.5:443"), 1, syn, nil)
	fragment[14+7] = 0x10 // a later fragment (offset 128 bytes) carries no TCP header
	if got := runBPF(t, prog, fragment); got != 0 {
		t.Errorf("a later IPv4 fragment was kept: %d", got)
	}
	v6 := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(v6[12:14], 0x86dd)
	v6[14] = 0x60
	v6[14+6] = 6
	binary.BigEndian.PutUint16(v6[54:56], 50000)
	binary.BigEndian.PutUint16(v6[56:58], 22)
	if got := runBPF(t, prog, v6); got != 2048 {
		t.Errorf("IPv6 to 22 dropped: %d", got)
	}
}
