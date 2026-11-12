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
		case bpfLdBInd:
			if a, ok = load(x+in.K, 1); !ok {
				return 0
			}
		case bpfLdxImm:
			x = in.K
		case bpfAluAndK:
			a &= in.K
		case bpfAluLshK:
			a <<= in.K
		case bpfAluAddX:
			a += x
		case bpfMiscTax:
			x = a
		case bpfJa:
			pc += int(in.K)
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

func TestPortFilterKeepsOnlyWatchedTCPAndUDP(t *testing.T) {
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
	// X1-L4: UDP to a watched port (QUIC, DTLS) is kept, UDP to another
	// port and any other protocol are dropped.
	udp := frame(client, netip.MustParseAddrPort("10.0.0.5:443"), 1, syn, nil)
	udp[14+9] = 17
	if got := runBPF(t, prog, udp); got != 2048 {
		t.Errorf("UDP to 443 dropped: %d", got)
	}
	udpOther := frame(client, netip.MustParseAddrPort("10.0.0.5:5353"), 1, syn, nil)
	udpOther[14+9] = 17
	if got := runBPF(t, prog, udpOther); got != 0 {
		t.Errorf("UDP to 5353 kept: %d", got)
	}
	sctp := frame(client, netip.MustParseAddrPort("10.0.0.5:443"), 1, syn, nil)
	sctp[14+9] = 132
	if got := runBPF(t, prog, sctp); got != 0 {
		t.Errorf("SCTP to 443 kept: %d", got)
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
	v6[14+6] = 17
	if got := runBPF(t, prog, v6); got != 2048 {
		t.Errorf("IPv6 UDP to 22 dropped: %d", got)
	}
	v6[14+6] = 58 // ICMPv6
	if got := runBPF(t, prog, v6); got != 0 {
		t.Errorf("ICMPv6 kept: %d", got)
	}
}

// tagged inserts VLAN tags (TPID, then a TCI with VLAN id vid) after a frame's
// MAC addresses, outermost first.
func tagged(frame []byte, tags ...[2]uint16) []byte {
	out := append([]byte(nil), frame[:12]...)
	for _, tag := range tags {
		out = binary.BigEndian.AppendUint16(out, tag[0])
		out = binary.BigEndian.AppendUint16(out, tag[1])
	}
	return append(out, frame[12:]...)
}

// X1-L2: frames behind one or two in-band VLAN tags (802.1Q, and QinQ with an
// 802.1ad outer tag) are read through to their TCP ports, IPv4 and IPv6 alike,
// with IPv4 options moving the ports; a third tag, or an unwatched port behind
// tags, is dropped in the kernel. Every jump stays inside BPF's 8-bit offsets
// at MaxWatchedPorts.
func TestPortFilterReadsThroughVLANTagsX1L2(t *testing.T) {
	prog := portFilterProgram([]uint16{443, 22}, 2048)
	client := netip.MustParseAddrPort("10.0.0.7:51000")
	v4 := frame(client, netip.MustParseAddrPort("10.0.0.5:443"), 1, syn, nil)
	other := frame(client, netip.MustParseAddrPort("10.0.0.5:5432"), 1, syn, nil)
	v6 := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(v6[12:14], 0x86dd)
	v6[14] = 0x60
	v6[14+6] = 6
	binary.BigEndian.PutUint16(v6[54:56], 50000)
	binary.BigEndian.PutUint16(v6[56:58], 22)
	// IPv4 with 4 bytes of options (IHL 6): the ports sit 4 bytes later.
	opts := append(append([]byte(nil), v4[:34]...), 0x01, 0x01, 0x01, 0x01)
	opts = append(opts, v4[34:]...)
	opts[14] = 0x46
	dot1q, dot1ad := [2]uint16{tpid8021Q, 10}, [2]uint16{tpid8021AD, 100}
	for _, tc := range []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"untagged IPv4 to 443", v4, 2048},
		{"untagged IPv4 with options", opts, 2048},
		{"802.1Q IPv4 to 443", tagged(v4, dot1q), 2048},
		{"802.1Q IPv4 with options", tagged(opts, dot1q), 2048},
		{"QinQ IPv4 to 443", tagged(v4, dot1ad, dot1q), 2048},
		{"QinQ 802.1Q twice", tagged(v4, dot1q, dot1q), 2048},
		{"802.1Q IPv6 to 22", tagged(v6, dot1q), 2048},
		{"QinQ IPv6 to 22", tagged(v6, dot1ad, dot1q), 2048},
		{"802.1Q to 5432", tagged(other, dot1q), 0},
		{"QinQ to 5432", tagged(other, dot1ad, dot1q), 0},
		{"three tags", tagged(v4, dot1ad, dot1q, dot1q), 0},
	} {
		if got := runBPF(t, prog, tc.pkt); got != tc.want {
			t.Errorf("%s: filter returned %d, want %d", tc.name, got, tc.want)
		}
	}
	udp := tagged(v4, dot1q)
	udp[18+9] = 17
	if got := runBPF(t, prog, udp); got != 2048 {
		t.Errorf("tagged UDP to 443 dropped: %d", got)
	}
	sctp := tagged(v4, dot1q)
	sctp[18+9] = 132
	if got := runBPF(t, prog, sctp); got != 0 {
		t.Errorf("tagged SCTP to 443 kept: %d", got)
	}
	fragment := tagged(v4, dot1ad, dot1q)
	fragment[22+7] = 0x10
	if got := runBPF(t, prog, fragment); got != 0 {
		t.Errorf("a tagged later IPv4 fragment was kept: %d", got)
	}

	ports := make([]uint16, MaxWatchedPorts)
	for i := range ports {
		ports[i] = uint16(1000 + i)
	}
	full := portFilterProgram(ports, 2048)
	if len(full) > 255 {
		t.Fatalf("%d instructions at MaxWatchedPorts", len(full))
	}
	for i, in := range full {
		if (in.Code == bpfJeqK || in.Code == bpfJsetK) && (i+1+int(in.Jt) >= len(full) || i+1+int(in.Jf) >= len(full)) {
			t.Fatalf("instruction %d jumps past the program", i)
		}
	}
	last := tagged(frame(client, netip.MustParseAddrPort("10.0.0.5:1031"), 1, syn, nil), dot1ad, dot1q)
	if got := runBPF(t, full, last); got != 2048 {
		t.Fatalf("the last of %d watched ports behind QinQ was dropped", MaxWatchedPorts)
	}
}
