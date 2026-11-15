// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"
)

// captureFrames reads every Ethernet frame of a saved capture with its time.
func captureFrames(t testing.TB, file string) ([][]byte, []time.Time) {
	t.Helper()
	data, err := os.ReadFile(file) // #nosec G304 -- the test reads its own fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	frames, times, err := pcapFrames(data)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return frames, times
}

// pcapFrames reads every Ethernet frame of a classic capture with its time.
func pcapFrames(data []byte) ([][]byte, []time.Time, error) {
	if len(data) < 24 {
		return nil, nil, errors.New("not a capture")
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if binary.BigEndian.Uint32(data[0:4]) == 0xa1b2c3d4 || binary.BigEndian.Uint32(data[0:4]) == 0xa1b23c4d {
		order = binary.BigEndian
	}
	nanos := order.Uint32(data[0:4]) == 0xa1b23c4d
	link := order.Uint32(data[20:24])
	var frames [][]byte
	var times []time.Time
	for rest := data[24:]; len(rest) >= 16; {
		sec, frac, length := order.Uint32(rest[0:4]), order.Uint32(rest[4:8]), int(order.Uint32(rest[8:12]))
		if 16+length > len(rest) {
			return nil, nil, errors.New("truncated record")
		}
		frame := ethernetFrame(link, rest[16:16+length])
		rest = rest[16+length:]
		if frame == nil {
			continue
		}
		nsec := int64(frac)
		if !nanos {
			nsec *= int64(time.Microsecond)
		}
		frames = append(frames, frame)
		times = append(times, time.Unix(int64(sec), nsec).UTC())
	}
	return frames, times, nil
}

// fragmentIPv4 splits an untagged IPv4 frame's payload into pieces of at
// most size bytes (a multiple of 8), as a router would, newest last.
func fragmentIPv4(frame []byte, id uint16, size int) [][]byte {
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	payload := ip[ihl:total]
	var out [][]byte
	for off := 0; off < len(payload); off += size {
		end := min(off+size, len(payload))
		piece := make([]byte, 14+ihl+end-off)
		copy(piece, frame[:14+ihl])
		copy(piece[14+ihl:], payload[off:end])
		binary.BigEndian.PutUint16(piece[14+2:14+4], uint16(ihl+end-off)) // #nosec G115 -- fixture lengths fit (CWE-190)
		binary.BigEndian.PutUint16(piece[14+4:14+6], id)
		field := uint16(off / 8) // #nosec G115 -- fixture offsets fit (CWE-190)
		if end < len(payload) {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(piece[14+6:14+8], field)
		out = append(out, piece)
	}
	return out
}

// toIPv6 re-frames an untagged IPv4 frame as IPv6 between documentation
// addresses, with the extension headers given ahead of the transport header.
func toIPv6(frame []byte, ext ...[]byte) []byte {
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	l4 := ip[ihl:total]
	chainLen := 0
	for _, h := range ext {
		chainLen += len(h) - 1 // the trailing byte is the header's own type, not sent
	}
	out := make([]byte, 14+40+chainLen+len(l4))
	copy(out, frame[:12])
	binary.BigEndian.PutUint16(out[12:14], 0x86dd)
	v6 := out[14:]
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:6], uint16(chainLen+len(l4))) // #nosec G115 -- fixture lengths fit (CWE-190)
	v6[6] = ip[9]
	if len(ext) > 0 {
		v6[6] = ext[0][len(ext[0])-1] // each header's own type rides in its last byte below
	}
	v6[7] = 64
	copy(v6[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 15: ip[15]})
	copy(v6[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 15: ip[19]})
	// Rebuild the chain with real next-header fields: each header names the
	// next one, the last names the transport protocol.
	off := 40
	for i, h := range ext {
		next := ip[9]
		if i+1 < len(ext) {
			next = ext[i+1][len(ext[i+1])-1]
		}
		copy(v6[off:], h[:len(h)-1])
		v6[off] = next
		off += len(h) - 1
	}
	copy(v6[off:], l4)
	return out[:14+off+len(l4)]
}

// hopByHop is an 8-byte hop-by-hop options header (a PadN option); its own
// type, 0, rides in the trailing byte toIPv6 reads.
func hopByHop() []byte { return []byte{0, 0, 1, 4, 0, 0, 0, 0, 0} }

// destinationOptions is an 8-byte destination options header (type 60).
func destinationOptions() []byte { return []byte{0, 0, 1, 4, 0, 0, 0, 0, 60} }

// fragmentIPv6 splits an IPv6 frame (no extension headers) into fragments
// carrying an IPv6 fragment header.
func fragmentIPv6(frame []byte, id uint32, size int) [][]byte {
	v6 := frame[14:]
	length := int(binary.BigEndian.Uint16(v6[4:6]))
	proto, payload := v6[6], v6[40:40+length]
	var out [][]byte
	for off := 0; off < len(payload); off += size {
		end := min(off+size, len(payload))
		piece := make([]byte, 14+40+8+end-off)
		copy(piece, frame[:14+40])
		piece[14+6] = 44
		binary.BigEndian.PutUint16(piece[14+4:14+6], uint16(8+end-off)) // #nosec G115 -- fixture lengths fit (CWE-190)
		h := piece[14+40 : 14+48]
		h[0] = proto
		field := uint16(off/8) << 3 // #nosec G115 -- fixture offsets fit (CWE-190)
		if end < len(payload) {
			field |= 1
		}
		binary.BigEndian.PutUint16(h[2:4], field)
		binary.BigEndian.PutUint32(h[4:8], id)
		copy(piece[14+48:], payload[off:end])
		out = append(out, piece)
	}
	return out
}

func withTags(frame []byte, tags ...[2]uint16) []byte {
	out := append([]byte(nil), frame[:12]...)
	for _, tag := range tags {
		out = binary.BigEndian.AppendUint16(out, tag[0])
		out = binary.BigEndian.AppendUint16(out, tag[1])
	}
	return append(out, frame[12:]...)
}

// TestReframedCaptureYieldsTheHandshakeX1L2R: the real TLS 1.3 handshake of
// X1-L3 (OpenSSL 3.5.9, captured with tcpdump on a Linux loopback) is read
// again with every packet re-framed as the observer meets it on other
// networks: IPv4 fragments delivered last piece first, IPv6 behind a
// hop-by-hop header and a destination options header, IPv6 fragments, and
// three in-band VLAN tags. Each copy yields the same X25519MLKEM768
// handshake; the fragments are reassembled, and none is dropped.
func TestReframedCaptureYieldsTheHandshakeX1L2R(t *testing.T) {
	frames, times := captureFrames(t, "testdata/x1l3-tls13-mlkem.pcap")
	if len(frames) != 19 {
		t.Fatalf("the capture has %d frames, want 19", len(frames))
	}
	dot1q, dot1ad := [2]uint16{tpid8021Q, 10}, [2]uint16{tpid8021AD, 100}
	big := func(frame []byte) bool { return len(frame) > 14+20+20+200 }
	variants := map[string]func(i int, frame []byte) [][]byte{
		"IPv4 fragments, last first": func(i int, frame []byte) [][]byte {
			if !big(frame) {
				return [][]byte{frame}
			}
			pieces := fragmentIPv4(frame, uint16(1000+i), 256) // #nosec G115 -- fixture ids fit (CWE-190)
			for l, r := 0, len(pieces)-1; l < r; l, r = l+1, r-1 {
				pieces[l], pieces[r] = pieces[r], pieces[l]
			}
			return pieces
		},
		"IPv6 hop-by-hop and destination options": func(_ int, frame []byte) [][]byte {
			return [][]byte{toIPv6(frame, hopByHop(), destinationOptions())}
		},
		"IPv6 fragments": func(i int, frame []byte) [][]byte {
			v6 := toIPv6(frame)
			if !big(frame) {
				return [][]byte{v6}
			}
			return fragmentIPv6(v6, uint32(5000+i), 256) // #nosec G115 -- fixture ids fit (CWE-190)
		},
		"three VLAN tags": func(_ int, frame []byte) [][]byte {
			return [][]byte{withTags(frame, dot1ad, dot1q, dot1q)}
		},
	}
	for name, reframe := range variants {
		var events []Event
		a := NewAssembler([]uint16{8443}, 16, time.Minute, func(e Event) { events = append(events, e) })
		for i, frame := range frames {
			for _, piece := range reframe(i, frame) {
				a.Frame(piece, times[i])
			}
		}
		a.Flush(time.Now())
		st := a.Stats()
		if len(events) != 1 {
			t.Fatalf("%s: events %+v, stats %+v; want one handshake", name, events, st)
		}
		obs := events[0].Obs
		if obs.TLSVersion != "TLSv1.3" || obs.Group != "X25519MLKEM768" || obs.ServerName != "obs.example.test" || events[0].Server.Port() != 8443 {
			t.Fatalf("%s: observation = %+v at %s", name, obs, events[0].Server)
		}
		fragmented := name == "IPv4 fragments, last first" || name == "IPv6 fragments"
		if fragmented && (st.Fragments == 0 || st.Reassembled == 0) || st.FragmentsDropped != 0 || st.OutOfOrder != 0 {
			t.Fatalf("%s: stats = %+v", name, st)
		}
	}
}

// TestReassemblyIsBoundedX1L2R: overlapping, oversized, misaligned and
// stale fragments, a second last piece and a full table each drop their
// datagram, counted; an IPv6 chain of more extension headers than the
// observer walks is not read.
func TestReassemblyIsBoundedX1L2R(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	base := func(id uint32, offset int, more bool, n int) ipPacket {
		return ipPacket{proto: 6, payload: make([]byte, n), frag: &ipFragment{id: id, offset: offset, more: more}}
	}
	var st Stats
	r := newReassembler()
	if _, done := r.add(base(1, 0, true, 16), now, &st); done {
		t.Fatal("one piece of two completed a datagram")
	}
	if _, done := r.add(base(1, 8, false, 16), now, &st); done || st.FragmentsDropped != 1 {
		t.Fatalf("an overlapping piece: done %v stats %+v", done, st)
	}
	if _, done := r.add(base(2, 65528, false, 16), now, &st); done || st.FragmentsDropped != 2 {
		t.Fatalf("a datagram past 65535 bytes: done %v stats %+v", done, st)
	}
	if _, done := r.add(base(3, 0, true, 12), now, &st); done || st.FragmentsDropped != 3 {
		t.Fatalf("a misaligned middle piece: done %v stats %+v", done, st)
	}
	r.add(base(4, 16, false, 8), now, &st)
	if _, done := r.add(base(4, 16, false, 8), now, &st); done || st.FragmentsDropped != 4 {
		t.Fatalf("a second last piece: done %v stats %+v", done, st)
	}
	r.add(base(5, 0, true, 8), now, &st)
	if _, done := r.add(base(6, 0, true, 8), now.Add(reassemblyTimeout+time.Second), &st); done || st.FragmentsDropped != 5 || len(r.pending) != 1 {
		t.Fatalf("a stale datagram was not forgotten: pending %d stats %+v", len(r.pending), st)
	}
	r = newReassembler()
	for i := range maxReassemblies {
		r.add(base(uint32(100+i), 0, true, 8), now, &st) // #nosec G115 -- small loop index (CWE-190)
	}
	before := st.FragmentsDropped
	if _, done := r.add(base(999, 0, true, 8), now, &st); done || st.FragmentsDropped != before+1 || len(r.pending) != maxReassemblies {
		t.Fatalf("a datagram past the table's bound: pending %d stats %+v", len(r.pending), st)
	}
	whole, done := r.add(base(100, 8, false, 8), now, &st)
	if !done || len(whole.payload) != 16 || whole.frag != nil {
		t.Fatalf("a completed datagram = %+v %v", whole, done)
	}
	// Nine hop-by-hop headers are one more than the observer walks.
	frames, _ := captureFrames(t, "testdata/x1l3-tls13-mlkem.pcap")
	var chain [][]byte
	for range maxIPv6ExtensionHeaders + 1 {
		chain = append(chain, hopByHop())
	}
	if _, ok := decodePacket(toIPv6(frames[0], chain...)); ok {
		t.Fatal("a chain of nine extension headers was read")
	}
	if _, ok := decodePacket(toIPv6(frames[0], chain[:maxIPv6ExtensionHeaders]...)); !ok {
		t.Fatal("a chain of eight extension headers was not read")
	}
}

// TestKernelFragmentedDTLSCapturesYieldTheHandshakeX1L2R: real DTLS 1.2
// handshakes (OpenSSL 3.5.9's s_server and s_client, an RSA-4096
// certificate, datagrams up to 4000 bytes) captured with tcpdump 4.99.6 on a
// Linux loopback whose MTU the server's flight exceeds, so the kernel split
// it into IP fragments: IPv4 at MTU 576 with path MTU discovery off, and IPv6
// at MTU 1280 with fragment headers. Each capture yields the handshake, its
// fragments reassembled and none dropped.
func TestKernelFragmentedDTLSCapturesYieldTheHandshakeX1L2R(t *testing.T) {
	for _, file := range []string{"testdata/x1l2r-dtls12-ipv4-fragments.pcap", "testdata/x1l2r-dtls12-ipv6-fragments.pcap"} {
		events, st := replayUDPCapture(t, file, 4433)
		if len(events) != 1 {
			t.Fatalf("%s: events %+v, stats %+v; want one handshake", file, events, st)
		}
		obs := events[0].Obs
		if obs.TLSVersion != "DTLSv1.2" || events[0].Server.Port() != 4433 {
			t.Fatalf("%s: observation = %+v at %s", file, obs, events[0].Server)
		}
		if st.Fragments == 0 || st.Reassembled == 0 || st.FragmentsDropped != 0 {
			t.Fatalf("%s: stats = %+v, want fragments reassembled and none dropped", file, st)
		}
		t.Logf("X1L2R_DTLS_OK %s fragments=%d reassembled=%d", file, st.Fragments, st.Reassembled)
	}
}

// FuzzDecodeFrame's seeds are compiled in: the ClusterFuzzLite runner has no
// source tree to read them from.
//
//go:embed testdata/x1l3-tls13-mlkem.pcap
var seedTLS13Capture []byte

//go:embed testdata/x1l2r-dtls12-ipv4-fragments.pcap
var seedIPv4FragmentsCapture []byte

//go:embed testdata/x1l2r-dtls12-ipv6-fragments.pcap
var seedIPv6FragmentsCapture []byte

// FuzzDecodeFrame feeds hostile frames through the IP layer, the reassembler
// and the readers above it (X1-L2R): nothing panics, and the reassembler
// never holds more than its bound.
func FuzzDecodeFrame(f *testing.F) {
	for _, capture := range [][]byte{seedTLS13Capture, seedIPv4FragmentsCapture, seedIPv6FragmentsCapture} {
		frames, _, _ := pcapFrames(capture)
		for _, frame := range frames {
			f.Add(frame)
		}
	}
	f.Fuzz(func(t *testing.T, frame []byte) {
		a := NewAssembler([]uint16{443, 4433, 8443}, 16, time.Minute, func(Event) {})
		at := time.Unix(1_900_000_000, 0)
		a.Frame(frame, at)
		a.Frame(frame, at.Add(time.Second))
		if len(a.reasm.pending) > maxReassemblies {
			t.Fatalf("the reassembler holds %d datagrams", len(a.reasm.pending))
		}
		for _, buf := range a.reasm.pending {
			if len(buf.data) > maxReassembledBytes {
				t.Fatalf("a held datagram grew to %d bytes", len(buf.data))
			}
		}
	})
}
