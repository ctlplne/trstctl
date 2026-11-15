// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

// readFixture reads one of this package's saved captures.
func readFixture(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file) // #nosec G304 -- the test reads its own fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// replayCapture replays a saved capture, classic pcap or pcapng, for the
// given ports with the hold at held (0: the default) and ends what is open.
func replayCapture(t *testing.T, data []byte, held int, ports ...uint16) ([]Event, Stats, int) {
	t.Helper()
	var events []Event
	a := NewAssembler(ports, 16, time.Minute, func(e Event) { events = append(events, e) })
	if held > 0 {
		if err := a.SetMaxHeldSegments(held); err != nil {
			t.Fatal(err)
		}
	}
	packets, err := ReplayPcap(bytes.NewReader(data), a)
	if err != nil {
		t.Fatal(err)
	}
	a.Flush(time.Unix(2_000_000_000, 0))
	return events, a.Stats(), packets
}

// leafCertificateDER is the X1-L3R server's leaf certificate.
func leafCertificateDER(t *testing.T) []byte {
	t.Helper()
	block, _ := pem.Decode(readFixture(t, "testdata/x1l3r-leaf.pem"))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("testdata/x1l3r-leaf.pem holds no certificate")
	}
	return block.Bytes
}

// flightEnd is when the X1-L3R server's flight ended: the dumpcap capture's
// segment carrying the ServerHelloDone, to the nanosecond.
var flightEnd = time.Unix(0, 1794731558136305820)

// X1-L3R: pcapng, the format Wireshark and its dumpcap write by default, is
// read as a classic capture is. dumpcap 4.6.9 captured a real TLS 1.2
// handshake (OpenSSL 3.5.9 with an RSA-4096 leaf and CA at MTU 576, so the
// server's flight spans seven segments) with its section header and interface
// options, nanosecond timestamps (if_tsresol 9) and an interface statistics
// block, which is skipped: the version, suite, group and leaf certificate are
// read, at the nanosecond the server's flight ended. The same capture in
// big-endian byte order reads the same. mergecap's section of two interfaces,
// X1-L3's microsecond tcpdump capture beside the nanosecond one, yields both
// handshakes, each at its own interface's resolution; and the capture's
// packets as simple packet blocks, which carry no time, yield the handshake.
func TestReplayedPcapNGCapturesX1L3R(t *testing.T) {
	leaf := leafCertificateDER(t)
	dumpcap := readFixture(t, "testdata/x1l3r-tls12-dumpcap.pcapng")
	for name, capture := range map[string][]byte{"dumpcap": dumpcap, "big-endian": bigEndianPcapNG(t, dumpcap)} {
		events, st, packets := replayCapture(t, capture, 0, 8443)
		if packets != 26 || len(events) != 1 {
			t.Fatalf("%s: %d packets, events %+v, stats %+v; want 26 packets and one handshake", name, packets, events, st)
		}
		obs := events[0].Obs
		if obs.TLSVersion != "TLSv1.2" || obs.CipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || obs.Group != "x25519" ||
			obs.ServerName != "resync.example.test" || !bytes.Equal(obs.CertificateDER, leaf) || !events[0].At.Equal(flightEnd) {
			t.Fatalf("%s: observation %+v at %s", name, obs, events[0].At)
		}
		if st.Resynced != 0 || st.OutOfOrder != 0 || st.ActiveFlows != 0 || st.BufferedBytes != 0 {
			t.Fatalf("%s: stats %+v", name, st)
		}
	}

	classic, _, _ := replayCapture(t, readFixture(t, "testdata/x1l3-tls13-mlkem.pcap"), 0, 8443)
	merged, st, packets := replayCapture(t, readFixture(t, "testdata/x1l3r-merged.pcapng"), 0, 8443)
	if len(classic) != 1 || packets != 45 || len(merged) != 2 {
		t.Fatalf("merged: %d packets, events %+v, stats %+v; want 45 packets and two handshakes", packets, merged, st)
	}
	at := map[string]time.Time{}
	for _, e := range merged {
		at[e.Obs.TLSVersion] = e.At
	}
	if !at["TLSv1.3"].Equal(classic[0].At) || !at["TLSv1.2"].Equal(flightEnd) {
		t.Fatalf("merged: handshakes at %v; want TLS 1.3 at %s (microseconds) and TLS 1.2 at %s (nanoseconds)", at, classic[0].At, flightEnd)
	}

	events, _, packets := replayCapture(t, simplePacketBlocks(t, dumpcap), 0, 8443)
	if packets != 26 || len(events) != 1 || events[0].Obs.Group != "x25519" || !bytes.Equal(events[0].Obs.CertificateDER, leaf) {
		t.Fatalf("simple packet blocks: %d packets, events %+v", packets, events)
	}
}

// ngBlock is one little-endian pcapng block with its body padded.
func ngBlock(typ uint32, body []byte) []byte {
	b := make([]byte, 12+(len(body)+3)&^3)
	binary.LittleEndian.PutUint32(b[0:], typ)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b))) // #nosec G115 -- a bounded test block (CWE-190)
	copy(b[8:], body)
	binary.LittleEndian.PutUint32(b[len(b)-4:], uint32(len(b))) // #nosec G115 -- a bounded test block (CWE-190)
	return b
}

var (
	ngSection   = ngBlock(pcapngSectionHeader, []byte{0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	ngInterface = ngBlock(pcapngInterface, []byte{1, 0, 0, 0, 0, 0, 4, 0})
)

// ngPacket is an enhanced packet block for interface id carrying frame.
func ngPacket(id uint32, frame []byte) []byte {
	body := make([]byte, 20, 20+len(frame))
	binary.LittleEndian.PutUint32(body[0:], id)
	binary.LittleEndian.PutUint32(body[12:], uint32(len(frame))) // #nosec G115 -- a bounded test frame (CWE-190)
	binary.LittleEndian.PutUint32(body[16:], uint32(len(frame))) // #nosec G115 -- a bounded test frame (CWE-190)
	return ngBlock(pcapngEnhancedPacket, append(body, frame...))
}

// X1-L3R: the pcapng reader is bounded and says what it refuses. A packet
// naming an interface the section never described, a section's interface
// table past 64, a block over the record bound or not a multiple of four
// bytes, a trailing length that disagrees, a packet longer than its block, a
// truncated block and a timestamp resolution no clock has are each refused;
// a second section forgets the first's interfaces; blocks the observer does
// not read (name resolution, custom) are skipped; and the timestamp units
// are exact for powers of ten and of two.
func TestPcapNGIsBoundedX1L3R(t *testing.T) {
	frames, _, err := pcapFrames(readFixture(t, "testdata/x1l3r-tls12-lost-segment.pcap"))
	if err != nil || len(frames) == 0 {
		t.Fatalf("frames: %v", err)
	}
	join := func(blocks ...[]byte) []byte { return bytes.Join(blocks, nil) }
	many := [][]byte{ngSection}
	for range maxPcapNGInterfaces + 1 {
		many = append(many, ngInterface)
	}
	oddLength := append([]byte(nil), ngInterface...)
	binary.LittleEndian.PutUint32(oddLength[4:], 13)
	huge := make([]byte, 8)
	binary.LittleEndian.PutUint32(huge[0:], pcapngEnhancedPacket)
	binary.LittleEndian.PutUint32(huge[4:], maxPcapNGBlock+4)
	badTrailer := append([]byte(nil), ngInterface...)
	binary.LittleEndian.PutUint32(badTrailer[len(badTrailer)-4:], 24)
	long := ngPacket(0, frames[0])
	binary.LittleEndian.PutUint32(long[20:], uint32(len(long))) // #nosec G115 -- a bounded test block (CWE-190)
	nanoRes := ngBlock(pcapngInterface, []byte{1, 0, 0, 0, 0, 0, 4, 0, 9, 0, 1, 0, 19, 0, 0, 0, 0, 0, 0, 0})
	for name, tc := range map[string]struct {
		capture []byte
		want    string
	}{
		"an undescribed interface": {join(ngSection, ngInterface, ngPacket(1, frames[0])), "names interface 1 of 1"},
		"a second section":         {join(ngSection, ngInterface, ngSection, ngPacket(0, frames[0])), "names interface 0 of 0"},
		"65 interfaces":            {join(many...), "more than 64 interfaces"},
		"an odd length":            {join(ngSection, oddLength), "is 13 bytes"},
		"an oversized block":       {join(ngSection, ngInterface, huge), "bytes"},
		"a wrong trailing length":  {join(ngSection, badTrailer), "trailing length"},
		"a packet past its block":  {join(ngSection, ngInterface, long), "packet is"},
		"a truncated block":        {join(ngSection, ngInterface[:10]), "reading a pcapng block"},
		"10^-19 seconds":           {join(ngSection, nanoRes, ngPacket(0, frames[0])), "timestamp resolution"},
	} {
		_, err := ReplayPcap(bytes.NewReader(tc.capture), NewAssembler([]uint16{8443}, 4, time.Minute, func(Event) {}))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v; want an error saying %q", name, err, tc.want)
		}
	}

	nameResolution := ngBlock(4, []byte{1, 0, 8, 0, 127, 0, 0, 1, 'l', 'o', 'c', 0, 0, 0, 0, 0})
	custom := ngBlock(0x00000BAD, []byte{0x7f, 0, 0, 0, 1, 2, 3, 4})
	skipped := join(ngSection, ngInterface, nameResolution, custom, ngPacket(0, frames[0]))
	if packets, err := ReplayPcap(bytes.NewReader(skipped), NewAssembler([]uint16{8443}, 4, time.Minute, func(Event) {})); err != nil || packets != 1 {
		t.Fatalf("skipped blocks: %d packets, %v", packets, err)
	}

	for _, tc := range []struct {
		option    byte
		perSecond uint64
	}{{6, 1_000_000}, {9, 1_000_000_000}, {0, 1}, {0x80 | 10, 1024}, {0x80, 1}} {
		got, ok, err := pcapngTSResol(binary.LittleEndian, []byte{9, 0, 1, 0, tc.option, 0, 0, 0, 0, 0, 0, 0})
		if err != nil || !ok || got != tc.perSecond {
			t.Errorf("if_tsresol %#x = %d, %v, %v; want %d", tc.option, got, ok, err, tc.perSecond)
		}
	}
	if at := pcapngTime(5*1024+512, 1024); !at.Equal(time.Unix(5, 500_000_000)) {
		t.Errorf("5.5 s in 1/1024 s ticks = %s", at)
	}
	if at := pcapngTime(1794731558136305820, 1_000_000_000); !at.Equal(flightEnd) {
		t.Errorf("nanosecond ticks = %s", at)
	}
}

// bigEndianPcapNG re-encodes a little-endian pcapng capture in big-endian
// byte order, as dumpcap on a big-endian host writes it: each block's type,
// lengths and fixed fields, and each option's code, length and numeric
// value, swapped; packet data and string values as they are.
func bigEndianPcapNG(t *testing.T, le []byte) []byte {
	t.Helper()
	var out []byte
	for len(le) >= 12 {
		typ, length := binary.LittleEndian.Uint32(le[0:4]), int(binary.LittleEndian.Uint32(le[4:8]))
		body := le[8 : length-4]
		be := make([]byte, length)
		binary.BigEndian.PutUint32(be[0:], typ)
		binary.BigEndian.PutUint32(be[4:], uint32(length))        // #nosec G115 -- a bounded test block (CWE-190)
		binary.BigEndian.PutUint32(be[length-4:], uint32(length)) // #nosec G115 -- a bounded test block (CWE-190)
		dst := be[8 : length-4]
		copy(dst, body)
		var fixed []int      // the widths of the block's fixed fields
		var numeric []uint16 // option codes whose values are numbers
		options := 0
		switch typ {
		case pcapngSectionHeader: // byte-order magic, major and minor version, section length
			fixed, options = []int{4, 2, 2, 8}, 16
		case pcapngInterface: // link type, reserved, snap length; if_speed, if_tsoffset
			fixed, numeric, options = []int{2, 2, 4}, []uint16{8, 14}, 8
		case pcapngEnhancedPacket: // interface, time high and low, captured and original lengths
			fixed, numeric = []int{4, 4, 4, 4, 4}, []uint16{2, 4, 5, 6}
			options = 20 + (int(binary.LittleEndian.Uint32(body[12:16]))+3)&^3
		case 5: // interface statistics: interface, time high and low; counters
			fixed, numeric, options = []int{4, 4, 4}, []uint16{4, 5, 6, 7, 8}, 12
		default:
			t.Fatalf("block type %#x", typ)
		}
		off := 0
		for _, w := range fixed {
			reverse(dst[off:off+w], body[off:off+w])
			off += w
		}
		for o := options; o+4 <= len(body); {
			code, size := binary.LittleEndian.Uint16(body[o:]), int(binary.LittleEndian.Uint16(body[o+2:]))
			binary.BigEndian.PutUint16(dst[o:], code)
			binary.BigEndian.PutUint16(dst[o+2:], uint16(size)) // #nosec G115 -- an option length is 16 bits (CWE-190)
			if code == pcapngOptionEnd {
				break
			}
			for _, n := range numeric {
				if n == code {
					reverse(dst[o+4:o+4+size], body[o+4:o+4+size])
				}
			}
			if typ == 5 && (code == 2 || code == 3) { // isb_starttime, isb_endtime: two 32-bit halves
				reverse(dst[o+4:o+8], body[o+4:o+8])
				reverse(dst[o+8:o+12], body[o+8:o+12])
			}
			o += 4 + (size+3)&^3
		}
		out = append(out, be...)
		le = le[length:]
	}
	return out
}

func reverse(dst, src []byte) {
	for i := range src {
		dst[i] = src[len(src)-1-i]
	}
}

// simplePacketBlocks rewrites a little-endian pcapng capture's enhanced
// packet blocks as simple packet blocks (interface 0, no timestamp).
func simplePacketBlocks(t *testing.T, le []byte) []byte {
	t.Helper()
	var out []byte
	for len(le) >= 12 {
		typ, length := binary.LittleEndian.Uint32(le[0:4]), int(binary.LittleEndian.Uint32(le[4:8]))
		block := le[:length]
		if typ == pcapngEnhancedPacket {
			captured := int(binary.LittleEndian.Uint32(block[20:24]))
			body := append(append([]byte(nil), block[24:28]...), block[28:28+captured]...)
			block = ngBlock(pcapngSimplePacket, body)
		}
		out = append(out, block...)
		le = le[length:]
	}
	return out
}

// FuzzReplayPcapNG's seeds are compiled in: the ClusterFuzzLite runner has
// no source tree to read them from.
//
//go:embed testdata/x1l3r-tls12-dumpcap.pcapng
var seedDumpcapPcapNG []byte

//go:embed testdata/x1l3r-merged.pcapng
var seedMergedPcapNG []byte

// FuzzReplayPcapNG feeds hostile pcapng captures to the reader and the
// assembler behind it (X1-L3R): nothing panics, and the assembler's buffers
// stay inside their bounds.
func FuzzReplayPcapNG(f *testing.F) {
	f.Add(seedDumpcapPcapNG)
	f.Add(seedMergedPcapNG)
	f.Add(bytes.Join([][]byte{ngSection, ngInterface, ngPacket(0, make([]byte, 60))}, nil))
	f.Fuzz(func(t *testing.T, capture []byte) {
		a := NewAssembler([]uint16{8443, 4433}, 16, time.Minute, func(Event) {})
		_, _ = ReplayPcap(bytes.NewReader(capture), a)
		a.Flush(time.Unix(2_000_000_000, 0))
		if st := a.Stats(); st.ActiveFlows != 0 || st.BufferedBytes != 0 {
			t.Fatalf("after the capture ended: %+v", st)
		}
	})
}
