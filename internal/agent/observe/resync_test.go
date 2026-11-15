// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"testing"
	"time"
)

// The X1-L3R server's port, and when the lost-segment capture's client
// acknowledged bytes past the gap and the server's FIN ended the connection.
const resyncServerPort = 8443

var (
	acknowledgedPastGap = time.Unix(0, 1794731558136307112)
	serverFIN           = time.Unix(0, 1794731558140329072)
)

// X1-L3R: the dumpcap capture without its packet 8, a 524-byte segment inside
// the server's Certificate record that the capture missed and the client
// received (editcap deleted it), still yields the TLS 1.2 handshake. The
// client's acknowledgment of bytes past the gap shows the gap will never
// fill: the observer cuts the server's bytes back to the end of the
// ServerHello record, resumes at the ServerKeyExchange record header after
// the gap, and reads the X25519 group and the end of the flight then, at that
// acknowledgment rather than when the connection ends. The certificate the
// gap cut through is not reported. X1-L3's reordered capture, whose gaps fill,
// is not resynchronized.
func TestALostSegmentResynchronizesAtTheNextRecordX1L3R(t *testing.T) {
	events, st, packets := replayCapture(t, readFixture(t, "testdata/x1l3r-tls12-lost-segment.pcap"), 0, resyncServerPort)
	if packets != 25 || len(events) != 1 {
		t.Fatalf("%d packets, events %+v, stats %+v; want 25 packets and one handshake", packets, events, st)
	}
	obs := events[0].Obs
	if obs.TLSVersion != "TLSv1.2" || obs.CipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || obs.Group != "x25519" ||
		obs.ServerName != "resync.example.test" || obs.CertificateDER != nil || !events[0].At.Equal(acknowledgedPastGap) {
		t.Fatalf("observation %+v at %s; want TLS 1.2 with x25519 and no certificate at %s", obs, events[0].At, acknowledgedPastGap)
	}
	if st.Resynced != 1 || st.OutOfOrder != 0 || st.ActiveFlows != 0 || st.BufferedBytes != 0 {
		t.Fatalf("stats %+v", st)
	}
	_, st, _ = replayCapture(t, readFixture(t, "testdata/x1l3-tls13-mlkem-reordered.pcap"), 0, 8443)
	if st.Resynced != 0 || st.Reordered == 0 || st.OutOfOrder != 0 {
		t.Fatalf("the reordered capture: stats %+v", st)
	}
}

// lostSegmentFrames is the lost-segment capture's frames with their times,
// without the client's segments after its ClientHello, so that no
// acknowledgment past the gap is seen.
func lostSegmentFrames(t *testing.T) ([][]byte, []time.Time) {
	t.Helper()
	frames, times, err := pcapFrames(readFixture(t, "testdata/x1l3r-tls12-lost-segment.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	var keptFrames [][]byte
	var keptTimes []time.Time
	hello := false
	for i, frame := range frames {
		s, ok := DecodeFrame(frame)
		if !ok {
			t.Fatalf("frame %d did not decode", i)
		}
		fromClient := s.Dst.Port() == resyncServerPort
		if fromClient && hello {
			continue
		}
		hello = hello || (fromClient && len(s.Payload) > 0)
		keptFrames, keptTimes = append(keptFrames, frame), append(keptTimes, times[i])
	}
	return keptFrames, keptTimes
}

// replayFrames feeds frames to an assembler with the hold at held (0: the
// default) and ends what is open.
func replayFrames(t *testing.T, frames [][]byte, times []time.Time, held int) ([]Event, Stats) {
	t.Helper()
	var events []Event
	a := NewAssembler([]uint16{resyncServerPort}, 16, time.Minute, func(e Event) { events = append(events, e) })
	if held > 0 {
		if err := a.SetMaxHeldSegments(held); err != nil {
			t.Fatal(err)
		}
	}
	for i, frame := range frames {
		a.Frame(frame, times[i])
	}
	a.Flush(time.Unix(2_000_000_000, 0))
	return events, a.Stats()
}

// X1-L3R: with no acknowledgment past the gap in the capture (the client's
// segments after its ClientHello removed), the same gap is skipped when the
// server's FIN ends the connection, and the handshake is read then.
func TestAGapOpenWhenTheConnectionEndsIsSkippedX1L3R(t *testing.T) {
	frames, times := lostSegmentFrames(t)
	events, st := replayFrames(t, frames, times, 0)
	if len(events) != 1 || events[0].Obs.Group != "x25519" || events[0].Obs.CertificateDER != nil || !events[0].At.Equal(serverFIN) {
		t.Fatalf("events %+v, stats %+v; want the x25519 handshake at the server's FIN %s", events, st, serverFIN)
	}
	if st.Resynced != 1 || st.OutOfOrder != 0 || st.BufferedBytes != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// reframe copies a TCP-over-IPv4 frame, with its addresses, flags and
// acknowledgment, around a new sequence number and payload.
func reframe(orig []byte, seq uint32, payload []byte) []byte {
	ihl := int(orig[14]&0x0f) * 4
	head := 14 + ihl + int(orig[14+ihl+12]>>4)*4
	out := append(append([]byte(nil), orig[:head]...), payload...)
	binary.BigEndian.PutUint16(out[16:18], uint16(head-14+len(payload))) // #nosec G115 -- a bounded test frame (CWE-190)
	binary.BigEndian.PutUint32(out[14+ihl+4:], seq)
	return out
}

// X1-L3R: the hold is configurable. The lost-segment capture, without the
// client's later segments, with the server's segments after the gap re-framed
// as segments of at most 100 bytes (20 before the end of the flight): at the
// default hold of 16 the 17th finds it full before the ServerKeyExchange
// record is whole, so no record can be resumed at and the connection is given
// up, counted out of order. With the hold at 20 (SetMaxHeldSegments, which
// the agent's --observe-hold-segments sets) the first segment after the
// flight finds it full with the flight held, and the observer resynchronizes
// then, before the connection ends. A hold of 0 or past 1024 is refused.
func TestTheHoldIsConfigurableX1L3R(t *testing.T) {
	frames, times := lostSegmentFrames(t)
	var small [][]byte
	var smallTimes []time.Time
	gap := false
	var serverNext uint32
	for i, frame := range frames {
		s, _ := DecodeFrame(frame)
		if s.Src.Port() == resyncServerPort && len(s.Payload) > 0 {
			gap = gap || (serverNext != 0 && s.Seq != serverNext)
			serverNext = s.Seq + uint32(len(s.Payload)) // #nosec G115 -- a bounded test segment (CWE-190)
			if gap {
				for off := 0; off < len(s.Payload); off += 100 {
					piece := s.Payload[off:min(off+100, len(s.Payload))]
					small = append(small, reframe(frame, s.Seq+uint32(off), piece)) // #nosec G115 -- a bounded test offset (CWE-190)
					smallTimes = append(smallTimes, times[i])
				}
				continue
			}
		}
		small, smallTimes = append(small, frame), append(smallTimes, times[i])
	}
	if len(small) <= len(frames) {
		t.Fatal("nothing was re-framed")
	}
	events, st := replayFrames(t, small, smallTimes, 0)
	if len(events) != 0 || st.OutOfOrder != 1 || st.Resynced != 0 || st.BufferedBytes != 0 {
		t.Fatalf("at the default hold: events %+v, stats %+v; want the connection given up", events, st)
	}
	events, st = replayFrames(t, small, smallTimes, 20)
	if len(events) != 1 || events[0].Obs.Group != "x25519" || !events[0].At.Before(serverFIN) || st.Resynced != 1 || st.OutOfOrder != 0 {
		t.Fatalf("at a hold of 20: events %+v, stats %+v; want the x25519 handshake before the server's FIN", events, st)
	}
	a := NewAssembler([]uint16{443}, 4, time.Minute, func(Event) {})
	for _, n := range []int{0, -1, MaxHeldSegmentsLimit + 1} {
		if err := a.SetMaxHeldSegments(n); err == nil {
			t.Errorf("a hold of %d was taken", n)
		}
	}
	if err := a.SetMaxHeldSegments(MaxHeldSegmentsLimit); err != nil {
		t.Errorf("a hold of %d: %v", MaxHeldSegmentsLimit, err)
	}
}

// X1-L3R: resynchronizing reads only what is TLS from the first byte, and
// resumes only where records run on: a direction whose bytes are not TLS
// records, or that read no whole record before the gap, is not cut; a
// record header the held bytes only begin is not resumed at, and neither is
// a handshake record that does not open a message; a record cut back at
// the gap leaves no handshake message unfinished.
func TestResynchronizationResumesOnlyAtRecordsThatRunOnX1L3R(t *testing.T) {
	record := func(typ byte, body []byte) []byte {
		return append([]byte{typ, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...) // #nosec G115 -- a bounded test record (CWE-190)
	}
	message := func(kind byte, body []byte) []byte {
		return append([]byte{kind, 0, byte(len(body) >> 8), byte(len(body))}, body...) // #nosec G115 -- a bounded test message (CWE-190)
	}
	hello := record(0x16, message(2, bytes.Repeat([]byte{7}, 40)))
	cert := message(11, bytes.Repeat([]byte{9}, 300))
	for name, tc := range map[string]struct {
		buf     []byte
		cut     int
		resumes bool
	}{
		"a whole ServerHello":                {append(append([]byte(nil), hello...), record(0x16, cert[:100])[:50]...), len(hello), true},
		"a message split across two records": {append(append(append([]byte(nil), hello...), record(0x16, cert[:150])...), record(0x16, cert[150:])[:20]...), len(hello), true},
		"no whole record":                    {hello[:30], 0, false},
		"not TLS":                            {[]byte("SSH-2.0-OpenSSH_10.0\r\n"), 0, false},
	} {
		cut, ok := tlsResumeCut(tc.buf)
		if cut != tc.cut || ok != tc.resumes {
			t.Errorf("%s: cut %d, %v; want %d, %v", name, cut, ok, tc.cut, tc.resumes)
		}
	}
	kx := record(0x16, message(12, append([]byte{0x03, 0x00, 0x1d}, bytes.Repeat([]byte{5}, 60)...)))
	done := record(0x16, message(14, nil))
	tail := bytes.Repeat([]byte{0x16, 0x03, 0x03}, 10) // record-like bytes inside a certificate
	for name, tc := range map[string]struct {
		run  []byte
		want int
	}{
		"a key exchange and the end of the flight": {append(append(append([]byte(nil), tail...), kx...), done...), len(tail)},
		"a header the held bytes only begin":       {append(append([]byte(nil), tail...), kx[:20]...), -1},
		"a record that ends where the run does":    {append(append([]byte(nil), tail...), done...), len(tail)},
		"a handshake record opening no message":    {append(append([]byte(nil), tail...), record(0x16, []byte{0xee, 1, 2, 3, 4})...), -1},
		"a change of cipher spec and an alert":     {append(append(append([]byte(nil), tail...), record(0x14, []byte{1})...), record(0x15, []byte{1, 0})...), len(tail)},
	} {
		if got := nextTLSRecord(tc.run); got != tc.want {
			t.Errorf("%s: resumes at %d, want %d", name, got, tc.want)
		}
	}
}

// FuzzTLSResync's seeds are compiled in: the ClusterFuzzLite runner has no
// source tree to read them from.
//
//go:embed testdata/x1l3r-tls12-lost-segment.pcap
var seedLostSegmentCapture []byte

// FuzzTLSResync drives hostile bytes through the cut and the resume search
// (X1-L3R): neither panics, the cut stays inside the bytes, and a resume
// point found is a record from which records run on.
func FuzzTLSResync(f *testing.F) {
	frames, _, _ := pcapFrames(seedLostSegmentCapture)
	for _, frame := range frames {
		if s, ok := DecodeFrame(frame); ok && len(s.Payload) > 0 {
			f.Add(s.Payload)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if cut, ok := tlsResumeCut(b); cut < 0 || cut > len(b) || ok != (cut > 0) {
			t.Fatalf("cut %d, %v of %d bytes", cut, ok, len(b))
		}
		if at := nextTLSRecord(b); at >= 0 && (at+5 > len(b) || !recordsRunToEnd(b[at:])) {
			t.Fatalf("resumes at %d of %d bytes", at, len(b))
		}
	})
}
