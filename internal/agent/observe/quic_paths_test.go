// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	_ "embed"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// captureDatagrams is a saved capture's frames, their times, and each
// frame's UDP datagram.
func captureDatagrams(t *testing.T, file string) ([][]byte, []time.Time, []Datagram) {
	t.Helper()
	frames, times, err := pcapFrames(readFixture(t, file))
	if err != nil {
		t.Fatal(err)
	}
	datagrams := make([]Datagram, len(frames))
	for i, frame := range frames {
		d, ok := DecodeUDPFrame(frame)
		if !ok {
			t.Fatalf("%s: frame %d is not UDP", file, i+1)
		}
		datagrams[i] = d
	}
	return frames, times, datagrams
}

// replayQUICFrames feeds frames to an assembler watching port and ends what
// is open.
func replayQUICFrames(frames [][]byte, times []time.Time, port uint16) ([]Event, Stats, *Assembler) {
	var events []Event
	a := NewAssembler([]uint16{port}, 16, time.Minute, func(e Event) { events = append(events, e) })
	for i, frame := range frames {
		a.Frame(frame, times[i])
	}
	a.Flush(time.Unix(2_000_000_000, 0))
	return events, a.Stats(), a
}

// isRetry reports whether a datagram starts with a QUIC v1 Retry packet.
func isRetry(d Datagram) bool {
	return len(d.Payload) > 5 && d.Payload[0]&0xf0 == 0xf0 && binary.BigEndian.Uint32(d.Payload[1:5]) == 1
}

// withPort copies an IPv4 UDP frame with its source port (from, true) or
// destination port changed.
func withPort(frame []byte, source bool, port uint16) []byte {
	out := append([]byte(nil), frame...)
	udp := 14 + int(out[14]&0x0f)*4
	if !source {
		udp += 2
	}
	binary.BigEndian.PutUint16(out[udp:], port)
	return out
}

// X1-L4R: a real QUIC Retry flow is read. nginx 1.30.6 with quic_retry on
// answers each of the two Initial datagrams of OpenSSL 3.5.9's ClientHello
// with a Retry; the client acts on the first and sends its ClientHello again
// to the connection ID that Retry chose, under Initial keys derived from it.
// The observer reads the X25519MLKEM768 handshake. It acts as the client
// does (RFC 9000 section 17.2.5.2, RFC 9001 section 5.8): when the second
// Retry arrives after the client's next Initial, as a reordering network can
// deliver it, and when a Retry with a forged integrity tag follows, neither
// is acted on, and the handshake is still read.
func TestReplayedQUICRetryCaptureX1L4R(t *testing.T) {
	frames, times, datagrams := captureDatagrams(t, "testdata/x1l4r-quic-retry.pcap")
	var retries []int
	for i, d := range datagrams {
		if isRetry(d) {
			retries = append(retries, i)
		}
	}
	if len(retries) != 2 || retries[1] != retries[0]+1 {
		t.Fatalf("Retry datagrams at %v; want two in a row", retries)
	}
	second := retries[1]
	nextInitial := second + 1 // the client's first Initial after the Retry
	reordered := slices.Concat(frames[:second], frames[nextInitial:nextInitial+1], frames[second:second+1], frames[nextInitial+1:])
	reorderedTimes := slices.Concat(times[:second], times[nextInitial:nextInitial+1], times[second:second+1], times[nextInitial+1:])
	forged := append([]byte(nil), frames[second]...)
	forged[len(forged)-1] ^= 0x01
	after := nextInitial + 2
	withForged := slices.Concat(frames[:after], [][]byte{forged}, frames[after:])
	withForgedTimes := slices.Concat(times[:after], []time.Time{times[after-1]}, times[after:])
	for name, tc := range map[string]struct {
		frames [][]byte
		times  []time.Time
	}{
		"as captured":                        {frames, times},
		"the second Retry after the Initial": {reordered, reorderedTimes},
		"a second, forged Retry after them":  {withForged, withForgedTimes},
	} {
		events, st, _ := replayQUICFrames(tc.frames, tc.times, 8444)
		if len(events) != 1 {
			t.Fatalf("%s: %d handshakes, stats %+v; want one", name, len(events), st)
		}
		q := events[0].Obs
		if q.Protocol != "quic" || q.TLSVersion != "TLSv1.3" || q.CipherSuite != "TLS_AES_256_GCM_SHA384" || q.Group != "X25519MLKEM768" ||
			q.ServerName != "quic.x1l4r.test" || !q.CertificateHidden || events[0].Server.Port() != 8444 || st.Connections != 1 {
			t.Fatalf("%s: observation %+v at %s, stats %+v", name, q, events[0].Server, st)
		}
	}
}

// X1-L4R: a Retry whose integrity tag is not for this connection, which the
// client ignores, is ignored. X1-L4's nginx capture (no Retry) with a Retry
// from the Retry capture, addressed to this connection's ports, delivered
// after the client's ClientHello and before the server's Initial: the
// handshake is read as if it were not there.
func TestARetryForAnotherConnectionIsIgnoredX1L4R(t *testing.T) {
	frames, times, datagrams := captureDatagrams(t, "testdata/x1l4b-quic-mlkem.pcap")
	retryFrames, _, retryDatagrams := captureDatagrams(t, "testdata/x1l4r-quic-retry.pcap")
	var foreign []byte
	for i, d := range retryDatagrams {
		if isRetry(d) {
			foreign = retryFrames[i]
			break
		}
	}
	server := 0 // the server's first datagram
	for i, d := range datagrams {
		if d.Src.Port() == 8443 {
			server = i
			break
		}
	}
	if foreign == nil || server == 0 {
		t.Fatal("no Retry to insert, or no server datagram")
	}
	foreign = withPort(withPort(foreign, true, 8443), false, datagrams[0].Src.Port())
	injected := slices.Concat(frames[:server], [][]byte{foreign}, frames[server:])
	injectedTimes := slices.Concat(times[:server], []time.Time{times[server]}, times[server:])
	events, st, _ := replayQUICFrames(injected, injectedTimes, 8443)
	if len(events) != 1 || events[0].Obs.Group != "X25519MLKEM768" || events[0].Obs.ServerName != "quic.x1l4.test" {
		t.Fatalf("%d handshakes, stats %+v; want X1-L4's handshake", len(events), st)
	}
}

// X1-L4R: a NAT rebinding in the middle of a real QUIC handshake is
// followed. OpenSSL 3.5.9's QUIC client behind a NAT connects to Caddy
// 2.11.4 (whose QUIC is quic-go), captured where a mirror port in front of
// the server would be: the ClientHello's first Initial datagram from NAT
// port 41000 (its second was lost), the server's acknowledgment naming the
// connection ID it chose, the rest of the ClientHello from port 42000 after
// the NAT gave the client a new port, addressed to that connection ID, and
// the server's ServerHello sent back to port 41000. The observer follows the
// connection to the new port by its connection ID and reads one handshake,
// one connection with one path followed; the client's later Initials on the
// new port are the same connection.
func TestAPathChangeMidHandshakeIsFollowedX1L4R(t *testing.T) {
	frames, times, datagrams := captureDatagrams(t, "testdata/x1l4r-quic-rebinding.pcap")
	ports := map[uint16]bool{}
	for _, d := range datagrams {
		if d.Dst.Port() == 8443 {
			ports[d.Src.Port()] = true
		}
	}
	if !ports[41000] || !ports[42000] || len(ports) != 2 {
		t.Fatalf("client ports %v; want 41000 and 42000", ports)
	}
	events, st, a := replayQUICFrames(frames, times, 8443)
	if len(events) != 1 {
		t.Fatalf("%d handshakes, stats %+v; want one", len(events), st)
	}
	q := events[0].Obs
	if q.Protocol != "quic" || q.TLSVersion != "TLSv1.3" || q.CipherSuite != "TLS_AES_128_GCM_SHA256" || q.Group != "X25519MLKEM768" ||
		q.ServerName != "quic.x1l4r.test" || events[0].Server != netip.MustParseAddrPort("10.2.0.2:8443") ||
		events[0].Client != netip.MustParseAddr("10.2.0.1") {
		t.Fatalf("observation %+v between %s and %s", q, events[0].Client, events[0].Server)
	}
	if st.Connections != 1 || st.PathsFollowed != 1 || st.Unrecognized != 0 || st.ActiveFlows != 0 || len(a.cids) != 0 || len(a.udp) != 0 || a.udpPaths != 0 {
		t.Fatalf("stats %+v, %d connection IDs and %d pairs left", st, len(a.cids), len(a.udp))
	}
}

// X1-L4R: a path change after the handshake is the same connection too. In
// X1-L4's nginx capture the client's 1-RTT packets go to a connection ID the
// server issued in encrypted frames; with the client's last one moved to
// another port, as a NAT that rebinds between two of its packets would move
// it, the observer, which learned that connection ID from the client's
// previous 1-RTT packet at the length of the server's own, counts it once,
// not as a second connection it cannot read.
func TestAPathChangeAfterTheHandshakeIsTheSameConnectionX1L4R(t *testing.T) {
	frames, times, datagrams := captureDatagrams(t, "testdata/x1l4b-quic-mlkem.pcap")
	last, oneRTT := -1, 0
	for i, d := range datagrams {
		if d.Dst.Port() == 8443 && d.Payload[0]&0x80 == 0 {
			last, oneRTT = i, oneRTT+1
		}
	}
	if oneRTT < 2 {
		t.Fatalf("the capture has %d 1-RTT packets from the client; want two or more", oneRTT)
	}
	moved := append([][]byte(nil), frames...)
	moved[last] = withPort(frames[last], true, datagrams[last].Src.Port()+1)
	events, st, _ := replayQUICFrames(moved, times, 8443)
	if len(events) != 1 || st.Connections != 1 || st.PathsFollowed != 1 || st.Unrecognized != 0 {
		t.Fatalf("%d handshakes, stats %+v; want one connection with one path followed", len(events), st)
	}
}

// X1-L4R: following is bounded. A connection is followed on at most four
// address pairs and by at most four connection IDs; a datagram that names
// a followed connection ID but neither comes from nor goes to that
// connection's server is not joined to it; and when the connection ends,
// every pair and connection ID it was followed by is forgotten.
func TestQUICFollowingIsBoundedX1L4R(t *testing.T) {
	frames, times, datagrams := captureDatagrams(t, "testdata/x1l4r-quic-rebinding.pcap")
	var continuation int // the client's datagram from the new port
	for i, d := range datagrams {
		if d.Src.Port() == 42000 {
			continuation = i
			break
		}
	}
	var events []Event
	a := NewAssembler([]uint16{8443}, 16, time.Minute, func(e Event) { events = append(events, e) })
	for i := range continuation + 1 {
		a.Frame(frames[i], times[i])
	}
	at := times[continuation]
	for port := uint16(43000); port < 43006; port++ {
		a.Frame(withPort(frames[continuation], true, port), at)
	}
	elsewhere := withPort(frames[continuation], false, 9443)
	a.Frame(elsewhere, at)
	var f *udpFlow
	for _, flow := range a.udp {
		if flow.server.Port() == 8443 && len(flow.cids) > 0 {
			f = flow
		}
	}
	if f == nil || len(f.paths) != maxQUICPaths || len(f.cids) > maxQUICConnectionIDs || len(f.cids) == 0 {
		t.Fatalf("followed connection: %+v", f)
	}
	st := a.Stats()
	if st.PathsFollowed != maxQUICPaths-1 || st.Connections != 1+6-(maxQUICPaths-2) {
		t.Fatalf("stats %+v; want %d paths followed and the pairs past the bound counted as connections", st, maxQUICPaths-1)
	}
	for _, flow := range a.udp {
		if flow == f && flow.paths[0] != keyOf(datagrams[0].Src, datagrams[0].Dst) {
			t.Fatalf("the connection's first pair is %v", flow.paths[0])
		}
	}
	a.Flush(time.Unix(2_000_000_000, 0))
	if len(a.cids) != 0 || len(a.udp) != 0 || a.udpPaths != 0 || a.Stats().ActiveFlows != 0 {
		t.Fatalf("after the connections ended: %d connection IDs, %d pairs, %d extra paths", len(a.cids), len(a.udp), a.udpPaths)
	}
}

// FuzzQUICDatagram's seed capture is compiled in: the ClusterFuzzLite runner
// has no source tree to read it from.
//
//go:embed testdata/x1l4r-quic-rebinding.pcap
var seedRebindingCapture []byte

// FuzzQUICDatagram sends a hostile datagram both ways on new address pairs,
// after the real rebinding capture has left a followed connection (X1-L4R):
// nothing panics, no connection is followed on more pairs or by more
// connection IDs than its bounds, and once the connections end nothing they
// were followed by is left.
func FuzzQUICDatagram(f *testing.F) {
	frames, times, _ := pcapFrames(seedRebindingCapture)
	for _, frame := range frames {
		if d, ok := DecodeUDPFrame(frame); ok {
			f.Add(d.Payload)
		}
	}
	server := netip.MustParseAddrPort("10.2.0.2:8443")
	f.Fuzz(func(t *testing.T, payload []byte) {
		a := NewAssembler([]uint16{server.Port()}, 16, time.Minute, func(Event) {})
		for i, frame := range frames {
			a.Frame(frame, times[i])
		}
		at := times[len(times)-1]
		for port := uint16(45000); port < 45006; port++ {
			client := netip.AddrPortFrom(netip.MustParseAddr("10.2.0.1"), port)
			a.Datagram(Datagram{Src: client, Dst: server, Payload: payload}, at)
			a.Datagram(Datagram{Src: server, Dst: client, Payload: payload}, at)
		}
		for _, flow := range a.udp {
			if len(flow.paths) > maxQUICPaths || len(flow.cids) > maxQUICConnectionIDs {
				t.Fatalf("a connection followed on %d pairs by %d connection IDs", len(flow.paths), len(flow.cids))
			}
		}
		a.Flush(time.Unix(2_000_000_000, 0))
		if len(a.udp) != 0 || len(a.cids) != 0 || a.udpPaths != 0 {
			t.Fatalf("after the connections ended: %d pairs, %d connection IDs, %d extra paths", len(a.udp), len(a.cids), a.udpPaths)
		}
	})
}
