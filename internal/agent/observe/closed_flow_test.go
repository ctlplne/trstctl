// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"net/netip"
	"os"
	"testing"
	"time"
)

// X1-L7: in the real capture of an OpenSSL 3.5.9 TLS 1.3 handshake the
// server's FIN arrives first. The connection is counted once and its last
// client bytes (the close_notify) open nothing, so nothing reads as
// unrecognized, and the client's own FIN ends what the assembler remembered.
func TestServerFirstFINCountsTheConnectionOnceX1L7(t *testing.T) {
	data, err := os.ReadFile("testdata/x1l3-tls13-mlkem.pcap")
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	a := NewAssembler([]uint16{8443}, 16, time.Minute, func(e Event) { events = append(events, e) })
	if _, err := ReplayPcap(bytes.NewReader(data), a); err != nil {
		t.Fatal(err)
	}
	a.Flush(time.Now())
	if st := a.Stats(); len(events) != 1 || st.Connections != 1 || st.Unrecognized != 0 || st.ClosedFlows != 0 || st.ClosedTableFull != 0 {
		t.Fatalf("events %d, stats %+v; want one connection, nothing unrecognized, nothing left remembered", len(events), st)
	}
}

// X1-L7: a connection one side ended is remembered until the other side's
// FIN, an RST, a new SYN on the same addresses or the idle sweep, and the
// table that remembers it is bounded by the flow table's size.
func TestClosedFlowIsRememberedUntilTheOtherSideEndsItX1L7(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.10:50000")
	server := netip.MustParseAddrPort("198.51.100.1:443")
	now := time.Unix(1_800_000_000, 0)
	a := NewAssembler([]uint16{443}, 1, time.Minute, func(Event) {})
	open := func(c netip.AddrPort) {
		a.Segment(Segment{Src: c, Dst: server, SYN: true, Seq: 1}, now)
	}
	open(client)
	a.Segment(Segment{Src: server, Dst: client, FIN: true, ACK: true, Seq: 9}, now)
	// (This connection carried no handshake, so its end reads as one
	// unrecognized connection; what follows must add nothing to that.)
	unrecognized := a.Stats().Unrecognized
	// The client's close_notify and its ACK of the server's FIN open nothing.
	a.Segment(Segment{Src: client, Dst: server, ACK: true, Seq: 2, Payload: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}}, now)
	a.Segment(Segment{Src: client, Dst: server, ACK: true, Seq: 9}, now)
	if st := a.Stats(); st.Connections != 1 || st.ActiveFlows != 0 || st.ClosedFlows != 1 {
		t.Fatalf("after the server's FIN and the client's last bytes: %+v; want one connection, remembered closed", st)
	}
	// A FIN from the side that already closed does not end it; the other
	// side's does.
	a.Segment(Segment{Src: server, Dst: client, FIN: true, ACK: true, Seq: 9}, now)
	if st := a.Stats(); st.ClosedFlows != 1 {
		t.Fatalf("a repeated FIN from the closer ended the record: %+v", st)
	}
	a.Segment(Segment{Src: client, Dst: server, FIN: true, ACK: true, Seq: 9}, now)
	if st := a.Stats(); st.ClosedFlows != 0 || st.Connections != 1 || st.Unrecognized != unrecognized {
		t.Fatalf("after the client's FIN: %+v; want one connection and %d unrecognized", st, unrecognized)
	}

	// A new SYN on the same addresses is a new connection.
	open(client)
	a.Segment(Segment{Src: server, Dst: client, FIN: true, ACK: true, Seq: 9}, now)
	open(client)
	if st := a.Stats(); st.Connections != 3 || st.ActiveFlows != 1 || st.ClosedFlows != 0 {
		t.Fatalf("a new SYN after a server FIN: %+v; want it counted as a third connection", st)
	}
	// The bound: one flow at a time, so one remembered close; a second
	// connection's close is counted as not remembered.
	a.Segment(Segment{Src: server, Dst: client, FIN: true, ACK: true, Seq: 9}, now)
	other := netip.MustParseAddrPort("192.0.2.11:50001")
	open(other)
	a.Segment(Segment{Src: server, Dst: other, FIN: true, ACK: true, Seq: 9}, now)
	if st := a.Stats(); st.ClosedFlows != 1 || st.ClosedTableFull != 1 {
		t.Fatalf("the remembered closes are not bounded: %+v", st)
	}
	// The idle sweep forgets what is remembered.
	a.Segment(Segment{Src: netip.MustParseAddrPort("192.0.2.12:50002"), Dst: netip.MustParseAddrPort("198.51.100.1:80"), ACK: true}, now.Add(2*time.Minute))
	if st := a.Stats(); st.ClosedFlows != 0 {
		t.Fatalf("the idle sweep left %d remembered closes", st.ClosedFlows)
	}
}

// X1-L7: past 256 distinct clients an item's count is an estimate from a
// fixed 1 KiB sketch, within a few percent, never below 257; up to 256 it
// is exact, and a client seen again is not counted again.
func TestClientCountIsEstimatedPastTheExactSetX1L7(t *testing.T) {
	item := func(clients, repeats int) Item {
		t.Helper()
		g := NewAggregate(4)
		server := netip.MustParseAddrPort("198.51.100.1:443")
		at := time.Unix(1_800_000_000, 0)
		for r := 0; r < repeats; r++ {
			for i := 0; i < clients; i++ {
				addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) // #nosec G115 -- the test's client index fits three bytes (CWE-190)
				g.Add(Event{Server: server, Client: addr, At: at, Obs: Observation{Protocol: "tls", TLSVersion: "TLSv1.3", Group: "X25519"}})
			}
		}
		items, _ := g.Changed()
		if len(items) != 1 {
			t.Fatalf("%d clients: %d items", clients, len(items))
		}
		return items[0]
	}
	if got := item(256, 3); got.Clients != 256 || got.ClientsEstimated || got.Connections != 768 {
		t.Fatalf("256 clients three times: %d clients (estimated %v), %d connections", got.Clients, got.ClientsEstimated, got.Connections)
	}
	for _, n := range []int{257, 300, 10_000} {
		got := item(n, 2)
		if !got.ClientsEstimated || got.Clients < 257 || got.Connections != uint64(2*n) { // #nosec G115 -- small positive test counts (CWE-190)
			t.Fatalf("%d clients twice: %+v", n, got)
		}
		if diff := float64(got.Clients-n) / float64(n); diff > 0.05 || diff < -0.05 {
			t.Fatalf("%d clients estimated as %d (%.1f%% off); want within 5%%", n, got.Clients, 100*diff)
		}
	}
}
