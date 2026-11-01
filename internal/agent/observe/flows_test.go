// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// frame builds an Ethernet/IPv4/TCP frame.
func frame(src, dst netip.AddrPort, seq uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)+len(payload))) // #nosec G115 -- bounded test packet length (CWE-190)
	ip[8], ip[9] = 64, 6
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return bytes.Join([][]byte{eth, ip, tcp, payload}, nil)
}

const (
	fin = 0x01
	syn = 0x02
	rst = 0x04
	ack = 0x10
)

func TestAssemblerReadsOneConnectionInOrderAndKeepsNothing(t *testing.T) {
	client := netip.MustParseAddrPort("10.0.0.7:51000")
	server := netip.MustParseAddrPort("10.0.0.5:443")
	var events []Event
	a := NewAssembler([]uint16{443}, 16, time.Minute, func(e Event) { events = append(events, e) })
	now := time.Unix(1_700_000_000, 0)
	feed := func(src, dst netip.AddrPort, seq uint32, flags byte, payload []byte) {
		s, ok := DecodeFrame(frame(src, dst, seq, flags, payload))
		if !ok {
			t.Fatal("frame did not decode")
		}
		a.Segment(s, now)
	}
	hello := clientHello("api.example.test", 0x11ec)
	reply := bytes.Join([][]byte{serverHello13(0x1301, 0x11ec, nil), record(0x14, []byte{1}), record(0x17, []byte("secret app data"))}, nil)
	feed(client, server, 100, syn, nil)
	feed(server, client, 900, syn|ack, nil)
	// The ClientHello arrives in two segments, the second retransmitted once.
	feed(client, server, 101, ack, hello[:40])
	feed(client, server, 141, ack, hello[40:])
	feed(client, server, 141, ack, hello[40:])
	feed(server, client, 901, ack, reply)
	feed(client, server, 101+uint32(len(hello)), ack, []byte("more application data")) // #nosec G115 -- bounded test fixture length (CWE-190)
	feed(client, server, 200, fin|ack, nil)
	if len(events) != 1 || events[0].Server != server || events[0].Client != client.Addr() ||
		events[0].Obs.Group != "X25519MLKEM768" || events[0].Obs.TLSVersion != "TLSv1.3" {
		t.Fatalf("events = %+v", events)
	}
	if st := a.Stats(); st.ActiveFlows != 0 || st.BufferedBytes != 0 || st.Observations != 1 || st.Connections != 1 {
		t.Fatalf("stats after the connection closed = %+v", st)
	}
}

func TestAssemblerBoundsAndCountsWhatItDrops(t *testing.T) {
	var events []Event
	a := NewAssembler([]uint16{443}, 2, time.Second, func(e Event) { events = append(events, e) })
	now := time.Unix(1_700_000_000, 0)
	server := netip.MustParseAddrPort("10.0.0.5:443")
	for i := 0; i < 3; i++ {
		c := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.9"), uint16(40000+i))
		s, _ := DecodeFrame(frame(c, server, 1, syn, nil))
		a.Segment(s, now)
	}
	if st := a.Stats(); st.ActiveFlows != 2 || st.TableFull != 1 {
		t.Fatalf("flow table = %+v, want 2 flows and 1 refused", st)
	}
	// A gap ends reading of that connection, and it is counted.
	c := netip.MustParseAddrPort("10.0.0.9:40000")
	s, _ := DecodeFrame(frame(c, server, 500, ack, []byte("late")))
	a.Segment(s, now)
	if st := a.Stats(); st.OutOfOrder != 1 {
		t.Fatalf("stats = %+v, want one out-of-order connection", st)
	}
	// Idle connections are forgotten.
	s, _ = DecodeFrame(frame(netip.MustParseAddrPort("10.0.0.9:40001"), server, 2, ack, []byte("x")))
	a.Segment(s, now.Add(3*time.Second))
	if st := a.Stats(); st.ActiveFlows != 1 {
		t.Fatalf("idle sweep left %d flows", st.ActiveFlows)
	}
	// Ports nobody watches are ignored.
	s, _ = DecodeFrame(frame(netip.MustParseAddrPort("10.0.0.9:40009"), netip.MustParseAddrPort("10.0.0.5:5432"), 1, syn, nil))
	a.Segment(s, now.Add(3*time.Second))
	if st := a.Stats(); st.ActiveFlows != 1 || len(events) != 0 {
		t.Fatalf("an unwatched port opened a flow: %+v", st)
	}
}

func TestDecodeFrameRejectsNonTCPAndTruncated(t *testing.T) {
	good := frame(netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("10.0.0.2:443"), 1, syn, nil)
	for i := 0; i < len(good); i++ {
		if _, ok := DecodeFrame(good[:i]); ok {
			t.Fatalf("a %d-byte frame decoded", i)
		}
	}
	udp := bytes.Clone(good)
	udp[14+9] = 17
	if _, ok := DecodeFrame(udp); ok {
		t.Fatal("a UDP datagram decoded as TCP")
	}
}
