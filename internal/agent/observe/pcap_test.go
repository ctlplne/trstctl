// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// X1-L3: a real TLS 1.3 handshake captured with tcpdump (OpenSSL 3.5.9 on a
// Linux loopback at MTU 1280, segmentation offloads off, so the ClientHello
// and the server's first flight each span two segments) is read from the
// saved capture; and from a copy in which each of those second segments
// arrives before its first, the observer holds the early segment, reads the
// handshake once the gap fills, and reports the same X25519MLKEM768
// handshake.
func TestReplayedCaptureIsReadInEitherSegmentOrderX1L3(t *testing.T) {
	for _, tc := range []struct {
		file          string
		wantReordered bool
	}{
		{"testdata/x1l3-tls13-mlkem.pcap", false},
		{"testdata/x1l3-tls13-mlkem-reordered.pcap", true},
	} {
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		var events []Event
		a := NewAssembler([]uint16{8443}, 16, time.Minute, func(e Event) { events = append(events, e) })
		packets, err := ReplayPcap(bytes.NewReader(data), a)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		a.Flush(time.Now())
		st := a.Stats()
		if packets != 19 || len(events) != 1 {
			t.Fatalf("%s: %d packets, events %+v, stats %+v; want 19 packets and one handshake", tc.file, packets, events, st)
		}
		obs := events[0].Obs
		if obs.TLSVersion != "TLSv1.3" || obs.Group != "X25519MLKEM768" || obs.ServerName != "obs.example.test" || !obs.PQHybrid() ||
			events[0].Server.Port() != 8443 {
			t.Fatalf("%s: observation = %+v at %s", tc.file, obs, events[0].Server)
		}
		if st.OutOfOrder != 0 || (st.Reordered > 0) != tc.wantReordered || st.ActiveFlows != 0 || st.BufferedBytes != 0 {
			t.Fatalf("%s: stats = %+v", tc.file, st)
		}
	}
}

// A gap whose bytes never arrive reads what came before it when the
// connection ends, and nothing it held is kept.
func TestAGapThatNeverFillsKeepsNothingX1L3(t *testing.T) {
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
	hello := clientHello("gap.example.test", 0x11ec)
	feed(client, server, 100, syn, nil)
	feed(server, client, 900, syn|ack, nil)
	// The ClientHello's second half arrives; its first half never does.
	feed(client, server, 141, ack, hello[40:])
	if st := a.Stats(); st.BufferedBytes != len(hello)-40 || st.OutOfOrder != 0 {
		t.Fatalf("stats while waiting = %+v", st)
	}
	feed(client, server, 141+uint32(len(hello)-40), fin|ack, nil) // #nosec G115 -- bounded test fixture length (CWE-190)
	if st := a.Stats(); len(events) != 0 || st.ActiveFlows != 0 || st.BufferedBytes != 0 || st.Unrecognized != 1 {
		t.Fatalf("after the connection ended: events %+v, stats %+v", events, st)
	}
}

func TestReplayPcapRefusesWhatItDoesNotRead(t *testing.T) {
	a := NewAssembler([]uint16{443}, 4, time.Minute, func(Event) {})
	ng := make([]byte, 24)
	binary.LittleEndian.PutUint32(ng, 0x0a0d0d0a)
	if _, err := ReplayPcap(bytes.NewReader(ng), a); !errors.Is(err, ErrPcapNG) {
		t.Fatalf("pcapng = %v", err)
	}
	wifi := make([]byte, 24)
	binary.LittleEndian.PutUint32(wifi, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(wifi[20:], 105)
	if _, err := ReplayPcap(bytes.NewReader(wifi), a); err == nil || !strings.Contains(err.Error(), "link type 105") {
		t.Fatalf("an 802.11 capture = %v", err)
	}
	huge := make([]byte, 40)
	binary.LittleEndian.PutUint32(huge, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(huge[20:], pcapLinkEthernet)
	binary.LittleEndian.PutUint32(huge[32:], maxPcapRecord+1)
	if _, err := ReplayPcap(bytes.NewReader(huge), a); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("an oversized record = %v", err)
	}
}
