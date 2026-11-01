// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Segment is one TCP segment's addressing and payload, decoded from a frame.
type Segment struct {
	Src, Dst netip.AddrPort
	Seq      uint32
	SYN, ACK bool
	FIN, RST bool
	Payload  []byte
}

// DecodeFrame reads an Ethernet frame (with up to two VLAN tags) carrying
// IPv4 or IPv6 and TCP. ok is false for anything else.
func DecodeFrame(frame []byte) (Segment, bool) {
	if len(frame) < 14 {
		return Segment{}, false
	}
	etherType, rest := binary.BigEndian.Uint16(frame[12:14]), frame[14:]
	for i := 0; i < 2 && (etherType == 0x8100 || etherType == 0x88a8); i++ {
		if len(rest) < 4 {
			return Segment{}, false
		}
		etherType, rest = binary.BigEndian.Uint16(rest[2:4]), rest[4:]
	}
	var src, dst netip.Addr
	var tcp []byte
	switch etherType {
	case 0x0800:
		if len(rest) < 20 || rest[0]>>4 != 4 {
			return Segment{}, false
		}
		ihl := int(rest[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(rest[2:4]))
		fragment := binary.BigEndian.Uint16(rest[6:8])
		if rest[9] != 6 || ihl < 20 || total < ihl || total > len(rest) || fragment&0x3fff != 0 {
			return Segment{}, false
		}
		src, dst = netip.AddrFrom4([4]byte(rest[12:16])), netip.AddrFrom4([4]byte(rest[16:20]))
		tcp = rest[ihl:total]
	case 0x86dd:
		if len(rest) < 40 || rest[6] != 6 {
			return Segment{}, false
		}
		payload := int(binary.BigEndian.Uint16(rest[4:6]))
		if 40+payload > len(rest) {
			return Segment{}, false
		}
		src, dst = netip.AddrFrom16([16]byte(rest[8:24])), netip.AddrFrom16([16]byte(rest[24:40]))
		tcp = rest[40 : 40+payload]
	default:
		return Segment{}, false
	}
	if len(tcp) < 20 {
		return Segment{}, false
	}
	offset := int(tcp[12]>>4) * 4
	if offset < 20 || offset > len(tcp) {
		return Segment{}, false
	}
	flags := tcp[13]
	return Segment{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:2])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:4])),
		Seq:     binary.BigEndian.Uint32(tcp[4:8]),
		FIN:     flags&0x01 != 0,
		SYN:     flags&0x02 != 0,
		RST:     flags&0x04 != 0,
		ACK:     flags&0x10 != 0,
		Payload: tcp[offset:],
	}, true
}

// Event is one observed connection, emitted once.
type Event struct {
	Server netip.AddrPort
	Client netip.Addr
	At     time.Time
	Obs    Observation
}

// Stats counts what the assembler did; drops are never silent.
type Stats struct {
	Segments      uint64 `json:"segments"`
	Connections   uint64 `json:"connections"`
	Observations  uint64 `json:"observations"`
	TableFull     uint64 `json:"table_full"`
	OutOfOrder    uint64 `json:"out_of_order"`
	Unrecognized  uint64 `json:"unrecognized"`
	ActiveFlows   int    `json:"active_flows"`
	BufferedBytes int    `json:"buffered_bytes"`
}

type flowKey struct{ lo, hi netip.AddrPort }

func keyOf(a, b netip.AddrPort) flowKey {
	if a.Compare(b) < 0 {
		return flowKey{a, b}
	}
	return flowKey{b, a}
}

type flow struct {
	client, server         netip.AddrPort
	clientNext, serverNext uint32
	clientSet, serverSet   bool
	clientBuf, serverBuf   []byte
	finished               bool
	last                   time.Time
}

// Assembler follows TCP connections to watched server ports in order, feeds
// the first bytes of each direction to Parse, emits one Event per connection
// it can read, and drops the bytes. The flow table and every buffer are
// bounded; a connection that would exceed them is counted, never stored.
type Assembler struct {
	mu       sync.Mutex
	ports    map[uint16]bool
	maxFlows int
	idle     time.Duration
	flows    map[flowKey]*flow
	emit     func(Event)
	stats    Stats
	swept    time.Time
}

// NewAssembler watches the given server ports with at most maxFlows open
// connections, forgetting one idle for longer than idle.
func NewAssembler(ports []uint16, maxFlows int, idle time.Duration, emit func(Event)) *Assembler {
	watched := map[uint16]bool{}
	for _, p := range ports {
		watched[p] = true
	}
	return &Assembler{ports: watched, maxFlows: maxFlows, idle: idle, flows: map[flowKey]*flow{}, emit: emit}
}

// Stats reports the assembler's counters and its current footprint.
func (a *Assembler) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.stats
	s.ActiveFlows = len(a.flows)
	for _, f := range a.flows {
		s.BufferedBytes += len(f.clientBuf) + len(f.serverBuf)
	}
	return s
}

// Segment feeds one decoded segment.
func (a *Assembler) Segment(s Segment, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.Segments++
	if now.Sub(a.swept) > a.idle/2 {
		a.sweep(now)
	}
	key := keyOf(s.Src, s.Dst)
	f := a.flows[key]
	if f == nil {
		if !a.ports[s.Dst.Port()] || s.RST || s.FIN || (s.SYN && s.ACK) {
			return
		}
		if len(a.flows) >= a.maxFlows {
			a.stats.TableFull++
			return
		}
		f = &flow{client: s.Src, server: s.Dst}
		a.flows[key] = f
		a.stats.Connections++
	}
	f.last = now
	if s.RST || s.FIN {
		a.finish(key, f, now)
		return
	}
	fromClient := s.Src == f.client
	next, set := &f.serverNext, &f.serverSet
	if fromClient {
		next, set = &f.clientNext, &f.clientSet
	}
	if s.SYN {
		*next, *set = s.Seq+1, true
		return
	}
	if len(s.Payload) == 0 || f.finished {
		return
	}
	if !*set {
		// Joined mid-connection: read from here; Parse gives up on bytes
		// that do not start a handshake.
		*next, *set = s.Seq, true
	}
	payload := s.Payload
	if delta := int32(*next - s.Seq); delta > 0 { // #nosec G115 -- TCP sequence numbers wrap; the difference read as a signed 32-bit distance is RFC 1982 serial arithmetic (CWE-190)
		if int(delta) >= len(payload) {
			return // a retransmission of bytes already read
		}
		payload = payload[delta:]
	} else if delta < 0 {
		a.stats.OutOfOrder++
		f.finished = true
		f.clientBuf, f.serverBuf = nil, nil
		return
	}
	*next += uint32(len(payload)) // #nosec G115 -- one segment's payload is under 64 KiB, and sequence numbers wrap mod 2^32 by design (CWE-190)
	if fromClient {
		f.clientBuf = appendBounded(f.clientBuf, payload)
	} else {
		f.serverBuf = appendBounded(f.serverBuf, payload)
	}
	obs, ok, done := Parse(f.clientBuf, f.serverBuf)
	if done {
		a.complete(f, obs, ok, now)
	}
}

func appendBounded(buf, payload []byte) []byte {
	if room := MaxDirectionBytes - len(buf); len(payload) > room {
		payload = payload[:room]
	}
	return append(buf, payload...)
}

func (a *Assembler) complete(f *flow, obs Observation, ok bool, now time.Time) {
	f.finished = true
	f.clientBuf, f.serverBuf = nil, nil
	if !ok {
		a.stats.Unrecognized++
		return
	}
	a.stats.Observations++
	a.emit(Event{Server: f.server, Client: f.client.Addr(), At: now, Obs: obs})
}

func (a *Assembler) finish(key flowKey, f *flow, now time.Time) {
	if !f.finished {
		obs, ok, _ := Parse(f.clientBuf, f.serverBuf)
		a.complete(f, obs, ok, now)
	}
	delete(a.flows, key)
}

func (a *Assembler) sweep(now time.Time) {
	a.swept = now
	for key, f := range a.flows {
		if now.Sub(f.last) > a.idle {
			a.finish(key, f, now)
		}
	}
}
