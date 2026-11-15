// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Segment is one TCP segment's addressing and payload, decoded from a frame.
type Segment struct {
	Src, Dst netip.AddrPort
	Seq      uint32
	// Ack is the acknowledgment number, meaningful when ACK is set.
	Ack      uint32
	SYN, ACK bool
	FIN, RST bool
	Payload  []byte
}

// DecodeFrame reads an Ethernet frame (with up to maxVLANTags VLAN tags)
// carrying a whole IPv4 or IPv6 packet and TCP, walking IPv6 extension
// headers. ok is false for anything else, a fragment among it: Assembler.Frame
// reassembles those (X1-L2R).
func DecodeFrame(frame []byte) (Segment, bool) {
	pkt, ok := decodePacket(frame)
	if !ok {
		return Segment{}, false
	}
	return segmentOf(pkt)
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
	Segments uint64 `json:"segments"`
	// Datagrams counts UDP datagrams read for QUIC and DTLS (X1-L4).
	Datagrams    uint64 `json:"datagrams"`
	Connections  uint64 `json:"connections"`
	Observations uint64 `json:"observations"`
	TableFull    uint64 `json:"table_full"`
	OutOfOrder   uint64 `json:"out_of_order"`
	// Reordered counts segments that arrived ahead of a gap, were held, and
	// were read once the gap filled (X1-L3).
	Reordered uint64 `json:"reordered"`
	// Resynced counts gaps that would never fill, skipped to the next TLS
	// record header after them (X1-L3R): the other side acknowledged bytes
	// the capture never carried, the hold filled, or the connection ended.
	Resynced     uint64 `json:"resynced"`
	Unrecognized uint64 `json:"unrecognized"`
	// PathsFollowed counts address pairs joined to a QUIC connection
	// already followed, by its connection IDs: a NAT rebinding or a client
	// that moved (X1-L4R).
	PathsFollowed uint64 `json:"paths_followed"`
	// Fragments counts IP fragments read, Reassembled the datagrams rebuilt
	// from them, and FragmentsDropped the fragments of datagrams given up:
	// overlapping, oversized, timed out or past the table's bound (X1-L2R).
	Fragments        uint64 `json:"fragments"`
	Reassembled      uint64 `json:"reassembled"`
	FragmentsDropped uint64 `json:"fragments_dropped"`
	ActiveFlows      int    `json:"active_flows"`
	BufferedBytes    int    `json:"buffered_bytes"`
	// ClosedFlows is how many connections one side has ended and the
	// assembler still remembers (X1-L7); ClosedTableFull counts ends it
	// could not remember because that table was full.
	ClosedFlows     int    `json:"closed_flows"`
	ClosedTableFull uint64 `json:"closed_table_full"`
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
	fromClient, fromServer direction
	finished               bool
	last                   time.Time
}

// direction is one side of a connection: the next sequence number to read,
// the bytes read so far, and the segments held past a gap (X1-L3).
type direction struct {
	next  uint32
	set   bool
	buf   []byte
	ahead []heldSegment
	// triedRead and triedHeld are how many bytes were read and held when a
	// resynchronization last found nothing to resume at; another try waits
	// for either to change (X1-L3R).
	triedRead, triedHeld int
}

// heldSegment is a segment that arrived ahead of a gap in its direction,
// kept until the bytes before it arrive (X1-L3).
type heldSegment struct {
	seq     uint32
	payload []byte
}

const (
	// DefaultMaxHeldSegments is how many segments one direction holds while
	// it waits for a gap to fill, unless SetMaxHeldSegments says otherwise.
	// One more skips the gap if a TLS record follows it (X1-L3R) and
	// otherwise ends reading that connection, counted as out of order. Held
	// bytes stay inside the first MaxDirectionBytes, the only part Parse
	// reads, whatever the count.
	DefaultMaxHeldSegments = 16
	// MaxHeldSegmentsLimit bounds SetMaxHeldSegments.
	MaxHeldSegmentsLimit = 1024
)

func heldBytes(held []heldSegment) int {
	n := 0
	for _, h := range held {
		n += len(h.payload)
	}
	return n
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
	// closed remembers a connection one side ended with a FIN (X1-L7)
	// until the other side's FIN, an RST, a new SYN on the same addresses
	// or the idle sweep, so the other side's last bytes (a TLS
	// close_notify, the final ACK) do not open it again mid-stream and
	// count it twice. It holds at most maxFlows entries.
	closed map[flowKey]closedFlow
	udp    map[flowKey]*udpFlow
	// cids finds a QUIC connection by a connection ID it was seen with, and
	// cidLengths records those IDs' lengths; udpPaths counts the address
	// pairs in udp that are a followed connection's second or later path
	// (X1-L4R).
	cids       map[string]*udpFlow
	cidLengths uint32
	udpPaths   int
	// reasm rebuilds fragmented IP datagrams (X1-L2R).
	reasm *reassembler
	// maxHeld bounds the segments one direction holds past a gap (X1-L3R).
	maxHeld int
	emit    func(Event)
	stats   Stats
	swept   time.Time
}

// NewAssembler watches the given server ports with at most maxFlows open
// connections, forgetting one idle for longer than idle.
func NewAssembler(ports []uint16, maxFlows int, idle time.Duration, emit func(Event)) *Assembler {
	watched := map[uint16]bool{}
	for _, p := range ports {
		watched[p] = true
	}
	return &Assembler{ports: watched, maxFlows: maxFlows, idle: idle, flows: map[flowKey]*flow{}, closed: map[flowKey]closedFlow{},
		udp: map[flowKey]*udpFlow{}, cids: map[string]*udpFlow{}, reasm: newReassembler(), maxHeld: DefaultMaxHeldSegments, emit: emit}
}

// SetMaxHeldSegments sets how many segments one direction of a connection
// holds while it waits for a gap to fill (X1-L3R), from 1 to
// MaxHeldSegmentsLimit. Held bytes stay inside MaxDirectionBytes whatever the
// count, so a larger hold costs a segment header each, not more bytes.
func (a *Assembler) SetMaxHeldSegments(n int) error {
	if n < 1 || n > MaxHeldSegmentsLimit {
		return fmt.Errorf("observe: the hold is 1 to %d segments, not %d", MaxHeldSegmentsLimit, n)
	}
	a.mu.Lock()
	a.maxHeld = n
	a.mu.Unlock()
	return nil
}

// Frame reads one captured Ethernet frame (X1-L2R): a TCP segment goes to
// Segment and a UDP datagram to Datagram, and an IPv4 or IPv6 fragment is held
// until its datagram is whole.
func (a *Assembler) Frame(frame []byte, at time.Time) {
	pkt, ok := decodePacket(frame)
	if !ok {
		return
	}
	if pkt.frag != nil {
		a.mu.Lock()
		whole, done := a.reasm.add(pkt, at, &a.stats)
		a.mu.Unlock()
		if !done {
			return
		}
		pkt = whole
	}
	if seg, ok := segmentOf(pkt); ok {
		a.Segment(seg, at)
	} else if d, ok := datagramOf(pkt); ok {
		a.Datagram(d, at)
	}
}

// closedFlow is a connection one side ended: when, and which side.
type closedFlow struct {
	at     time.Time
	closer netip.AddrPort
}

// Stats reports the assembler's counters and its current footprint.
func (a *Assembler) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.stats
	s.ActiveFlows = a.activeFlows()
	s.ClosedFlows = len(a.closed)
	for _, f := range a.flows {
		s.BufferedBytes += len(f.fromClient.buf) + len(f.fromServer.buf) + heldBytes(f.fromClient.ahead) + heldBytes(f.fromServer.ahead)
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
		if c, ok := a.closed[key]; ok {
			if !s.SYN || s.ACK {
				// The ended connection's last segments: read nothing,
				// count nothing; the other side's FIN or an RST ends it.
				if s.RST || (s.FIN && s.Src != c.closer) {
					delete(a.closed, key)
				}
				return
			}
			delete(a.closed, key) // a new connection on the same addresses
		}
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
		if !s.RST {
			a.rememberClosed(key, s.Src, now)
		}
		return
	}
	d, other := &f.fromServer, &f.fromClient
	if s.Src == f.client {
		d, other = &f.fromClient, &f.fromServer
	}
	if s.SYN {
		d.next, d.set = s.Seq+1, true
		return
	}
	if s.ACK && !f.finished && a.acknowledged(other, s.Ack) && a.completeIfDone(f, now) {
		return
	}
	if len(s.Payload) == 0 || f.finished {
		return
	}
	if !d.set {
		// Joined mid-connection: read from here; Parse gives up on bytes
		// that do not start a handshake.
		d.next, d.set = s.Seq, true
	}
	payload := s.Payload
	if delta := int32(d.next - s.Seq); delta > 0 { // #nosec G115 -- TCP sequence numbers wrap; the difference read as a signed 32-bit distance is RFC 1982 serial arithmetic (CWE-190)
		if int(delta) >= len(payload) {
			return // a retransmission of bytes already read
		}
		payload = payload[delta:]
	} else if delta < 0 {
		// Ahead of a gap: hold it until the bytes before it arrive. A full
		// hold means the gap is not filling: skip it if a TLS record
		// follows (X1-L3R), then hold this segment against where reading
		// resumed; otherwise give the connection up.
		if !a.hold(d, s.Seq, payload) {
			if !a.resync(d) {
				a.stats.OutOfOrder++
				a.abandon(f)
				return
			}
			if !a.hold(d, s.Seq, payload) {
				a.stats.OutOfOrder++
				a.abandon(f)
				return
			}
			a.stats.Reordered += a.release(d)
			a.completeIfDone(f, now)
		}
		return
	}
	d.next += uint32(len(payload)) // #nosec G115 -- one segment's payload is under 64 KiB, and sequence numbers wrap mod 2^32 by design (CWE-190)
	d.buf = appendBounded(d.buf, payload)
	a.stats.Reordered += a.release(d)
	a.completeIfDone(f, now)
}

// completeIfDone parses what the connection has read and completes it once
// nothing more can be learned, reporting whether it did.
func (a *Assembler) completeIfDone(f *flow, now time.Time) bool {
	obs, ok, done := Parse(f.fromClient.buf, f.fromServer.buf)
	if done {
		a.complete(f, obs, ok, now)
	}
	return done
}

// hold keeps a copy of a segment that starts past what the direction has
// read, trimmed to the part Parse can still use; a segment at or before that
// point is read, not held. A segment wholly past the usable part is dropped
// and changes nothing. It reports false when the direction already holds
// maxHeld segments or MaxDirectionBytes held bytes.
func (a *Assembler) hold(d *direction, seq uint32, payload []byte) bool {
	gap := -int(int32(d.next - seq)) // #nosec G115 -- RFC 1982 serial arithmetic on wrapping sequence numbers (CWE-190)
	if gap <= 0 {
		// Reading resumed at or past this segment's start: it is read like
		// any in-order segment once released.
		gap = 0
	}
	room := MaxDirectionBytes - len(d.buf) - gap
	if room <= 0 {
		return true
	}
	if len(payload) > room {
		payload = payload[:room]
	}
	if len(d.ahead) >= a.maxHeld || heldBytes(d.ahead)+len(payload) > MaxDirectionBytes {
		return false
	}
	d.ahead = append(d.ahead, heldSegment{seq: seq, payload: append([]byte(nil), payload...)})
	return true
}

// release reads every held segment the stream has now reached, in order,
// drops those whose bytes were all read already, and returns how many it
// read.
func (a *Assembler) release(d *direction) uint64 {
	var read uint64
	for progressed := true; progressed && len(d.ahead) > 0; {
		progressed = false
		kept := d.ahead[:0]
		for _, h := range d.ahead {
			delta := int32(d.next - h.seq) // #nosec G115 -- RFC 1982 serial arithmetic on wrapping sequence numbers (CWE-190)
			switch {
			case delta < 0:
				kept = append(kept, h)
			case int(delta) < len(h.payload):
				chunk := h.payload[delta:]
				d.next += uint32(len(chunk)) // #nosec G115 -- a held payload is under MaxDirectionBytes, and sequence numbers wrap by design (CWE-190)
				d.buf = appendBounded(d.buf, chunk)
				read++
				progressed = true
			}
		}
		d.ahead = kept
	}
	return read
}

// abandon stops reading a connection and drops everything it held.
func (a *Assembler) abandon(f *flow) {
	f.finished = true
	f.fromClient.buf, f.fromServer.buf = nil, nil
	f.fromClient.ahead, f.fromServer.ahead = nil, nil
}

func appendBounded(buf, payload []byte) []byte {
	if room := MaxDirectionBytes - len(buf); len(payload) > room {
		payload = payload[:room]
	}
	return append(buf, payload...)
}

func (a *Assembler) complete(f *flow, obs Observation, ok bool, now time.Time) {
	a.abandon(f)
	if !ok {
		a.stats.Unrecognized++
		return
	}
	a.stats.Observations++
	a.emit(Event{Server: f.server, Client: f.client.Addr(), At: now, Obs: obs})
}

func (a *Assembler) finish(key flowKey, f *flow, now time.Time) {
	if !f.finished {
		// A gap still open when the connection ends will never fill
		// (X1-L3R).
		a.resync(&f.fromClient)
		a.resync(&f.fromServer)
		obs, ok, _ := Parse(f.fromClient.buf, f.fromServer.buf)
		a.complete(f, obs, ok, now)
	}
	delete(a.flows, key)
}

// rememberClosed records that closer ended the connection (X1-L7).
func (a *Assembler) rememberClosed(key flowKey, closer netip.AddrPort, now time.Time) {
	if len(a.closed) >= a.maxFlows {
		a.stats.ClosedTableFull++
		return
	}
	a.closed[key] = closedFlow{at: now, closer: closer}
}

func (a *Assembler) sweep(now time.Time) {
	a.swept = now
	for key, f := range a.flows {
		if now.Sub(f.last) > a.idle {
			a.finish(key, f, now)
		}
	}
	for key, c := range a.closed {
		if now.Sub(c.at) > a.idle {
			delete(a.closed, key)
		}
	}
	for key, f := range a.udp {
		if now.Sub(f.last) > a.idle {
			a.finishUDP(key, f, now)
		}
	}
}
