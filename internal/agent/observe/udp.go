// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/crypto/quicinitial"
)

// QUIC and DTLS over UDP (X1-L4 part 2). A QUIC handshake is TLS 1.3 carried
// in CRYPTO frames inside Initial packets, whose protection derives from the
// client's first Destination Connection ID and a published salt: the
// observer removes it as the server does (internal/crypto/quicinitial) and
// reads the ClientHello and ServerHello, however many packets they span. A
// DTLS handshake sends its hello messages, and on DTLS 1.2 the certificate
// and key exchange, in the clear, fragmented across records and datagrams
// and reassembled by message sequence. Nothing after those messages is read.

// Datagram is one UDP datagram's addressing and payload, decoded from a frame.
type Datagram struct {
	Src, Dst netip.AddrPort
	Payload  []byte
}

// DecodeUDPFrame reads an Ethernet frame (with up to maxVLANTags VLAN tags)
// carrying a whole IPv4 or IPv6 packet and UDP. ok is false for anything
// else, a fragment among it (X1-L2R).
func DecodeUDPFrame(frame []byte) (Datagram, bool) {
	pkt, ok := decodePacket(frame)
	if !ok {
		return Datagram{}, false
	}
	return datagramOf(pkt)
}

// maxUDPFlowDatagrams bounds how many datagrams of one flow are read before
// the observer gives up on its handshake.
const maxUDPFlowDatagrams = 32

const (
	// maxQUICConnectionIDs bounds the connection IDs one QUIC connection is
	// followed by: the client's first Destination Connection ID, its own,
	// and the ones the server chose in a Retry and in its Initial (X1-L4R).
	maxQUICConnectionIDs = 4
	// maxQUICPaths bounds the address pairs one QUIC connection is followed
	// on (X1-L4R).
	maxQUICPaths = 4
)

type udpFlow struct {
	client, server netip.AddrPort
	kind           byte // 'q' QUIC, 'd' DTLS
	keyDCID        []byte
	// odcid is the Destination Connection ID of the client's first Initial
	// packet, from which a Retry's integrity tag derives; retried and
	// serverSeen record a Retry acted on and the server's Initial read: a
	// client acts on one Retry at most, and on none after that (X1-L4R).
	odcid      []byte
	retried    bool
	serverSeen bool
	// serverCIDLength is the length of the connection ID the server chose,
	// which a 1-RTT packet's short header does not state (X1-L4R).
	serverCIDLength int
	clientCrypto    cryptoStream
	serverCrypto    cryptoStream
	clientDTLS      dtlsStream
	serverDTLS      dtlsStream
	datagrams       int
	finished        bool
	last            time.Time
	// learned are connection IDs read from this flow's packets and not yet
	// indexed; cids are those the assembler follows it by, and paths the
	// address pairs it is known on, the first its own (X1-L4R).
	learned [][]byte
	cids    []string
	paths   []flowKey
}

// Datagram feeds one decoded datagram. A flow starts with a datagram to a
// watched port; its handshake is read from the datagrams both ways.
func (a *Assembler) Datagram(d Datagram, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.Datagrams++
	if now.Sub(a.swept) > a.idle/2 {
		a.sweep(now)
	}
	key := keyOf(d.Src, d.Dst)
	f := a.udp[key]
	if f == nil {
		f = a.followQUIC(d, key)
	}
	if f == nil {
		if !a.ports[d.Dst.Port()] {
			return
		}
		if a.activeFlows() >= a.maxFlows {
			a.stats.TableFull++
			return
		}
		f = &udpFlow{client: d.Src, server: d.Dst, paths: []flowKey{key}}
		a.udp[key] = f
		a.stats.Connections++
	}
	f.last = now
	if f.kind == 'q' && d.Dst == f.server && len(f.cids) < maxQUICConnectionIDs && f.serverCIDLength > 0 &&
		len(d.Payload) > f.serverCIDLength && d.Payload[0]&0x80 == 0 {
		// A 1-RTT packet names the connection ID the client sends to now,
		// one the server issued in encrypted frames: followed too, so that a
		// NAT that moves the client between two of its packets is seen
		// (X1-L4R).
		f.learn(d.Payload[1 : 1+f.serverCIDLength])
		a.indexQUIC(f)
	}
	if f.finished || len(d.Payload) == 0 {
		return
	}
	// The server keeps its address; a client's can change (X1-L4R).
	obs, ok, done := f.read(d.Payload, d.Dst == f.server)
	a.indexQUIC(f)
	if done {
		a.completeUDP(f, obs, ok, now)
	}
}

// activeFlows is how many TCP and UDP connections are followed; a QUIC
// connection on several address pairs is one.
func (a *Assembler) activeFlows() int {
	return len(a.flows) + len(a.udp) - a.udpPaths
}

// followQUIC finds, by its Destination Connection ID, the QUIC connection a
// datagram on an address pair not seen before belongs to (X1-L4R): a NAT
// that gives the client a new port, or a client that moves, keeps the
// connection IDs. A long header names its connection ID's length; a short
// one is matched against the lengths of the connection IDs followed. The
// pair joins that connection's paths, at most maxQUICPaths, when the
// datagram is to or from its server; the connection is returned, or nil.
func (a *Assembler) followQUIC(d Datagram, key flowKey) *udpFlow {
	if len(a.cids) == 0 || len(d.Payload) < 2 {
		return nil
	}
	var f *udpFlow
	if d.Payload[0]&0x80 != 0 {
		if h, err := quicinitial.ParseHeader(d.Payload); err == nil && len(h.DCID) > 0 {
			f = a.cids[string(h.DCID)]
		}
	} else {
		// A short header, whose fixed bit a peer may grease (RFC 9287).
		for n := 1; n <= 20 && n < len(d.Payload) && f == nil; n++ {
			if a.cidLengths&(1<<n) != 0 {
				f = a.cids[string(d.Payload[1:1+n])]
			}
		}
	}
	if f == nil || len(f.paths) >= maxQUICPaths || (d.Src != f.server && d.Dst != f.server) {
		return nil
	}
	a.udp[key] = f
	f.paths = append(f.paths, key)
	a.udpPaths++
	a.stats.PathsFollowed++
	return f
}

// indexQUIC follows a QUIC flow by the connection IDs its packets named
// (X1-L4R), at most maxQUICConnectionIDs; one another flow is followed by
// stays that flow's.
func (a *Assembler) indexQUIC(f *udpFlow) {
	for _, cid := range f.learned {
		if len(f.cids) == maxQUICConnectionIDs {
			break
		}
		if _, taken := a.cids[string(cid)]; taken {
			continue
		}
		a.cids[string(cid)] = f
		f.cids = append(f.cids, string(cid))
		a.cidLengths |= 1 << len(cid)
	}
	f.learned = f.learned[:0]
}

// learn records a connection ID a flow's packet named, for indexQUIC.
func (f *udpFlow) learn(cid []byte) {
	if len(cid) == 0 || len(cid) > 20 {
		return
	}
	for _, have := range f.cids {
		if have == string(cid) {
			return
		}
	}
	f.learned = append(f.learned, bytes.Clone(cid))
}

func (a *Assembler) completeUDP(f *udpFlow, obs Observation, ok bool, now time.Time) {
	f.finished = true
	f.keyDCID = nil
	f.clientCrypto, f.serverCrypto = cryptoStream{}, cryptoStream{}
	f.clientDTLS, f.serverDTLS = dtlsStream{}, dtlsStream{}
	if !ok {
		a.stats.Unrecognized++
		return
	}
	a.stats.Observations++
	a.emit(Event{Server: f.server, Client: f.client.Addr(), At: now, Obs: obs})
}

func (a *Assembler) finishUDP(key flowKey, f *udpFlow, now time.Time) {
	if !f.finished {
		a.completeUDP(f, Observation{}, false, now)
	}
	delete(a.udp, key)
	// Every address pair and connection ID the flow was followed by goes
	// with it (X1-L4R).
	for _, k := range f.paths {
		if k != key {
			if _, ok := a.udp[k]; ok {
				delete(a.udp, k)
				a.udpPaths--
			}
		}
	}
	for _, cid := range f.cids {
		if a.cids[cid] == f {
			delete(a.cids, cid)
		}
	}
	f.paths, f.cids, f.learned = nil, nil, nil
}

func (f *udpFlow) read(payload []byte, fromClient bool) (Observation, bool, bool) {
	f.datagrams++
	if f.kind == 0 {
		switch {
		case !fromClient:
			return Observation{}, false, false
		case len(payload) >= 5 && payload[0]&0xc0 == 0xc0:
			f.kind = 'q'
		case len(payload) >= 13 && payload[0] == 0x16 && payload[1] == 0xfe:
			f.kind = 'd'
		default:
			return Observation{}, false, true
		}
	}
	var obs Observation
	var ok, done bool
	if f.kind == 'q' {
		obs, ok, done = f.readQUIC(payload, fromClient)
	} else {
		obs, ok, done = f.readDTLS(payload, fromClient)
	}
	if !done && f.datagrams >= maxUDPFlowDatagrams {
		return obs, false, true
	}
	return obs, ok, done
}

// ---------------------------------------------------------------- QUIC

func (f *udpFlow) readQUIC(payload []byte, fromClient bool) (Observation, bool, bool) {
	for off := 0; off < len(payload) && payload[off]&0x80 != 0; {
		packet := payload[off:]
		h, err := quicinitial.ParseHeader(packet)
		if err != nil {
			break
		}
		if h.Retry {
			// The client's next Initial packets use the connection ID the
			// server chose, and their keys derive from it. As the client
			// does (RFC 9000 section 17.2.5.2, RFC 9001 section 5.8), the
			// observer acts on one Retry at most, none after the server's
			// Initial, and only one whose integrity tag is right for the
			// client's first Destination Connection ID (X1-L4R).
			if !fromClient && !f.retried && !f.serverSeen && quicinitial.RetryValid(packet, f.odcid) {
				f.retried = true
				f.keyDCID = nil
				f.clientCrypto, f.serverCrypto = cryptoStream{}, cryptoStream{}
				f.learn(h.SCID)
			}
			break
		}
		if h.Initial {
			if fromClient {
				if f.odcid == nil {
					f.odcid = bytes.Clone(h.DCID)
					f.learn(h.DCID)
				}
				if f.keyDCID == nil {
					f.keyDCID = bytes.Clone(h.DCID)
				}
				f.learn(h.SCID)
			}
			if f.keyDCID != nil {
				if _, frames, err := quicinitial.Open(packet, f.keyDCID, !fromClient); err == nil {
					stream := &f.serverCrypto
					if fromClient {
						stream = &f.clientCrypto
					} else {
						f.serverSeen = true
						f.serverCIDLength = len(h.SCID)
						f.learn(h.SCID)
					}
					readQUICFrames(frames, stream)
				}
			}
		}
		off += h.Length
	}
	obs := Observation{Protocol: "quic"}
	var hello bool
	for _, m := range splitHandshake(f.clientCrypto.contiguous()) {
		if m.kind == 1 {
			obs = Observation{Protocol: "quic"}
			parseClientHello(m.body, &obs)
			hello = true
		}
	}
	if !hello {
		return obs, false, false
	}
	for _, m := range splitHandshake(f.serverCrypto.contiguous()) {
		if m.kind == 2 && !parseServerHello(m.body, &obs) {
			obs.CertificateHidden = true
			return obs, true, true
		}
	}
	return obs, false, false
}

// readQUICFrames reads the frames an Initial packet may carry, keeping the
// CRYPTO data; it stops at a frame it does not know.
func readQUICFrames(frames []byte, stream *cryptoStream) {
	r := quicReader{b: frames}
	for r.ok() && len(r.b) > 0 {
		switch typ := r.b[0]; typ {
		case 0x00, 0x01: // PADDING, PING
			r.b = r.b[1:]
		case 0x02, 0x03: // ACK
			r.b = r.b[1:]
			r.varint() // largest acknowledged
			r.varint() // delay
			ranges := r.varint()
			r.varint() // first range
			for i := uint64(0); i < ranges && r.ok(); i++ {
				r.varint()
				r.varint()
			}
			if typ == 0x03 {
				r.varint()
				r.varint()
				r.varint()
			}
		case 0x06: // CRYPTO
			r.b = r.b[1:]
			offset, length := r.varint(), r.varint()
			if !r.ok() || length > uint64(len(r.b)) {
				return
			}
			stream.write(offset, r.b[:length])
			r.b = r.b[length:]
		default: // CONNECTION_CLOSE or anything an Initial packet should not hold
			return
		}
	}
}

type quicReader struct {
	b   []byte
	bad bool
}

func (r *quicReader) ok() bool { return !r.bad }

func (r *quicReader) varint() uint64 {
	if r.bad || len(r.b) == 0 {
		r.bad = true
		return 0
	}
	n := 1 << (r.b[0] >> 6)
	if len(r.b) < n {
		r.bad = true
		return 0
	}
	v := uint64(r.b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(r.b[i])
	}
	r.b = r.b[n:]
	return v
}

// cryptoStream reassembles one direction's CRYPTO data by offset, within the
// first MaxDirectionBytes.
type cryptoStream struct {
	data   []byte
	filled []bool
}

func (c *cryptoStream) write(offset uint64, b []byte) {
	if offset >= MaxDirectionBytes {
		return
	}
	if room := MaxDirectionBytes - int(offset); len(b) > room {
		b = b[:room]
	}
	if end := int(offset) + len(b); end > len(c.data) {
		c.data = append(c.data, make([]byte, end-len(c.data))...)
		c.filled = append(c.filled, make([]bool, end-len(c.filled))...)
	}
	copy(c.data[offset:], b)
	for i := range b {
		c.filled[int(offset)+i] = true
	}
}

// contiguous is the reassembled data up to the first gap.
func (c *cryptoStream) contiguous() []byte {
	n := 0
	for n < len(c.filled) && c.filled[n] {
		n++
	}
	return c.data[:n]
}

// splitHandshake splits a byte stream into complete handshake messages.
func splitHandshake(stream []byte) []handshakeMessage {
	var msgs []handshakeMessage
	for len(stream) >= 4 {
		length := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
		if len(stream) < 4+length {
			break
		}
		msgs = append(msgs, handshakeMessage{kind: stream[0], body: stream[4 : 4+length]})
		stream = stream[4+length:]
	}
	return msgs
}

// ---------------------------------------------------------------- DTLS

// maxDTLSMessages bounds the handshake messages one direction reassembles.
const maxDTLSMessages = 16

type dtlsMessage struct {
	kind   byte
	seq    uint16
	data   []byte
	filled []bool
}

func (m *dtlsMessage) complete() bool {
	for _, f := range m.filled {
		if !f {
			return false
		}
	}
	return true
}

// dtlsStream reassembles one direction's plaintext handshake messages by
// message sequence and fragment offset.
type dtlsStream struct {
	msgs  []*dtlsMessage
	bytes int
	ended bool
}

func (s *dtlsStream) add(datagram []byte) {
	for len(datagram) >= 13 {
		kind, epoch, length := datagram[0], binary.BigEndian.Uint16(datagram[3:5]), int(binary.BigEndian.Uint16(datagram[11:13]))
		if len(datagram) < 13+length {
			return
		}
		body := datagram[13 : 13+length]
		datagram = datagram[13+length:]
		switch {
		case kind == 0x16 && epoch == 0:
			s.fragments(body)
		case kind == 0x14: // ChangeCipherSpec: what follows is encrypted
			s.ended = true
		case kind != 0x16:
			s.ended = true
		}
	}
}

func (s *dtlsStream) fragments(body []byte) {
	for len(body) >= 12 {
		kind := body[0]
		length := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		seq := binary.BigEndian.Uint16(body[4:6])
		offset := int(body[6])<<16 | int(body[7])<<8 | int(body[8])
		fragment := int(body[9])<<16 | int(body[10])<<8 | int(body[11])
		if len(body) < 12+fragment || offset+fragment > length || length > MaxDirectionBytes {
			return
		}
		data := body[12 : 12+fragment]
		body = body[12+fragment:]
		var m *dtlsMessage
		for _, existing := range s.msgs {
			if existing.seq == seq && existing.kind == kind && len(existing.data) == length {
				m = existing
			}
		}
		if m == nil {
			if len(s.msgs) >= maxDTLSMessages || s.bytes+length > MaxDirectionBytes {
				return
			}
			m = &dtlsMessage{kind: kind, seq: seq, data: make([]byte, length), filled: make([]bool, length)}
			s.msgs = append(s.msgs, m)
			s.bytes += length
		}
		copy(m.data[offset:], data)
		for i := offset; i < offset+fragment; i++ {
			m.filled[i] = true
		}
	}
}

// completeMessages lists the complete messages in message-sequence order.
func (s *dtlsStream) completeMessages() []*dtlsMessage {
	var out []*dtlsMessage
	for _, m := range s.msgs {
		if m.complete() {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

func (f *udpFlow) readDTLS(payload []byte, fromClient bool) (Observation, bool, bool) {
	if fromClient {
		f.clientDTLS.add(payload)
	} else {
		f.serverDTLS.add(payload)
	}
	obs := Observation{Protocol: "dtls"}
	var hello bool
	for _, m := range f.clientDTLS.completeMessages() {
		if m.kind == 1 {
			// A ClientHello sent again after a cookie exchange replaces the first.
			obs = Observation{Protocol: "dtls"}
			parseClientHello(dtlsClientHelloAsTLS(m.data), &obs)
			hello = true
		}
	}
	if !hello {
		return obs, false, false
	}
	var serverHello bool
	for _, m := range f.serverDTLS.completeMessages() {
		switch m.kind {
		case 2: // ServerHello or a DTLS 1.3 HelloRetryRequest
			serverHello = !parseServerHello(m.data, &obs)
			if serverHello && obs.TLSVersion == "DTLSv1.3" {
				obs.CertificateHidden = true
				return obs, true, true
			}
		case 11: // Certificate, in the clear before DTLS 1.3
			obs.CertificateDER = firstCertificate(m.data)
		case 12: // ServerKeyExchange: an ECDHE named curve
			if len(m.data) >= 3 && m.data[0] == 0x03 {
				obs.Group = groupName(binary.BigEndian.Uint16(m.data[1:3]))
			}
		case 14: // ServerHelloDone ends the server's flight
			return obs, serverHello, true
		}
	}
	return obs, false, f.serverDTLS.ended
}

// dtlsClientHelloAsTLS drops the cookie a DTLS ClientHello carries after its
// session ID, giving the TLS shape parseClientHello reads.
func dtlsClientHelloAsTLS(body []byte) []byte {
	if len(body) < 35 {
		return nil
	}
	session := 35 + int(body[34])
	if len(body) < session+1 {
		return nil
	}
	cookie := session + 1 + int(body[session])
	if len(body) < cookie {
		return nil
	}
	out := make([]byte, 0, len(body))
	out = append(out, body[:session]...)
	return append(out, body[cookie:]...)
}
