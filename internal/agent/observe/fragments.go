// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
	"time"
)

// The IP layer under the TCP and UDP readers (X1-L2R). decodePacket walks up
// to maxVLANTags in-band VLAN tags and up to maxIPv6ExtensionHeaders IPv6
// extension headers before the transport header, and names an IPv4 or IPv6
// fragment; reassembler rebuilds a fragmented datagram inside fixed bounds.
// A datagram whose fragments overlap is dropped whole (RFC 5722 for IPv6, the
// same rule for IPv4), and every drop is counted.

const (
	// maxVLANTags bounds the in-band 802.1Q / 802.1ad tags read before the
	// EtherType.
	maxVLANTags = 4
	// maxIPv6ExtensionHeaders bounds the IPv6 extension headers walked
	// before the transport header.
	maxIPv6ExtensionHeaders = 8
	// maxReassemblies bounds the datagrams held in pieces at once.
	maxReassemblies = 64
	// maxReassembledBytes is the largest datagram payload rebuilt (the IPv4
	// total length field's range).
	maxReassembledBytes = 65535
	// reassemblyTimeout forgets a datagram whose pieces stop arriving.
	reassemblyTimeout = 30 * time.Second
)

// ipPacket is one IP packet's transport bytes, or one fragment of them.
type ipPacket struct {
	src, dst netip.Addr
	proto    byte
	payload  []byte
	frag     *ipFragment
}

// ipFragment places one fragment in its datagram.
type ipFragment struct {
	v6     bool
	id     uint32
	offset int
	more   bool
}

// isIPv6ExtensionHeader reports the next-header values walked before the
// transport header: hop-by-hop options, routing, fragment, authentication,
// destination options and mobility.
func isIPv6ExtensionHeader(next byte) bool {
	switch next {
	case 0, 43, 44, 51, 60, 135:
		return true
	}
	return false
}

// decodePacket reads an Ethernet frame carrying IPv4 or IPv6.
func decodePacket(frame []byte) (ipPacket, bool) {
	if len(frame) < 14 {
		return ipPacket{}, false
	}
	etherType, rest := binary.BigEndian.Uint16(frame[12:14]), frame[14:]
	for i := 0; i < maxVLANTags && (etherType == tpid8021Q || etherType == tpid8021AD); i++ {
		if len(rest) < 4 {
			return ipPacket{}, false
		}
		etherType, rest = binary.BigEndian.Uint16(rest[2:4]), rest[4:]
	}
	switch etherType {
	case 0x0800:
		return decodeIPv4(rest)
	case 0x86dd:
		return decodeIPv6(rest)
	}
	return ipPacket{}, false
}

func decodeIPv4(b []byte) (ipPacket, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return ipPacket{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total < ihl || total > len(b) {
		return ipPacket{}, false
	}
	pkt := ipPacket{
		src: netip.AddrFrom4([4]byte(b[12:16])), dst: netip.AddrFrom4([4]byte(b[16:20])),
		proto: b[9], payload: b[ihl:total],
	}
	if field := binary.BigEndian.Uint16(b[6:8]); field&0x3fff != 0 {
		pkt.frag = &ipFragment{id: uint32(binary.BigEndian.Uint16(b[4:6])), offset: int(field&0x1fff) * 8, more: field&0x2000 != 0}
	}
	return pkt, true
}

func decodeIPv6(b []byte) (ipPacket, bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return ipPacket{}, false
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if 40+length > len(b) {
		return ipPacket{}, false
	}
	pkt := ipPacket{src: netip.AddrFrom16([16]byte(b[8:24])), dst: netip.AddrFrom16([16]byte(b[24:40]))}
	next, rest := b[6], b[40:40+length]
	for i := 0; isIPv6ExtensionHeader(next); i++ {
		if i == maxIPv6ExtensionHeaders || len(rest) < 8 {
			return ipPacket{}, false
		}
		var size int
		switch next {
		case 44: // fragment: next header, reserved, offset and M, identification
			field := binary.BigEndian.Uint16(rest[2:4])
			frag := &ipFragment{v6: true, id: binary.BigEndian.Uint32(rest[4:8]), offset: int(field>>3) * 8, more: field&1 != 0}
			if frag.offset != 0 || frag.more {
				pkt.frag = frag
			}
			size = 8
		case 51: // authentication header: length in 4-octet units, minus 2
			size = (int(rest[1]) + 2) * 4
		default: // options and routing headers: length in 8-octet units, minus 1
			size = (int(rest[1]) + 1) * 8
		}
		if size > len(rest) {
			return ipPacket{}, false
		}
		next, rest = rest[0], rest[size:]
	}
	pkt.proto, pkt.payload = next, rest
	return pkt, true
}

// segmentOf reads a whole TCP segment from a packet.
func segmentOf(pkt ipPacket) (Segment, bool) {
	tcp := pkt.payload
	if pkt.frag != nil || pkt.proto != 6 || len(tcp) < 20 {
		return Segment{}, false
	}
	offset := int(tcp[12]>>4) * 4
	if offset < 20 || offset > len(tcp) {
		return Segment{}, false
	}
	flags := tcp[13]
	return Segment{
		Src:     netip.AddrPortFrom(pkt.src, binary.BigEndian.Uint16(tcp[0:2])),
		Dst:     netip.AddrPortFrom(pkt.dst, binary.BigEndian.Uint16(tcp[2:4])),
		Seq:     binary.BigEndian.Uint32(tcp[4:8]),
		Ack:     binary.BigEndian.Uint32(tcp[8:12]),
		FIN:     flags&0x01 != 0,
		SYN:     flags&0x02 != 0,
		RST:     flags&0x04 != 0,
		ACK:     flags&0x10 != 0,
		Payload: tcp[offset:],
	}, true
}

// datagramOf reads a whole UDP datagram from a packet.
func datagramOf(pkt ipPacket) (Datagram, bool) {
	l4 := pkt.payload
	if pkt.frag != nil || pkt.proto != 17 || len(l4) < 8 {
		return Datagram{}, false
	}
	length := int(binary.BigEndian.Uint16(l4[4:6]))
	if length < 8 || length > len(l4) {
		return Datagram{}, false
	}
	return Datagram{
		Src:     netip.AddrPortFrom(pkt.src, binary.BigEndian.Uint16(l4[0:2])),
		Dst:     netip.AddrPortFrom(pkt.dst, binary.BigEndian.Uint16(l4[2:4])),
		Payload: l4[8:length],
	}, true
}

type fragmentKey struct {
	src, dst netip.Addr
	proto    byte
	v6       bool
	id       uint32
}

type fragmentRange struct{ start, end int }

// fragmentBuffer is one datagram held in pieces.
type fragmentBuffer struct {
	data   []byte
	ranges []fragmentRange
	// total is the datagram's length once its last fragment arrived, else -1.
	total int
	first time.Time
}

// reassembler holds fragments until their datagram is whole. It is bounded
// by maxReassemblies datagrams of at most maxReassembledBytes each, and
// forgets a datagram after reassemblyTimeout.
type reassembler struct {
	pending map[fragmentKey]*fragmentBuffer
}

func newReassembler() *reassembler {
	return &reassembler{pending: map[fragmentKey]*fragmentBuffer{}}
}

// add takes one fragment and returns its datagram once every piece has
// arrived. Overlapping fragments, a datagram over maxReassembledBytes, a full
// table and a timeout each drop the datagram, counted in st.
func (r *reassembler) add(pkt ipPacket, now time.Time, st *Stats) (ipPacket, bool) {
	st.Fragments++
	r.expire(now, st)
	f := pkt.frag
	key := fragmentKey{src: pkt.src, dst: pkt.dst, proto: pkt.proto, v6: f.v6, id: f.id}
	end := f.offset + len(pkt.payload)
	if len(pkt.payload) == 0 || (f.more && len(pkt.payload)%8 != 0) || end > maxReassembledBytes {
		r.drop(key, st)
		return ipPacket{}, false
	}
	buf := r.pending[key]
	if buf == nil {
		if len(r.pending) >= maxReassemblies {
			st.FragmentsDropped++
			return ipPacket{}, false
		}
		buf = &fragmentBuffer{total: -1, first: now}
		r.pending[key] = buf
	}
	for _, have := range buf.ranges {
		if f.offset < have.end && have.start < end {
			r.drop(key, st)
			return ipPacket{}, false
		}
	}
	if !f.more {
		if buf.total != -1 || end < maxEnd(buf.ranges) {
			r.drop(key, st)
			return ipPacket{}, false
		}
		buf.total = end
	} else if buf.total != -1 && end > buf.total {
		r.drop(key, st)
		return ipPacket{}, false
	}
	if len(buf.data) < end {
		buf.data = append(buf.data, make([]byte, end-len(buf.data))...)
	}
	copy(buf.data[f.offset:end], pkt.payload)
	buf.ranges = append(buf.ranges, fragmentRange{f.offset, end})
	if buf.total == -1 || covered(buf.ranges) != buf.total {
		return ipPacket{}, false
	}
	delete(r.pending, key)
	st.Reassembled++
	return ipPacket{src: pkt.src, dst: pkt.dst, proto: pkt.proto, payload: buf.data[:buf.total]}, true
}

func (r *reassembler) drop(key fragmentKey, st *Stats) {
	delete(r.pending, key)
	st.FragmentsDropped++
}

// expire forgets datagrams whose pieces stopped arriving.
func (r *reassembler) expire(now time.Time, st *Stats) {
	for key, buf := range r.pending {
		if now.Sub(buf.first) > reassemblyTimeout {
			delete(r.pending, key)
			st.FragmentsDropped++
		}
	}
}

func maxEnd(ranges []fragmentRange) int {
	end := 0
	for _, r := range ranges {
		end = max(end, r.end)
	}
	return end
}

// covered is how many bytes from offset 0 the ranges cover without a gap.
// Ranges never overlap (add refuses an overlap). Sort once so an empty or
// out-of-order range cannot make the scan revisit the same offset forever.
func covered(ranges []fragmentRange) int {
	slices.SortFunc(ranges, func(a, b fragmentRange) int { return cmp.Compare(a.start, b.start) })
	n := 0
	for _, r := range ranges {
		if r.start > n {
			break
		}
		if r.end > n {
			n = r.end
		}
	}
	return n
}
