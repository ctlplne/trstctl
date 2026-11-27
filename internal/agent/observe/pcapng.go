// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"
)

// pcapng (X1-L3R): what Wireshark, dumpcap and editcap write by default.
// replayPcapNG reads its section header blocks (in either byte order),
// interface description blocks (link type and timestamp resolution) and
// enhanced and simple packet blocks, feeding each frame to the assembler with
// its own time like a classic capture; other blocks are skipped. Every block
// is bounded by maxPcapNGBlock and every interface table by
// maxPcapNGInterfaces.

const (
	pcapngSectionHeader   = 0x0a0d0d0a
	pcapngInterface       = 0x00000001
	pcapngSimplePacket    = 0x00000003
	pcapngEnhancedPacket  = 0x00000006
	pcapngByteOrderMagic  = 0x1a2b3c4d
	pcapngOptionEnd       = 0
	pcapngOptionTSResol   = 9
	maxPcapNGBlock        = maxPcapRecord + 64
	maxPcapNGInterfaces   = 64
	pcapngDefaultResolNum = 1_000_000 // microseconds when if_tsresol is absent
)

type pcapngIface struct {
	link uint32
	// perSecond is the timestamp unit as ticks per second.
	perSecond uint64
}

// replayPcapNG reads a pcapng capture whose first four bytes (the section
// header's type) were already read.
func replayPcapNG(br *bufio.Reader, a *Assembler) (int, error) {
	order := binary.ByteOrder(binary.LittleEndian)
	var ifaces []pcapngIface
	packets := 0
	blockType := uint32(pcapngSectionHeader)
	for first := true; ; first = false {
		if !first {
			var head [4]byte
			if _, err := io.ReadFull(br, head[:]); err != nil {
				if errors.Is(err, io.EOF) {
					return packets, nil
				}
				return packets, fmt.Errorf("observe: reading a pcapng block: %w", err)
			}
			blockType = order.Uint32(head[:])
		}
		var lenBytes [4]byte
		if _, err := io.ReadFull(br, lenBytes[:]); err != nil {
			return packets, fmt.Errorf("observe: reading a pcapng block length: %w", err)
		}
		if blockType == pcapngSectionHeader {
			// A section header fixes the byte order of everything after it.
			var magic [4]byte
			if _, err := io.ReadFull(br, magic[:]); err != nil {
				return packets, fmt.Errorf("observe: reading a pcapng section header: %w", err)
			}
			switch {
			case binary.LittleEndian.Uint32(magic[:]) == pcapngByteOrderMagic:
				order = binary.LittleEndian
			case binary.BigEndian.Uint32(magic[:]) == pcapngByteOrderMagic:
				order = binary.BigEndian
			default:
				return packets, errors.New("observe: a pcapng section header has no byte-order magic")
			}
			length := order.Uint32(lenBytes[:])
			if length < 28 || length%4 != 0 || length > maxPcapNGBlock {
				return packets, fmt.Errorf("observe: a pcapng section header is %d bytes", length)
			}
			rest := make([]byte, length-12)
			if _, err := io.ReadFull(br, rest); err != nil {
				return packets, fmt.Errorf("observe: reading a pcapng section header: %w", err)
			}
			if order.Uint32(rest[len(rest)-4:]) != length {
				return packets, errors.New("observe: a pcapng section header's trailing length does not match")
			}
			ifaces = ifaces[:0] // interface ids restart in each section
			continue
		}
		length := order.Uint32(lenBytes[:])
		if length < 12 || length%4 != 0 || length > maxPcapNGBlock {
			return packets, fmt.Errorf("observe: a pcapng block (type %#x) is %d bytes", blockType, length)
		}
		body := make([]byte, length-12)
		if _, err := io.ReadFull(br, body); err != nil {
			return packets, fmt.Errorf("observe: reading a pcapng block: %w", err)
		}
		var trailer [4]byte
		if _, err := io.ReadFull(br, trailer[:]); err != nil || order.Uint32(trailer[:]) != length {
			return packets, errors.New("observe: a pcapng block's trailing length does not match")
		}
		switch blockType {
		case pcapngInterface:
			if len(body) < 8 {
				return packets, errors.New("observe: a pcapng interface block is short")
			}
			if len(ifaces) == maxPcapNGInterfaces {
				return packets, fmt.Errorf("observe: a pcapng section names more than %d interfaces", maxPcapNGInterfaces)
			}
			iface := pcapngIface{link: uint32(order.Uint16(body[0:2])), perSecond: pcapngDefaultResolNum}
			resol, ok, err := pcapngTSResol(order, body[8:])
			if err != nil {
				return packets, err
			}
			if ok {
				iface.perSecond = resol
			}
			ifaces = append(ifaces, iface)
		case pcapngEnhancedPacket:
			if len(body) < 20 {
				return packets, errors.New("observe: a pcapng packet block is short")
			}
			id, captured := order.Uint32(body[0:4]), order.Uint32(body[12:16])
			if int(id) >= len(ifaces) {
				return packets, fmt.Errorf("observe: a pcapng packet names interface %d of %d", id, len(ifaces))
			}
			if captured > maxPcapRecord || int(captured) > len(body)-20 {
				return packets, fmt.Errorf("observe: a pcapng packet is %d bytes", captured)
			}
			packets++
			iface := ifaces[id]
			ticks := uint64(order.Uint32(body[4:8]))<<32 | uint64(order.Uint32(body[8:12]))
			at := pcapngTime(ticks, iface.perSecond)
			if frame := ethernetFrame(iface.link, body[20:20+captured]); frame != nil {
				if err := feedCapturedFrame(a, frame, at); err != nil {
					return packets, err
				}
			}
		case pcapngSimplePacket:
			// No timestamp and the first interface; the original length
			// precedes the data, which the block's own length bounds.
			if len(body) < 4 || len(ifaces) == 0 {
				return packets, errors.New("observe: a pcapng simple packet block has no interface")
			}
			packets++
			original := order.Uint32(body[0:4])
			data := body[4:]
			if int(original) < len(data) {
				data = data[:original]
			}
			if frame := ethernetFrame(ifaces[0].link, data); frame != nil {
				if err := feedCapturedFrame(a, frame, time.Time{}); err != nil {
					return packets, err
				}
			}
		}
	}
}

// pcapngTSResol reads an interface's if_tsresol option: a power of ten, or of
// two when the top bit is set, as ticks per second. ok is false when the
// option is absent (microseconds); a unit finer than a uint64 count of ticks
// per second can state is refused.
func pcapngTSResol(order binary.ByteOrder, options []byte) (perSecond uint64, ok bool, err error) {
	for len(options) >= 4 {
		code, size := order.Uint16(options[0:2]), int(order.Uint16(options[2:4]))
		if code == pcapngOptionEnd {
			return 0, false, nil
		}
		padded := (size + 3) &^ 3
		if 4+padded > len(options) {
			return 0, false, nil
		}
		if code == pcapngOptionTSResol && size >= 1 {
			v := options[4]
			exp := uint64(v & 0x7f)
			if v&0x80 != 0 {
				if exp > 63 {
					return 0, false, fmt.Errorf("observe: a pcapng interface states a timestamp resolution of 2^-%d seconds", exp)
				}
				return 1 << exp, true, nil
			}
			if exp > 18 {
				return 0, false, fmt.Errorf("observe: a pcapng interface states a timestamp resolution of 10^-%d seconds", exp)
			}
			perSecond = 1
			for range exp {
				perSecond *= 10
			}
			return perSecond, true, nil
		}
		options = options[4+padded:]
	}
	return 0, false, nil
}

// pcapngTime converts a timestamp in ticks of 1/perSecond seconds.
func pcapngTime(ticks, perSecond uint64) time.Time {
	if perSecond == 0 {
		return time.Time{}
	}
	sec := ticks / perSecond
	if sec > math.MaxInt64/2 {
		return time.Time{}
	}
	// frac/perSecond of a second in nanoseconds, without overflow: the
	// 128-bit product divided by perSecond is under one second.
	hi, lo := bits.Mul64(ticks%perSecond, uint64(time.Second))
	nsec, _ := bits.Div64(hi, lo, perSecond)
	return time.Unix(int64(sec), int64(nsec)).UTC() // #nosec G115 -- sec is bounded above and nsec is under 1e9 (CWE-190)
}
