// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Saved captures (X1-L3). ReplayPcap reads a classic pcap file — what tcpdump
// -w writes — and feeds its frames to an assembler in file order with each
// packet's own time, so a capture taken on a mirror port, or anywhere the
// agent cannot listen, is read like live traffic. pcapng is not read.

const (
	pcapLinkEthernet = 1
	pcapLinkRaw      = 101
	pcapLinkSLL      = 113
	pcapLinkSLL2     = 276
	// maxPcapRecord bounds one packet record; tcpdump's default snap length
	// is 262144.
	maxPcapRecord = 262144
)

// ErrPcapNG is returned for a pcapng file.
var ErrPcapNG = errors.New("observe: the capture is pcapng; save it as pcap (tcpdump -w, or editcap -F pcap)")

// ReplayPcap feeds every TCP segment of a classic pcap capture to a, and
// returns how many packet records it read. Frames that are not TCP over IPv4
// or IPv6 are skipped as they are on an interface.
func ReplayPcap(r io.Reader, a *Assembler) (int, error) {
	br := bufio.NewReader(r)
	var header [24]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		return 0, fmt.Errorf("observe: reading the pcap header: %w", err)
	}
	var order binary.ByteOrder
	nanos := false
	switch magic := binary.LittleEndian.Uint32(header[0:4]); magic {
	case 0xa1b2c3d4:
		order = binary.LittleEndian
	case 0xa1b23c4d:
		order, nanos = binary.LittleEndian, true
	case 0xd4c3b2a1:
		order = binary.BigEndian
	case 0x4d3cb2a1:
		order, nanos = binary.BigEndian, true
	case 0x0a0d0d0a:
		return 0, ErrPcapNG
	default:
		return 0, fmt.Errorf("observe: not a pcap capture (magic %#x)", magic)
	}
	link := order.Uint32(header[20:24]) & 0x0fffffff
	switch link {
	case pcapLinkEthernet, pcapLinkRaw, pcapLinkSLL, pcapLinkSLL2:
	default:
		return 0, fmt.Errorf("observe: the capture's link type %d is not Ethernet, raw IP or Linux cooked", link)
	}
	packets := 0
	var record [16]byte
	for {
		if _, err := io.ReadFull(br, record[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return packets, nil
			}
			return packets, fmt.Errorf("observe: reading packet record %d: %w", packets+1, err)
		}
		sec, frac, length := order.Uint32(record[0:4]), order.Uint32(record[4:8]), order.Uint32(record[8:12])
		if length > maxPcapRecord {
			return packets, fmt.Errorf("observe: packet record %d is %d bytes, more than %d", packets+1, length, maxPcapRecord)
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(br, data); err != nil {
			return packets, fmt.Errorf("observe: reading packet record %d: %w", packets+1, err)
		}
		packets++
		frame := ethernetFrame(link, data)
		if frame == nil {
			continue
		}
		seg, ok := DecodeFrame(frame)
		if !ok {
			continue
		}
		nsec := int64(frac)
		if !nanos {
			nsec *= int64(time.Microsecond)
		}
		a.Segment(seg, time.Unix(int64(sec), nsec).UTC())
	}
}

// ethernetFrame gives the record as an Ethernet frame DecodeFrame reads.
func ethernetFrame(link uint32, data []byte) []byte {
	withType := func(etherType uint16, payload []byte) []byte {
		frame := make([]byte, 14+len(payload))
		binary.BigEndian.PutUint16(frame[12:14], etherType)
		copy(frame[14:], payload)
		return frame
	}
	switch link {
	case pcapLinkEthernet:
		return data
	case pcapLinkSLL:
		if len(data) < 16 {
			return nil
		}
		return withType(binary.BigEndian.Uint16(data[14:16]), data[16:])
	case pcapLinkSLL2:
		if len(data) < 20 {
			return nil
		}
		return withType(binary.BigEndian.Uint16(data[0:2]), data[20:])
	case pcapLinkRaw:
		if len(data) == 0 {
			return nil
		}
		switch data[0] >> 4 {
		case 4:
			return withType(0x0800, data)
		case 6:
			return withType(0x86dd, data)
		}
	}
	return nil
}

// Flush ends every connection still open, reading what each holds, as the
// end of a capture does.
func (a *Assembler) Flush(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, f := range a.flows {
		a.finish(key, f, now)
	}
}
