// SPDX-License-Identifier: BUSL-1.1

package observe

import (
	"encoding/binary"
	"sort"
)

// Resynchronization (X1-L3R). A gap in one direction of a connection that
// will never fill, because the capture missed a segment the endpoint
// received, is skipped: the bytes before it are cut back to the end of the
// last whole TLS record that finishes a handshake message, and reading
// resumes at the first TLS record header in the held bytes after it, so the
// records past the gap (a TLS 1.2 server's key exchange and the end of its
// flight) are still read. A gap is known to be permanent when the other side
// acknowledges bytes past it (the receiver had them, so nothing will send them
// again), when the direction's hold is full, or when the connection ends.
// Only a direction that is TLS records from its first byte resynchronizes;
// any other, or a gap with no record header after it, is read as before.
// Each resynchronization is counted in Stats.Resynced.

// maxTLSRecord is the longest record a header may state: 2^14 bytes plus
// the 2048 a TLS 1.2 record may add in protection.
const maxTLSRecord = 1<<14 + 2048

// acknowledged takes the other side's cumulative acknowledgment of d's
// bytes. One past the gap d is waiting on means the receiver had bytes the
// capture never carried, so the gap will never fill. It reports whether d
// resynchronized.
func (a *Assembler) acknowledged(d *direction, ack uint32) bool {
	if !d.set || len(d.ahead) == 0 || int32(ack-d.next) <= 0 { // #nosec G115 -- RFC 1982 serial arithmetic on wrapping sequence numbers (CWE-190)
		return false
	}
	return a.resync(d)
}

// resync skips d's gap to the first TLS record header after it and reports
// whether it did; when it did not, nothing changed. A try that found nothing
// to resume at is not repeated until d has read or holds other bytes.
func (a *Assembler) resync(d *direction) bool {
	held := heldBytes(d.ahead)
	if held == 0 || (len(d.buf) == d.triedRead && held == d.triedHeld) {
		return false
	}
	cut, ok := tlsResumeCut(d.buf)
	at := -1
	var run []byte
	var start uint32
	if ok {
		run, start = heldRun(d.ahead, d.next)
		at = nextTLSRecord(run)
	}
	if at < 0 {
		d.triedRead, d.triedHeld = len(d.buf), held
		return false
	}
	d.buf = d.buf[:cut]
	d.next = start + uint32(at) // #nosec G115 -- at is under MaxDirectionBytes, and sequence numbers wrap by design (CWE-190)
	kept := d.ahead[:0]
	for _, h := range d.ahead {
		if int32(h.seq+uint32(len(h.payload))-d.next) > 0 { // #nosec G115 -- a held payload is under MaxDirectionBytes; RFC 1982 serial arithmetic (CWE-190)
			kept = append(kept, h)
		}
	}
	d.ahead = kept
	d.triedRead, d.triedHeld = 0, 0
	a.stats.Resynced++
	a.release(d)
	return true
}

// tlsResumeCut is where a direction's bytes are cut before a gap: the end of
// the last whole TLS record after which no handshake message is left
// unfinished. ok is false unless the bytes are TLS records from the first,
// at least one of them whole.
func tlsResumeCut(b []byte) (cut int, ok bool) {
	need, got := 0, 0 // bytes owed to the current handshake message; header bytes read
	var header [4]byte
	for pos := 0; pos+5 <= len(b) && plausibleRecord(b[pos:]); {
		end := pos + 5 + int(binary.BigEndian.Uint16(b[pos+3:pos+5]))
		if end > len(b) {
			break
		}
		if b[pos] == 0x16 {
			for body := b[pos+5 : end]; len(body) > 0; {
				if need > 0 {
					n := min(need, len(body))
					need, body = need-n, body[n:]
					continue
				}
				header[got], got, body = body[0], got+1, body[1:]
				if got == 4 {
					need, got = int(header[1])<<16|int(header[2])<<8|int(header[3]), 0
				}
			}
		}
		pos = end
		if need == 0 && got == 0 {
			cut = pos
		}
	}
	return cut, cut > 0
}

// heldRun returns the held bytes from the earliest held segment up to the
// first gap among them, and the sequence number they start at. Every held
// segment starts past next.
func heldRun(ahead []heldSegment, next uint32) ([]byte, uint32) {
	order := append([]heldSegment(nil), ahead...)
	sort.Slice(order, func(i, j int) bool {
		return int32(order[i].seq-next) < int32(order[j].seq-next) // #nosec G115 -- RFC 1982 serial arithmetic (CWE-190)
	})
	start := order[0].seq
	var run []byte
	for _, h := range order {
		off := int(h.seq - start)
		if off > len(run) {
			break
		}
		if off+len(h.payload) > len(run) {
			run = append(run, h.payload[len(run)-off:]...)
		}
	}
	return run, start
}

// nextTLSRecord is the offset of the first TLS record header in b from which
// plausible records run to the end of b, or -1.
func nextTLSRecord(b []byte) int {
	for at := 0; at+5 <= len(b); at++ {
		if recordsRunToEnd(b[at:]) {
			return at
		}
	}
	return -1
}

// recordsRunToEnd reports whether b starts with a whole TLS record (a
// handshake record opening a handshake message) after which plausible
// records follow one another to the end of b; the last may run past it, or
// only begin.
func recordsRunToEnd(b []byte) bool {
	if !plausibleRecord(b) || (b[0] == 0x16 && !opensHandshakeMessage(b)) {
		return false
	}
	end := 5 + int(binary.BigEndian.Uint16(b[3:5]))
	if end > len(b) {
		return false // nothing after it shows the header is one
	}
	for b = b[end:]; len(b) >= 5; b = b[end:] {
		if !plausibleRecord(b) {
			return false
		}
		end = 5 + int(binary.BigEndian.Uint16(b[3:5]))
		if end >= len(b) {
			return true
		}
	}
	return beginsRecordHeader(b)
}

// beginsRecordHeader reports whether b, shorter than a record header, can be
// the start of one; an empty b can.
func beginsRecordHeader(b []byte) bool {
	switch {
	case len(b) == 0:
		return true
	case b[0] < 0x14 || b[0] > 0x17:
		return false
	case len(b) >= 2 && b[1] != 0x03:
		return false
	case len(b) >= 3 && (b[2] < 0x01 || b[2] > 0x04):
		return false
	}
	return true
}

// plausibleRecord reports whether b starts with a TLS record header: a
// content type, version 3.1 to 3.4, and a length a record can have.
func plausibleRecord(b []byte) bool {
	if len(b) < 5 || b[1] != 0x03 || b[2] < 0x01 || b[2] > 0x04 {
		return false
	}
	length := int(binary.BigEndian.Uint16(b[3:5]))
	switch b[0] {
	case 0x14: // change_cipher_spec: one byte, 1
		return length == 1 && (len(b) < 6 || b[5] == 0x01)
	case 0x15: // alert
		return length >= 2 && length <= maxTLSRecord
	case 0x16, 0x17: // handshake, application data
		return length >= 1 && length <= maxTLSRecord
	}
	return false
}

// opensHandshakeMessage reports whether the handshake record b starts with
// a handshake message's header of a known type.
func opensHandshakeMessage(b []byte) bool {
	if len(b) < 9 {
		return false
	}
	switch b[5] {
	case 0, 1, 2, 4, 8, 11, 12, 13, 14, 15, 16, 20, 22, 24:
		return true
	}
	return false
}
