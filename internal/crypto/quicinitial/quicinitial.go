// SPDX-License-Identifier: BUSL-1.1

// Package quicinitial reads QUIC Initial packets as a passive observer can
// (X1-L4): their protection is not secret. RFC 9001 section 5.2 derives the
// Initial keys from the Destination Connection ID of the client's first
// Initial packet and a salt published for each QUIC version, so anyone who
// sees that packet can remove the header protection and decrypt the packet,
// exactly as the server does, to read the CRYPTO frames that carry the TLS
// ClientHello and ServerHello. Nothing after the Initial packets — the
// Handshake and 1-RTT packets with the certificate and application data — is
// readable this way, and this package does not try.
package quicinitial

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// The QUIC versions whose Initial protection this package removes.
const (
	Version1 uint32 = 0x00000001 // RFC 9000
	Version2 uint32 = 0x6b3343cf // RFC 9369
)

var (
	saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// ErrNotInitial reports a packet that is not a long-header Initial packet of
// a version this package reads.
var ErrNotInitial = errors.New("quicinitial: not an Initial packet of QUIC version 1 or 2")

// Header is a long-header packet's clear fields.
type Header struct {
	Version uint32
	Initial bool
	// Retry marks a Retry packet: it has no length and fills the datagram.
	Retry bool
	DCID  []byte
	SCID  []byte
	// Length is how many bytes of the datagram the packet takes, header
	// included; a datagram can carry several packets back to back.
	Length int
	// pnOffset is where the protected packet number starts.
	pnOffset int
}

// ParseHeader reads the long header at the start of b without removing any
// protection.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return Header{}, ErrNotInitial
	}
	h := Header{Version: binary.BigEndian.Uint32(b[1:5])}
	typ := (b[0] >> 4) & 0x03
	switch h.Version {
	case Version1:
		h.Initial, h.Retry = typ == 0, typ == 3
	case Version2:
		h.Initial, h.Retry = typ == 1, typ == 0
	default:
		return Header{}, ErrNotInitial
	}
	off := 5
	read := func() []byte {
		if off >= len(b) {
			return nil
		}
		n := int(b[off])
		if n > 20 || off+1+n > len(b) {
			return nil
		}
		v := b[off+1 : off+1+n]
		off += 1 + n
		return v
	}
	h.DCID = read()
	h.SCID = read()
	if h.DCID == nil || h.SCID == nil {
		return Header{}, fmt.Errorf("quicinitial: truncated connection IDs")
	}
	if h.Retry {
		h.Length = len(b)
		return h, nil
	}
	if h.Initial {
		tokenLen, n := varint(b[off:])
		if n == 0 || tokenLen > uint64(len(b)) {
			return Header{}, fmt.Errorf("quicinitial: truncated token")
		}
		off += n + int(tokenLen) // #nosec G115 -- the token length was checked against the datagram above (CWE-190)
	}
	if off > len(b) {
		return Header{}, fmt.Errorf("quicinitial: truncated header")
	}
	length, n := varint(b[off:])
	if n == 0 || length > uint64(len(b)) {
		return Header{}, fmt.Errorf("quicinitial: truncated length")
	}
	off += n
	if off+int(length) > len(b) { // #nosec G115 -- the length was checked against the datagram above (CWE-190)
		return Header{}, fmt.Errorf("quicinitial: the packet is longer than the datagram")
	}
	h.pnOffset = off
	h.Length = off + int(length) // #nosec G115 -- the length was checked against the datagram above (CWE-190)
	return h, nil
}

// Open removes the protection of the Initial packet at the start of b, with
// the keys derived from keyDCID — the Destination Connection ID of the
// client's Initial packet — for the client's side (fromServer false) or the
// server's, and returns its frames. b is not changed.
func Open(b []byte, keyDCID []byte, fromServer bool) (Header, []byte, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Header{}, nil, err
	}
	if !h.Initial {
		return h, nil, ErrNotInitial
	}
	key, iv, hp, err := initialKeys(h.Version, keyDCID, fromServer)
	if err != nil {
		return Header{}, nil, err
	}
	packet := append([]byte(nil), b[:h.Length]...)
	if h.pnOffset+4+16 > len(packet) {
		return Header{}, nil, fmt.Errorf("quicinitial: the packet is too short to sample")
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return Header{}, nil, err
	}
	mask := make([]byte, aes.BlockSize)
	hpBlock.Encrypt(mask, packet[h.pnOffset+4:h.pnOffset+4+16])
	packet[0] ^= mask[0] & 0x0f
	pnLen := int(packet[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		packet[h.pnOffset+i] ^= mask[1+i] // #nosec G602 -- i < pnLen <= 4, and the mask is one 16-byte AES block (CWE-129)
		pn = pn<<8 | uint64(packet[h.pnOffset+i])
	}
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return Header{}, nil, err
	}
	aead, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return Header{}, nil, err
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i)) // #nosec G115 -- one byte of the packet number (CWE-190)
	}
	headerEnd := h.pnOffset + pnLen
	frames, err := aead.Open(nil, nonce, packet[headerEnd:], packet[:headerEnd])
	if err != nil {
		return Header{}, nil, fmt.Errorf("quicinitial: the packet does not open with these Initial keys")
	}
	return h, frames, nil
}

// initialKeys derives one side's Initial packet key, IV and header
// protection key (RFC 9001 section 5.2; RFC 9369 section 3.3.1 for v2).
func initialKeys(version uint32, dcid []byte, fromServer bool) (key, iv, hp []byte, err error) {
	salt, prefix := saltV1, "quic "
	if version == Version2 {
		salt, prefix = saltV2, "quicv2 "
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	side := "client in"
	if fromServer {
		side = "server in"
	}
	secret, err := expandLabel(initial, side, sha256.Size)
	if err != nil {
		return nil, nil, nil, err
	}
	if key, err = expandLabel(secret, prefix+"key", 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = expandLabel(secret, prefix+"iv", 12); err != nil {
		return nil, nil, nil, err
	}
	if hp, err = expandLabel(secret, prefix+"hp", 16); err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hp, nil
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length)) // #nosec G115 -- a key length of at most 32 bytes (CWE-190)
	info = append(info, byte(len(full)))                       // #nosec G115 -- a label of under 32 bytes (CWE-190)
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

// varint reads a QUIC variable-length integer; n is 0 when b is too short.
func varint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}
