// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"errors"
	"fmt"
	"io"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const maxAuthenticationReply = 64 << 10
const MaxDirectoryFrameBytes = 2 << 20
const maxDirectoryReadBytes = 16 << 20

func lengthBytes(size int) []byte {
	if size < 0 || size > maxDirectoryReadBytes {
		panic("LDAP encoder length exceeds its internal bound")
	}
	if size < 128 {
		return []byte{byte(size)}
	}
	var encoded [4]byte
	index := len(encoded)
	for size > 0 {
		index--
		encoded[index] = byte(size & 0xff)
		size >>= 8
	}
	return append([]byte{0x80 | byte(len(encoded)-index)}, encoded[index:]...)
}

// tlv is used only for public routing/response fixtures, never a password.
func tlv(tag byte, public []byte) []byte {
	out := append([]byte{tag}, lengthBytes(len(public))...)
	return append(out, public...)
}
func newBindPacket(messageID byte, dn string, password []byte) (*secret.Buffer, error) {
	if messageID == 0 || messageID > 127 || len(dn) == 0 || len(dn) > 4096 || len(password) == 0 || len(password) > 64<<10 {
		return nil, errors.New("LDAP bind identity or credential exceeds its bound")
	}
	name := tlv(0x04, []byte(dn))
	authHeader := append([]byte{0x80}, lengthBytes(len(password))...)
	bodyLength := 3 + len(name) + len(authHeader) + len(password)
	bindHeader := append([]byte{0x60}, lengthBytes(bodyLength)...)
	outerLength := 3 + len(bindHeader) + bodyLength
	prefix := append([]byte{0x30}, lengthBytes(outerLength)...)
	prefix = append(prefix, 0x02, 0x01, messageID)
	prefix = append(prefix, bindHeader...)
	prefix = append(prefix, 0x02, 0x01, 0x03)
	prefix = append(prefix, name...)
	prefix = append(prefix, authHeader...)
	packet, err := secret.New(len(prefix) + len(password))
	if err != nil {
		return nil, err
	}
	copy(packet.Bytes(), prefix)
	copy(packet.Bytes()[len(prefix):], password)
	return packet, nil
}
func frameHeader(reader io.Reader, limit int) ([]byte, int, error) {
	var first [2]byte
	if _, err := io.ReadFull(reader, first[:]); err != nil {
		return nil, 0, err
	}
	if first[0] != 0x30 {
		return nil, 0, errors.New("LDAP response is not a message sequence")
	}
	header := append([]byte(nil), first[:]...)
	size := int(first[1])
	if first[1]&0x80 != 0 {
		count := int(first[1] & 0x7f)
		if count == 0 || count > 4 {
			return nil, 0, errors.New("LDAP response has an indefinite or oversized length")
		}
		extra := make([]byte, count)
		if _, err := io.ReadFull(reader, extra); err != nil {
			return nil, 0, err
		}
		header = append(header, extra...)
		size = 0
		for _, value := range extra {
			if size > limit>>8 {
				return nil, 0, errors.New("LDAP response exceeds its frame bound")
			}
			size = size<<8 | int(value)
		}
	}
	if size <= 0 || size > limit-len(header) {
		return nil, 0, errors.New("LDAP response exceeds its frame bound")
	}
	return header, size, nil
}
func readLDAPFrame(reader io.Reader, limit int) ([]byte, error) {
	header, size, err := frameHeader(reader, limit)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(header)+size)
	copy(out, header)
	if _, err := io.ReadFull(reader, out[len(header):]); err != nil {
		secret.Wipe(out)
		return nil, err
	}
	return out, nil
}
func takeTLV(raw []byte) (byte, []byte, []byte, error) {
	if len(raw) < 2 {
		return 0, nil, nil, errors.New("LDAP value is truncated")
	}
	size, offset := int(raw[1]), 2
	if raw[1]&0x80 != 0 {
		count := int(raw[1] & 0x7f)
		if count == 0 || count > 4 || count > len(raw)-2 {
			return 0, nil, nil, errors.New("LDAP value length is invalid")
		}
		offset += count
		size = 0
		for _, value := range raw[2:offset] {
			if size > maxAuthenticationReply>>8 {
				return 0, nil, nil, errors.New("LDAP authentication value exceeds its bound")
			}
			size = size<<8 | int(value)
		}
	}
	if size > len(raw)-offset || size > maxAuthenticationReply {
		return 0, nil, nil, errors.New("LDAP value exceeds its envelope")
	}
	return raw[0], raw[offset : offset+size], raw[offset+size:], nil
}

// parseLDAPResult validates the exact operation. Server diagnostics/referrals
// never enter errors or logs; only a closed numeric result is returned.
func parseLDAPResult(raw []byte, messageID, operation byte) error {
	if len(raw) > maxAuthenticationReply {
		return errors.New("LDAP authentication reply exceeds its bound")
	}
	tag, outer, rest, err := takeTLV(raw)
	if err != nil || tag != 0x30 || len(rest) != 0 {
		return errors.New("LDAP authentication envelope is invalid")
	}
	tag, id, tail, err := takeTLV(outer)
	if err != nil || tag != 0x02 || len(id) != 1 || id[0] != messageID {
		return errors.New("LDAP authentication reply belongs to another operation")
	}
	tag, result, extensions, err := takeTLV(tail)
	if err != nil || tag != operation {
		return errors.New("LDAP authentication reply has the wrong operation")
	}
	for len(extensions) > 0 {
		_, _, extensions, err = takeTLV(extensions)
		if err != nil {
			return errors.New("LDAP message extension is invalid")
		}
	}
	tag, code, next, err := takeTLV(result)
	if err != nil || tag != 0x0a || len(code) != 1 {
		return errors.New("LDAP authentication result code is invalid")
	}
	var diagnostic []byte
	for field := range 2 {
		var value []byte
		tag, value, next, err = takeTLV(next)
		if err != nil || tag != 0x04 {
			return errors.New("LDAP authentication result is truncated")
		}
		if field == 1 {
			diagnostic = value
		}
	}
	// RFC4511 permits trailing extension components. Bound their TLVs without
	// interpreting or exposing unknown server data.
	for len(next) > 0 {
		_, _, next, err = takeTLV(next)
		if err != nil {
			return errors.New("LDAP authentication extension is invalid")
		}
	}
	if code[0] != 0 {
		return &RefusalError{Result: code[0], ADData: adSubStatus(diagnostic)}
	}
	return nil
}

// RefusalError is an operation the directory answered with a result other
// than success. ADData is Active Directory's sub-status from the diagnostic
// message ("AcceptSecurityContext error, data 52e"; Microsoft's LDAP error
// reference), 0 when there is none; nothing else of the server's text is kept.
type RefusalError struct {
	Result byte
	ADData uint32
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("LDAP operation was refused (result %d)", e.Result)
}

// adSubStatus reads the hexadecimal sub-status after "data " in an Active
// Directory diagnostic message: at most eight digits, ended by a comma, a
// space or the message's end. Anything else is 0.
func adSubStatus(diagnostic []byte) uint32 {
	const marker = "data "
	for i := 0; i+len(marker) <= len(diagnostic); i++ {
		if string(diagnostic[i:i+len(marker)]) != marker || (i > 0 && diagnostic[i-1] != ' ') {
			continue
		}
		var value uint32
		digits := 0
		for _, c := range diagnostic[i+len(marker):] {
			var d byte
			switch {
			case c >= '0' && c <= '9':
				d = c - '0'
			case c >= 'a' && c <= 'f':
				d = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				d = c - 'A' + 10
			case c == ',' || c == ' ':
				if digits == 0 {
					return 0
				}
				return value
			default:
				return 0
			}
			if digits == 8 {
				return 0
			}
			value = value<<4 | uint32(d)
			digits++
		}
		if digits == 0 {
			return 0
		}
		return value
	}
	return 0
}
