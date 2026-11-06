// SPDX-License-Identifier: BUSL-1.1
package windependents

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf16"
	"unicode/utf8"
)

// nativeWideBytes bounds native string pointers after the Windows caller has
// converted them to offsets in its owned locked query buffer. Private values
// remain byte slices; only explicitly public names are decoded to strings.
func nativeWideBytes(raw []byte, offset int, multi bool) ([]byte, error) {
	if offset < 0 || offset%2 != 0 || offset > len(raw)-2 {
		return nil, errors.New("windows service: native string outside query buffer")
	}
	start := offset
	for offset+1 < len(raw) {
		if binary.LittleEndian.Uint16(raw[offset:]) == 0 {
			if !multi {
				return raw[start:offset], nil
			}
			if offset+3 < len(raw) && binary.LittleEndian.Uint16(raw[offset+2:]) == 0 {
				return raw[start : offset+2], nil
			}
		}
		offset += 2
	}
	return nil, errors.New("windows service: native string is unterminated")
}
func publicNativeText(raw []byte) (string, error) {
	if len(raw)%2 != 0 || len(raw) > 8192 {
		return "", errors.New("windows service: invalid public native name")
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	for i := 0; i < len(units); i++ {
		if units[i] >= 0xd800 && units[i] <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", errors.New("windows service: invalid public native surrogate")
			}
			i++
		} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
			return "", errors.New("windows service: invalid public native surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}
func serviceConfigurationHash(name, sid string, numbers []uint32, fields [][]byte) string {
	return nativeConfigurationHash("trstctl/windows-service/config/v1", name, sid, numbers, fields)
}
func nativeConfigurationHash(domain, name, sid string, numbers []uint32, fields [][]byte) string {
	h := sha256.New()
	// Length framing prevents a field boundary from changing the frozen meaning.
	write := func(raw []byte) {
		var size [8]byte
		binary.LittleEndian.PutUint64(size[:], uint64(len(raw)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(raw)
	}
	var counts [16]byte
	binary.LittleEndian.PutUint64(counts[:8], uint64(len(numbers)))
	binary.LittleEndian.PutUint64(counts[8:], uint64(len(fields)))
	_, _ = h.Write(counts[:])
	write([]byte(domain))
	write([]byte(name))
	write([]byte(sid))
	for _, value := range numbers {
		var raw [4]byte
		binary.LittleEndian.PutUint32(raw[:], value)
		write(raw[:])
	}
	for _, raw := range fields {
		write(raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func lockedWindowsPassword(password []byte) (*secret.Buffer, error) {
	if err := validateServicePassword(password); err != nil {
		return nil, err
	}
	units := 1
	for cursor := 0; cursor < len(password); {
		r, n := utf8.DecodeRune(password[cursor:])
		cursor += n
		units++
		if r > 0xffff {
			units++
		}
	}
	held, err := secret.New(units * 2)
	if err != nil {
		return nil, err
	}
	raw := held.Bytes()
	used := 0
	put := func(v uint16) { binary.LittleEndian.PutUint16(raw[used:], v); used += 2 }
	for len(password) > 0 {
		r, n := utf8.DecodeRune(password)
		password = password[n:]
		if r <= 0xffff {
			put(uint16(r & 0xffff))
		} else {
			r -= 0x10000
			put(0xd800 | uint16((r>>10)&0x3ff))
			put(0xdc00 | uint16(r&0x3ff))
		}
	}
	return held, nil
}
