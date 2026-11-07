// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

func nativeSIDBytes(raw []byte) (string, error) {
	if len(raw) < 8 || raw[0] != 1 || raw[1] > 15 || len(raw) < 8+4*int(raw[1]) {
		return "", ErrInventory
	}
	authority := uint64(0)
	for _, value := range raw[2:8] {
		authority = authority<<8 | uint64(value)
	}
	var result strings.Builder
	result.WriteString("S-1-")
	result.WriteString(strconv.FormatUint(authority, 10))
	for n := 0; n < int(raw[1]); n++ {
		result.WriteByte('-')
		result.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[8+4*n:])), 10))
	}
	return result.String(), nil
}
func nativeWideBytes(raw []byte, limit int) (string, error) {
	if limit < 0 || limit > 255 {
		return "", ErrInventory
	}
	units := make([]uint16, 0, limit)
	for n := 0; n <= limit; n++ {
		if len(raw) < 2*n+2 {
			return "", ErrInventory
		}
		unit := binary.LittleEndian.Uint16(raw[2*n:])
		if unit == 0 {
			for i := 0; i < len(units); i++ {
				if units[i] >= 0xd800 && units[i] <= 0xdbff {
					i++
					if i >= len(units) || units[i] < 0xdc00 || units[i] > 0xdfff {
						return "", ErrInventory
					}
				} else if units[i] >= 0xdc00 && units[i] <= 0xdfff {
					return "", ErrInventory
				}
			}
			return string(utf16.Decode(units)), nil
		}
		if n == limit {
			return "", ErrInventory
		}
		units = append(units, unit)
	}
	return "", ErrInventory
}
