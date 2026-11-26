// SPDX-License-Identifier: BUSL-1.1

package inputtext

import "bytes"

// PostgreSQL jsonb stores numbers as numeric: at most 131072 decimal digits
// before the point and 16383 after it. It also rejects unpaired UTF-16
// surrogate escapes that encoding/json replaces with U+FFFD. This lexical
// pass checks those shapes without converting numbers to float64 or changing
// the event's immutable payload. The caller confirms JSON syntax before
// returning a found error, so non-JSON event data remains opaque.
func validateJSONBShape(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); {
		if inString {
			switch raw[i] {
			case '"':
				inString = false
				i++
			case '\\':
				if i+1 >= len(raw) {
					return nil
				}
				if raw[i+1] != 'u' {
					i += 2
					continue
				}
				unit, ok := jsonHexUnit(raw, i)
				if !ok {
					i += 2
					continue
				}
				switch {
				case unit >= 0xd800 && unit <= 0xdbff:
					low, ok := jsonHexUnit(raw, i+6)
					if !ok || low < 0xdc00 || low > 0xdfff {
						return ErrInvalidUnicodeEscape
					}
					i += 12
				case unit >= 0xdc00 && unit <= 0xdfff:
					return ErrInvalidUnicodeEscape
				default:
					i += 6
				}
			default:
				i++
			}
			continue
		}
		switch {
		case raw[i] == '"':
			inString = true
			i++
		case raw[i] == '-' || (raw[i] >= '0' && raw[i] <= '9'):
			start := i
			for i < len(raw) && !jsonNumberDelimiter(raw[i]) {
				i++
			}
			if err := validateJSONBNumber(raw[start:i]); err != nil {
				return err
			}
		default:
			i++
		}
	}
	return nil
}

func jsonHexUnit(raw []byte, at int) (uint16, bool) {
	if at+6 > len(raw) || raw[at] != '\\' || raw[at+1] != 'u' {
		return 0, false
	}
	var value uint16
	for _, digit := range raw[at+2 : at+6] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func jsonNumberDelimiter(value byte) bool {
	return value == ',' || value == '}' || value == ']' || value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func validateJSONBNumber(token []byte) error {
	exponent := 0
	mantissa := token
	if at := bytes.IndexAny(token, "eE"); at >= 0 {
		mantissa = token[:at]
		power := token[at+1:]
		sign := 1
		if len(power) > 0 && (power[0] == '+' || power[0] == '-') {
			if power[0] == '-' {
				sign = -1
			}
			power = power[1:]
		}
		for _, digit := range power {
			if digit < '0' || digit > '9' {
				return nil // JSON syntax validation belongs to the caller.
			}
			if exponent > 200_000 {
				return ErrJSONNumberRange
			}
			exponent = exponent*10 + int(digit-'0')
		}
		exponent *= sign
	}
	before, after := 0, 0
	decimal := false
	for _, digit := range mantissa {
		if digit == '.' {
			decimal = true
			continue
		}
		if digit < '0' || digit > '9' {
			continue
		}
		if decimal {
			after++
		} else {
			before++
		}
	}
	if before+exponent > 131_072 || after-exponent > 16_383 {
		return ErrJSONNumberRange
	}
	return nil
}
