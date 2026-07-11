// SPDX-License-Identifier: MPL-2.0

package secret

import (
	"encoding/xml"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// JSONBytes is secret text that JSON/XML decoders keep in wipeable byte memory.
// Standard string fields are forbidden for tokens/passwords because the Go GC may
// copy immutable strings and those copies cannot be zeroed (AN-8).
type JSONBytes []byte

func (b *JSONBytes) UnmarshalJSON(raw []byte) error {
	decoded, err := decodeJSONString(raw)
	if err != nil {
		return err
	}
	Wipe(*b)
	*b = decoded
	return nil
}

func (b JSONBytes) MarshalJSON() ([]byte, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("secret: JSON secret is not valid UTF-8")
	}
	out := make([]byte, 0, len(b)+2)
	out = append(out, '"')
	for _, c := range b {
		switch c {
		case '"', '\\':
			out = append(out, '\\', c)
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 0x20 {
				out = append(out, '\\', 'u', '0', '0', lowerHex[c>>4], lowerHex[c&0x0f])
			} else {
				out = append(out, c)
			}
		}
	}
	return append(out, '"'), nil
}

// UnmarshalXML copies character data directly from the decoder's byte token. It
// rejects nested elements so an unexpected provider response cannot be flattened
// into a credential silently.
func (b *JSONBytes) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var out []byte
	for {
		token, err := d.Token()
		if err != nil {
			Wipe(out)
			return err
		}
		switch value := token.(type) {
		case xml.CharData:
			out = append(out, value...)
		case xml.StartElement:
			Wipe(out)
			return errors.New("secret: nested XML element in secret value")
		case xml.EndElement:
			if value.Name == start.Name {
				Wipe(*b)
				*b = out
				return nil
			}
		}
	}
}

func decodeJSONString(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("secret: expected a JSON string")
	}
	out := make([]byte, 0, len(raw)-2)
	for i := 1; i < len(raw)-1; i++ {
		c := raw[i]
		if c < 0x20 {
			Wipe(out)
			return nil, errors.New("secret: unescaped JSON control byte")
		}
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(raw)-1 {
			Wipe(out)
			return nil, errors.New("secret: truncated JSON escape")
		}
		switch raw[i] {
		case '"', '\\', '/':
			out = append(out, raw[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, next, err := decodeJSONRune(raw, i+1)
			if err != nil {
				Wipe(out)
				return nil, err
			}
			i = next - 1
			out = utf8.AppendRune(out, r)
		default:
			Wipe(out)
			return nil, errors.New("secret: invalid JSON escape")
		}
	}
	if !utf8.Valid(out) {
		Wipe(out)
		return nil, errors.New("secret: JSON secret is not valid UTF-8")
	}
	return out, nil
}

func decodeJSONRune(raw []byte, start int) (rune, int, error) {
	first, next, err := decodeHexRune(raw, start)
	if err != nil {
		return 0, start, err
	}
	if first < 0xD800 || first > 0xDFFF {
		return rune(first), next, nil
	}
	if first > 0xDBFF || next+6 > len(raw) || raw[next] != '\\' || raw[next+1] != 'u' {
		return 0, start, errors.New("secret: invalid JSON surrogate pair")
	}
	second, end, err := decodeHexRune(raw, next+2)
	if err != nil || second < 0xDC00 || second > 0xDFFF {
		return 0, start, errors.New("secret: invalid JSON surrogate pair")
	}
	r := utf16.DecodeRune(rune(first), rune(second))
	if r == utf8.RuneError {
		return 0, start, errors.New("secret: invalid JSON surrogate pair")
	}
	return r, end, nil
}

func decodeHexRune(raw []byte, start int) (uint16, int, error) {
	if start+4 > len(raw) {
		return 0, start, errors.New("secret: truncated JSON unicode escape")
	}
	var value uint16
	for _, c := range raw[start : start+4] {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			value |= uint16(c-'A') + 10
		default:
			return 0, start, fmt.Errorf("secret: invalid JSON unicode escape")
		}
	}
	return value, start + 4, nil
}

const lowerHex = "0123456789abcdef"
