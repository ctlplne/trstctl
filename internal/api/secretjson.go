package api

import (
	"bytes"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// secretJSONBytes is a JSON string on the wire backed by wipeable bytes in Go.
// It preserves the existing API contract while avoiding immutable string copies
// for secret values, bearer share tokens, workload credentials, and private keys.
type secretJSONBytes []byte

func (b *secretJSONBytes) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*b = nil
		return nil
	}
	out, err := decodeJSONStringBytes(data)
	if err != nil {
		return err
	}
	*b = out
	return nil
}

func (b secretJSONBytes) MarshalJSON() ([]byte, error) {
	return appendJSONQuotedBytes(nil, b), nil
}

func (b secretJSONBytes) wipe() {
	secret.Wipe([]byte(b))
}

func decodeJSONStringBytes(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, fmt.Errorf("expected JSON string")
	}
	out := make([]byte, 0, len(data)-2)
	for i := 1; i < len(data)-1; i++ {
		c := data[i]
		if c == '"' || c < 0x20 {
			return nil, fmt.Errorf("invalid JSON string")
		}
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(data)-1 {
			return nil, fmt.Errorf("invalid JSON escape")
		}
		switch esc := data[i]; esc {
		case '"', '\\', '/':
			out = append(out, esc)
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
			r, ni, err := decodeUnicodeEscape(data, i+1)
			if err != nil {
				return nil, err
			}
			i = ni
			out = utf8.AppendRune(out, r)
		default:
			return nil, fmt.Errorf("invalid JSON escape")
		}
	}
	return out, nil
}

func decodeUnicodeEscape(data []byte, start int) (rune, int, error) {
	if start+4 > len(data)-1 {
		return 0, 0, fmt.Errorf("invalid unicode escape")
	}
	v, ok := hex4(data[start : start+4])
	if !ok {
		return 0, 0, fmt.Errorf("invalid unicode escape")
	}
	r := rune(v)
	end := start + 3
	if utf16.IsSurrogate(r) {
		next := start + 4
		if next+6 > len(data)-1 || data[next] != '\\' || data[next+1] != 'u' {
			return 0, 0, fmt.Errorf("invalid unicode surrogate pair")
		}
		lo, ok := hex4(data[next+2 : next+6])
		if !ok {
			return 0, 0, fmt.Errorf("invalid unicode escape")
		}
		combined := utf16.DecodeRune(r, rune(lo))
		if combined == utf8.RuneError {
			return 0, 0, fmt.Errorf("invalid unicode surrogate pair")
		}
		r = combined
		end = next + 5
	}
	return r, end, nil
}

func hex4(src []byte) (uint16, bool) {
	if len(src) != 4 {
		return 0, false
	}
	var v uint16
	for _, c := range src {
		n, ok := hexNibble(c)
		if !ok {
			return 0, false
		}
		v = v<<4 | uint16(n)
	}
	return v, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func appendJSONQuotedBytes(dst []byte, src []byte) []byte {
	dst = append(dst, '"')
	for len(src) > 0 {
		r, size := utf8.DecodeRune(src)
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, `\ufffd`...)
			src = src[1:]
			continue
		}
		switch r {
		case '\\', '"':
			dst = append(dst, '\\', byte(r))
		case '\b':
			dst = append(dst, `\b`...)
		case '\f':
			dst = append(dst, `\f`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			if r < 0x20 {
				dst = append(dst, `\u00`...)
				dst = append(dst, "0123456789abcdef"[byte(r)>>4], "0123456789abcdef"[byte(r)&0x0f])
			} else {
				dst = append(dst, src[:size]...)
			}
		}
		src = src[size:]
	}
	dst = append(dst, '"')
	return dst
}
