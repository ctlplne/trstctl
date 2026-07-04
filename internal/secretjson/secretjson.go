// SPDX-License-Identifier: MPL-2.0

// Package secretjson contains JSON marshal helpers for edge payloads that must
// carry secret bytes as wire strings without first materializing those bytes as
// Go strings.
package secretjson

import (
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// StringBytes marshals src as a JSON string, escaping the source bytes directly.
// It is intended for PEM/API fields whose wire schema is a string while trstctl's
// in-memory custody stays in []byte (AN-8).
type StringBytes []byte

// MarshalJSON implements json.Marshaler without converting the secret bytes to a
// string.
func (b StringBytes) MarshalJSON() ([]byte, error) {
	return QuoteBytes(b), nil
}

// UnmarshalJSON decodes a JSON string into byte-backed material without
// materializing the string as a Go string.
func (b *StringBytes) UnmarshalJSON(src []byte) error {
	out, err := UnquoteBytes(src)
	if err != nil {
		return err
	}
	secret.Wipe(*b)
	*b = out
	return nil
}

// Base64Bytes marshals src as a base64-encoded JSON string without constructing a
// Go string copy of either the source or encoded value.
type Base64Bytes []byte

// MarshalJSON implements json.Marshaler without using EncodeToString.
func (b Base64Bytes) MarshalJSON() ([]byte, error) {
	return QuoteBase64(b), nil
}

// QuoteBytes returns src quoted as a JSON string. PEM and base64 connector
// payloads are ASCII; bytes outside the JSON control range are copied as-is.
func QuoteBytes(src []byte) []byte {
	out := make([]byte, 0, len(src)+2)
	return appendQuoted(out, src)
}

// QuoteBase64 returns base64(src) quoted as a JSON string.
func QuoteBase64(src []byte) []byte {
	encLen := base64.StdEncoding.EncodedLen(len(src))
	out := make([]byte, 0, encLen+2)
	out = append(out, '"')
	start := len(out)
	out = append(out, make([]byte, encLen)...)
	base64.StdEncoding.Encode(out[start:start+encLen], src)
	out = append(out, '"')
	return out
}

func appendQuoted(dst, src []byte) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for _, c := range src {
		switch c {
		case '\\', '"':
			dst = append(dst, '\\', c)
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0x0f])
			} else {
				dst = append(dst, c)
			}
		}
	}
	dst = append(dst, '"')
	return dst
}

// UnquoteBytes decodes a JSON string literal into bytes without constructing a
// Go string for the decoded value.
func UnquoteBytes(src []byte) ([]byte, error) {
	if len(src) < 2 || src[0] != '"' || src[len(src)-1] != '"' {
		return nil, errors.New("secretjson: expected JSON string")
	}
	out := make([]byte, 0, len(src)-2)
	for i := 1; i < len(src)-1; i++ {
		c := src[i]
		if c == '\\' {
			if i+1 >= len(src)-1 {
				return nil, errors.New("secretjson: incomplete escape")
			}
			i++
			switch esc := src[i]; esc {
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
				r, n, err := readJSONRune(src, i)
				if err != nil {
					return nil, err
				}
				out = utf8.AppendRune(out, r)
				i += n
			default:
				return nil, fmt.Errorf("secretjson: invalid escape %q", esc)
			}
			continue
		}
		if c < 0x20 {
			return nil, errors.New("secretjson: unescaped control byte")
		}
		out = append(out, c)
	}
	return out, nil
}

func readJSONRune(src []byte, slashU int) (rune, int, error) {
	r1, err := readHexRune(src, slashU+1)
	if err != nil {
		return 0, 0, err
	}
	if !utf16.IsSurrogate(r1) {
		return r1, 4, nil
	}
	if slashU+11 >= len(src) || src[slashU+5] != '\\' || src[slashU+6] != 'u' {
		return 0, 0, errors.New("secretjson: incomplete surrogate pair")
	}
	r2, err := readHexRune(src, slashU+7)
	if err != nil {
		return 0, 0, err
	}
	decoded := utf16.DecodeRune(r1, r2)
	if decoded == utf8.RuneError {
		return 0, 0, errors.New("secretjson: invalid surrogate pair")
	}
	return decoded, 10, nil
}

func readHexRune(src []byte, start int) (rune, error) {
	if start+4 > len(src) {
		return 0, errors.New("secretjson: short unicode escape")
	}
	var r rune
	for _, c := range src[start : start+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, fmt.Errorf("secretjson: invalid unicode escape byte %q", c)
		}
	}
	return r, nil
}
