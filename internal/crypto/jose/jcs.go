// SPDX-License-Identifier: BUSL-1.1

package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JSON Canonicalization Scheme (RFC 8785, JCS): the canonical form a JSF
// signature is computed over (Q3-L1). The input must be I-JSON (RFC 7493):
// valid UTF-8, no lone UTF-16 surrogate escapes, no repeated member names and
// numbers an IEEE 754 double holds. Anything else is refused rather than
// normalized, so two different documents never share one canonical form.

// maxJCSDepth bounds nesting (a CycloneDX BOM nests about ten levels).
const maxJCSDepth = 64

// jcsValue is one parsed I-JSON value.
type jcsValue struct {
	kind    byte                 // 'o' object, 'a' array, 's' string, 'n' number, 'l' true/false/null
	text    string               // the string, the number's text, or the literal
	keys    []string             // object member names in document order
	members map[string]*jcsValue // object members
	items   []*jcsValue          // array items
}

// Canonicalize returns the RFC 8785 canonical form of one I-JSON document.
func Canonicalize(doc []byte) ([]byte, error) {
	v, err := parseIJSON(doc)
	if err != nil {
		return nil, err
	}
	return v.canonical()
}

func (v *jcsValue) canonical() ([]byte, error) {
	var out bytes.Buffer
	if err := v.writeCanonical(&out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func parseIJSON(doc []byte) (*jcsValue, error) {
	if !utf8.Valid(doc) {
		return nil, errors.New("jose: JSON is not valid UTF-8")
	}
	if err := checkSurrogateEscapes(doc); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	v, err := readJCSValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("jose: JSON has data after the document")
	}
	return v, nil
}

func readJCSValue(dec *json.Decoder, depth int) (*jcsValue, error) {
	if depth > maxJCSDepth {
		return nil, fmt.Errorf("jose: JSON nests deeper than %d levels", maxJCSDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("jose: read JSON: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		return readJCSContainer(dec, t, depth)
	case string:
		return &jcsValue{kind: 's', text: t}, nil
	case json.Number:
		return &jcsValue{kind: 'n', text: t.String()}, nil
	case bool:
		return &jcsValue{kind: 'l', text: strconv.FormatBool(t)}, nil
	case nil:
		return &jcsValue{kind: 'l', text: "null"}, nil
	}
	return nil, fmt.Errorf("jose: unexpected JSON token %v", tok)
}

func readJCSContainer(dec *json.Decoder, open json.Delim, depth int) (*jcsValue, error) {
	var v *jcsValue
	switch open {
	case '{':
		v = &jcsValue{kind: 'o', members: map[string]*jcsValue{}}
	case '[':
		v = &jcsValue{kind: 'a'}
	default:
		return nil, fmt.Errorf("jose: unexpected %q in JSON", rune(open))
	}
	for dec.More() {
		if v.kind == 'a' {
			item, err := readJCSValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			v.items = append(v.items, item)
			continue
		}
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("jose: read JSON: %w", err)
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("jose: JSON member name is not a string")
		}
		if _, repeated := v.members[name]; repeated {
			return nil, fmt.Errorf("jose: JSON object repeats the member %q", name)
		}
		member, err := readJCSValue(dec, depth+1)
		if err != nil {
			return nil, err
		}
		v.keys = append(v.keys, name)
		v.members[name] = member
	}
	if _, err := dec.Token(); err != nil { // the closing delimiter
		return nil, fmt.Errorf("jose: read JSON: %w", err)
	}
	return v, nil
}

// checkSurrogateEscapes refuses a \uXXXX escape that is half of a UTF-16
// surrogate pair without its other half: encoding/json would read it as
// U+FFFD, so two different documents could share one canonical form.
func checkSurrogateEscapes(doc []byte) error {
	lone := errors.New("jose: JSON string holds a lone UTF-16 surrogate escape")
	inString := false
	for i := 0; i < len(doc); i++ {
		c := doc[i]
		if !inString {
			inString = c == '"'
			continue
		}
		if c == '"' {
			inString = false
			continue
		}
		if c != '\\' || i+1 >= len(doc) {
			continue
		}
		if doc[i+1] != 'u' {
			i++ // an escaped character, never the end of the string
			continue
		}
		u, ok := escapeUnit(doc, i)
		if !ok {
			continue // the decoder refuses the malformed escape
		}
		i += 5
		switch {
		case u >= 0xDC00 && u <= 0xDFFF:
			return lone
		case u >= 0xD800 && u <= 0xDBFF:
			low, ok := escapeUnit(doc, i+1)
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return lone
			}
			i += 6
		}
	}
	return nil
}

// escapeUnit reads the UTF-16 code unit of the \uXXXX escape at doc[at].
func escapeUnit(doc []byte, at int) (rune, bool) {
	if at+6 > len(doc) || doc[at] != '\\' || doc[at+1] != 'u' {
		return 0, false
	}
	var u rune
	for _, h := range doc[at+2 : at+6] {
		var d rune
		switch {
		case h >= '0' && h <= '9':
			d = rune(h - '0')
		case h >= 'a' && h <= 'f':
			d = rune(h-'a') + 10
		case h >= 'A' && h <= 'F':
			d = rune(h-'A') + 10
		default:
			return 0, false
		}
		u = u<<4 | d
	}
	return u, true
}

func (v *jcsValue) writeCanonical(out *bytes.Buffer) error {
	switch v.kind {
	case 'o':
		names := slices.Clone(v.keys)
		slices.SortFunc(names, compareUTF16)
		out.WriteByte('{')
		for i, name := range names {
			if i > 0 {
				out.WriteByte(',')
			}
			writeJCSString(out, name)
			out.WriteByte(':')
			if err := v.members[name].writeCanonical(out); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case 'a':
		out.WriteByte('[')
		for i, item := range v.items {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := item.writeCanonical(out); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case 's':
		writeJCSString(out, v.text)
	case 'n':
		number, err := jcsNumber(v.text)
		if err != nil {
			return err
		}
		out.WriteString(number)
	default:
		out.WriteString(v.text)
	}
	return nil
}

// compareUTF16 orders member names by their UTF-16 code units (RFC 8785
// §3.2.3), which puts a supplementary character before U+E000–U+FFFF.
func compareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

// writeJCSString writes a string as ECMAScript's JSON.stringify does (RFC 8785
// §3.2.2.2): only the quote, the backslash and the controls are escaped.
func writeJCSString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				_, _ = fmt.Fprintf(out, `\u%04x`, r)
				continue
			}
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
}

// jcsNumber renders a JSON number as ECMAScript's Number.prototype.toString
// does (RFC 8785 §3.2.2.3): the shortest digits that round-trip the IEEE 754
// double, fixed notation from 1e-6 up to 1e21 and exponential outside it.
func jcsNumber(text string) (string, error) {
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("jose: JSON number %q does not fit an IEEE 754 double", text)
	}
	if f == 0 {
		return "0", nil // -0 too
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	if f >= 1e-6 && f < 1e21 {
		return sign + strconv.FormatFloat(f, 'f', -1, 64), nil
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	return sign + mantissa + "e" + exponent[:1] + strings.TrimLeft(exponent[1:], "0"), nil
}
