// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"unicode/utf8"
)

// TOML MCP client configuration (P7-L1). Some clients list their MCP servers
// in TOML, one [mcp_servers.<name>] table each, with command, args, env (a
// table or an inline table), url, http_headers and type. This reader takes
// just enough of TOML for that: table headers, dotted and quoted keys, basic,
// literal and multi-line strings, arrays and inline tables. Every string
// value is decoded into its own byte buffer, never a Go string, so a
// credential can be wiped like the JSON path's; keys are names only.

const (
	maxTOMLPairs = 4096
	maxTOMLDepth = 8
)

// tomlValue is a TOML value: a string's decoded bytes, an array, or another
// scalar's raw text (a number, a boolean, a date).
type tomlValue struct {
	isString bool
	isArray  bool
	bytes    []byte
	items    []tomlValue
}

// tomlPair is one key path and its value; inline tables are expanded into
// pairs under their key.
type tomlPair struct {
	key []string
	val tomlValue
}

func (v *tomlValue) wipe() {
	clear(v.bytes)
	for i := range v.items {
		v.items[i].wipe()
	}
}

type tomlReader struct {
	data  []byte
	i     int
	pairs []tomlPair
	ok    bool
}

// parseTOMLPairs reads a TOML document into key paths and values. A document
// it cannot read names nothing (false); the caller wipes the pairs' values.
func parseTOMLPairs(data []byte) ([]tomlPair, bool) {
	r := &tomlReader{data: data, ok: true}
	var table []string
	skipping := false // inside an array of tables, which no server uses
	for r.ok {
		r.skipBlankLines()
		if r.i >= len(r.data) {
			break
		}
		if r.data[r.i] == '[' {
			if r.i+1 < len(r.data) && r.data[r.i+1] == '[' {
				r.i += 2
				if _, ok := r.keyPath(']'); !ok || !r.expect(']') || !r.expect(']') {
					return r.fail()
				}
				skipping = true
			} else {
				r.i++
				path, ok := r.keyPath(']')
				if !ok || !r.expect(']') {
					return r.fail()
				}
				table, skipping = path, false
			}
			if !r.endOfLine() {
				return r.fail()
			}
			continue
		}
		key, ok := r.keyPath('=')
		if !ok || !r.expect('=') {
			return r.fail()
		}
		r.spaces()
		full := append(append([]string(nil), table...), key...)
		if !r.value(full, 0, !skipping) || !r.endOfLine() {
			return r.fail()
		}
	}
	if !r.ok {
		return r.fail()
	}
	return r.pairs, true
}

func (r *tomlReader) fail() ([]tomlPair, bool) {
	r.ok = false
	for i := range r.pairs {
		r.pairs[i].val.wipe()
	}
	return nil, false
}

// skipBlankLines passes whitespace, newlines and comment lines.
func (r *tomlReader) skipBlankLines() {
	for r.i < len(r.data) {
		switch r.data[r.i] {
		case ' ', '\t', '\r', '\n':
			r.i++
		case '#':
			r.skipComment()
		default:
			return
		}
	}
}

func (r *tomlReader) skipComment() {
	for r.i < len(r.data) && r.data[r.i] != '\n' {
		r.i++
	}
}

func (r *tomlReader) spaces() {
	for r.i < len(r.data) && (r.data[r.i] == ' ' || r.data[r.i] == '\t') {
		r.i++
	}
}

// endOfLine accepts spaces and a comment up to the line's end.
func (r *tomlReader) endOfLine() bool {
	r.spaces()
	if r.i < len(r.data) && r.data[r.i] == '#' {
		r.skipComment()
	}
	if r.i >= len(r.data) {
		return true
	}
	if r.data[r.i] == '\r' {
		r.i++
	}
	if r.i < len(r.data) && r.data[r.i] == '\n' {
		r.i++
		return true
	}
	return r.i >= len(r.data)
}

func (r *tomlReader) expect(c byte) bool {
	r.spaces()
	if r.i < len(r.data) && r.data[r.i] == c {
		r.i++
		return true
	}
	return false
}

// keyPath reads a dotted key of bare and quoted parts, up to stop.
func (r *tomlReader) keyPath(stop byte) ([]string, bool) {
	var path []string
	for {
		r.spaces()
		if r.i >= len(r.data) {
			return nil, false
		}
		var part []byte
		switch r.data[r.i] {
		case '"':
			s, ok := r.basicString()
			if !ok {
				return nil, false
			}
			part = s
		case '\'':
			s, ok := r.literalString()
			if !ok {
				return nil, false
			}
			part = s
		default:
			start := r.i
			for r.i < len(r.data) && bareKeyByte(r.data[r.i]) {
				r.i++
			}
			if r.i == start {
				return nil, false
			}
			part = r.data[start:r.i]
		}
		path = append(path, string(part)) // a key is a name, never a value
		r.spaces()
		if r.i < len(r.data) && r.data[r.i] == '.' {
			r.i++
			continue
		}
		if r.i < len(r.data) && r.data[r.i] == stop && len(path) <= maxTOMLDepth {
			return path, true
		}
		return nil, false
	}
}

func bareKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// value reads one value for key; inline tables become pairs under key. keep
// is false inside an array of tables, whose values are read and dropped.
func (r *tomlReader) value(key []string, depth int, keep bool) bool {
	if depth > maxTOMLDepth || r.i >= len(r.data) {
		return false
	}
	if r.data[r.i] == '{' {
		r.i++
		for first := true; ; first = false {
			r.spaces()
			if r.i < len(r.data) && r.data[r.i] == '}' && first {
				r.i++
				return true
			}
			sub, ok := r.keyPath('=')
			if !ok || !r.expect('=') {
				return false
			}
			r.spaces()
			if !r.value(append(append([]string(nil), key...), sub...), depth+1, keep) {
				return false
			}
			r.spaces()
			if r.i >= len(r.data) {
				return false
			}
			if r.data[r.i] == '}' {
				r.i++
				return true
			}
			if r.data[r.i] != ',' {
				return false
			}
			r.i++
		}
	}
	v, ok := r.scalarOrArray(depth)
	if !ok {
		return false
	}
	if !keep || len(r.pairs) >= maxTOMLPairs {
		// Dropped (inside an array of tables), or past the bound: a
		// document that large names nothing.
		v.wipe()
		return !keep
	}
	r.pairs = append(r.pairs, tomlPair{key: key, val: v})
	return true
}

// scalarOrArray reads a string, an array or another scalar.
func (r *tomlReader) scalarOrArray(depth int) (tomlValue, bool) {
	switch r.data[r.i] {
	case '"':
		s, ok := r.basicString()
		return tomlValue{isString: true, bytes: s}, ok
	case '\'':
		s, ok := r.literalString()
		return tomlValue{isString: true, bytes: s}, ok
	case '[':
		r.i++
		arr := tomlValue{isArray: true}
		for {
			r.skipBlankLines()
			if r.i >= len(r.data) || depth > maxTOMLDepth {
				arr.wipe()
				return tomlValue{}, false
			}
			if r.data[r.i] == ']' {
				r.i++
				return arr, true
			}
			if r.data[r.i] == '{' {
				// An inline table in an array is no server field: read it and drop it.
				if !r.value(nil, depth+1, false) {
					arr.wipe()
					return tomlValue{}, false
				}
			} else {
				item, ok := r.scalarOrArray(depth + 1)
				if !ok {
					arr.wipe()
					return tomlValue{}, false
				}
				arr.items = append(arr.items, item)
			}
			r.skipBlankLines()
			if r.i < len(r.data) && r.data[r.i] == ',' {
				r.i++
				continue
			}
			r.skipBlankLines()
			if r.i < len(r.data) && r.data[r.i] == ']' {
				r.i++
				return arr, true
			}
			arr.wipe()
			return tomlValue{}, false
		}
	default:
		// A number, a boolean or a date: one token, but a date and its time
		// may be split by one space (1979-05-27 07:32:00Z).
		start := r.i
		r.bareToken()
		if r.i-start == 10 && r.i+1 < len(r.data) && r.data[r.i] == ' ' && r.data[r.i+1] >= '0' && r.data[r.i+1] <= '9' &&
			r.data[start+4] == '-' && r.data[start+7] == '-' {
			r.i++
			r.bareToken()
		}
		if r.i == start {
			return tomlValue{}, false
		}
		return tomlValue{bytes: append([]byte(nil), r.data[start:r.i]...)}, true
	}
}

// bareToken passes the bytes of an unquoted scalar.
func (r *tomlReader) bareToken() {
	for r.i < len(r.data) {
		c := r.data[r.i]
		if c == ',' || c == ']' || c == '}' || c == '#' || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			return
		}
		r.i++
	}
}

// basicString reads "..." or """...""" with TOML's escapes into a new buffer.
func (r *tomlReader) basicString() ([]byte, bool) {
	multi := r.i+2 < len(r.data) && r.data[r.i+1] == '"' && r.data[r.i+2] == '"'
	if multi {
		r.i += 3
		if r.i < len(r.data) && r.data[r.i] == '\n' {
			r.i++
		} else if r.i+1 < len(r.data) && r.data[r.i] == '\r' && r.data[r.i+1] == '\n' {
			r.i += 2
		}
	} else {
		r.i++
	}
	var out []byte
	for r.i < len(r.data) {
		c := r.data[r.i]
		switch {
		case multi && c == '"' && r.i+2 < len(r.data) && r.data[r.i+1] == '"' && r.data[r.i+2] == '"':
			r.i += 3
			// Up to two more quotes belong to the string.
			for k := 0; k < 2 && r.i < len(r.data) && r.data[r.i] == '"'; k++ {
				out = append(out, '"')
				r.i++
			}
			return out, true
		case !multi && c == '"':
			r.i++
			return out, true
		case !multi && (c == '\n' || c == '\r'):
			clear(out)
			return nil, false
		case c == '\\':
			r.i++
			if r.i >= len(r.data) {
				clear(out)
				return nil, false
			}
			e := r.data[r.i]
			r.i++
			switch e {
			case 'b':
				out = append(out, '\b')
			case 't':
				out = append(out, '\t')
			case 'n':
				out = append(out, '\n')
			case 'f':
				out = append(out, '\f')
			case 'r':
				out = append(out, '\r')
			case 'e':
				out = append(out, 0x1b)
			case '"':
				out = append(out, '"')
			case '\\':
				out = append(out, '\\')
			case 'u', 'U':
				n := 4
				if e == 'U' {
					n = 8
				}
				cp, ok := hexRune(r.data, r.i, n)
				if !ok {
					clear(out)
					return nil, false
				}
				r.i += n
				out = utf8.AppendRune(out, cp)
			case ' ', '\t', '\r', '\n':
				if !multi {
					clear(out)
					return nil, false
				}
				// A line-ending backslash trims the following whitespace.
				r.i--
				for r.i < len(r.data) && (r.data[r.i] == ' ' || r.data[r.i] == '\t' || r.data[r.i] == '\r' || r.data[r.i] == '\n') {
					r.i++
				}
			default:
				clear(out)
				return nil, false
			}
		default:
			out = append(out, c)
			r.i++
		}
	}
	clear(out)
	return nil, false
}

// literalString reads a literal string, on one line or across lines (opened
// by three single quotes), into a new buffer; it has no escapes.
func (r *tomlReader) literalString() ([]byte, bool) {
	multi := r.i+2 < len(r.data) && r.data[r.i+1] == '\'' && r.data[r.i+2] == '\''
	if multi {
		r.i += 3
		if r.i < len(r.data) && r.data[r.i] == '\n' {
			r.i++
		}
	} else {
		r.i++
	}
	var out []byte
	for r.i < len(r.data) {
		c := r.data[r.i]
		switch {
		case multi && c == '\'' && r.i+2 < len(r.data) && r.data[r.i+1] == '\'' && r.data[r.i+2] == '\'':
			r.i += 3
			for k := 0; k < 2 && r.i < len(r.data) && r.data[r.i] == '\''; k++ {
				out = append(out, '\'')
				r.i++
			}
			return out, true
		case !multi && c == '\'':
			r.i++
			return out, true
		case !multi && (c == '\n' || c == '\r'):
			clear(out)
			return nil, false
		default:
			out = append(out, c)
			r.i++
		}
	}
	clear(out)
	return nil, false
}

// hexRune reads n hex digits at i as a Unicode scalar value.
func hexRune(data []byte, i, n int) (rune, bool) {
	if i+n > len(data) {
		return 0, false
	}
	var v rune
	for _, c := range data[i : i+n] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | rune(d)
	}
	if v > utf8.MaxRune || (v >= 0xD800 && v <= 0xDFFF) {
		return 0, false
	}
	return v, true
}
