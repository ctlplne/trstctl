// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"bytes"
	"unicode/utf8"
)

// YAML MCP client configuration (P7-L1). Some clients list their MCP servers
// in YAML: an mcpServers (or mcp_servers, or servers) mapping of name to
// entry, or a sequence of entries that each carry a name. This reader takes
// the part of YAML such files use: block mappings and sequences by
// indentation, flow sequences and mappings on one line, plain, single- and
// double-quoted scalars, literal and folded block scalars, and comments.
// Anchors, aliases, tags and multi-document streams are not read: such a
// file names nothing. Scalars are decoded into their own byte buffers, never
// Go strings, so a credential can be wiped like the JSON path's.

const (
	maxYAMLNodes = 8192
	maxYAMLDepth = 16
)

// yamlNode is a mapping, a sequence or a scalar.
type yamlNode struct {
	kind   byte // 'm', 's' or 'v'
	keys   []string
	values []*yamlNode
	items  []*yamlNode
	scalar []byte
}

func (n *yamlNode) wipe() {
	if n == nil {
		return
	}
	clear(n.scalar)
	for _, v := range n.values {
		v.wipe()
	}
	for _, v := range n.items {
		v.wipe()
	}
}

// get returns a mapping's value for key, or nil.
func (n *yamlNode) get(key string) *yamlNode {
	if n == nil || n.kind != 'm' {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.values[i]
		}
	}
	return nil
}

type yamlLine struct {
	indent int
	text   []byte // without its indentation and comment
}

type yamlReader struct {
	lines []yamlLine
	i     int
	nodes int
	ok    bool
}

// parseYAMLTree reads a YAML document's block structure. A document it
// cannot read names nothing (nil); the caller wipes the tree.
func parseYAMLTree(data []byte) *yamlNode {
	lines, ok := yamlLines(data)
	if !ok || len(lines) == 0 {
		return nil
	}
	r := &yamlReader{lines: lines, ok: true}
	root := r.block(lines[0].indent, 0)
	if !r.ok || r.i != len(r.lines) {
		root.wipe()
		return nil
	}
	return root
}

// yamlLines splits a document into its content lines: blank lines, comment
// lines and a leading document marker dropped, comments cut outside quotes.
// A tab in the indentation, a second document, an anchor, alias or tag make
// it unreadable.
func yamlLines(data []byte) ([]yamlLine, bool) {
	var out []yamlLine
	for _, raw := range bytes.Split(data, []byte("\n")) {
		raw = bytes.TrimRight(raw, "\r")
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		if indent < len(raw) && raw[indent] == '\t' {
			return nil, false
		}
		text := bytes.TrimRight(cutYAMLComment(raw[indent:]), " \t")
		if len(text) == 0 {
			continue
		}
		if bytes.Equal(text, []byte("---")) {
			if len(out) == 0 {
				continue
			}
			return nil, false
		}
		if bytes.Equal(text, []byte("...")) || text[0] == '&' || text[0] == '*' || text[0] == '!' || text[0] == '%' {
			return nil, false
		}
		out = append(out, yamlLine{indent: indent, text: text})
	}
	return out, true
}

// cutYAMLComment drops a comment: a # at the start or after whitespace,
// outside quotes.
func cutYAMLComment(s []byte) []byte {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				quote = 0
			} else if quote == '"' && c == '\\' {
				i++
			}
		case c == '"' || c == '\'':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '[' || s[i-1] == '{' || s[i-1] == ',' || s[i-1] == ':' {
				quote = c
			}
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

func (r *yamlReader) node(kind byte) *yamlNode {
	r.nodes++
	if r.nodes > maxYAMLNodes {
		r.ok = false
	}
	return &yamlNode{kind: kind}
}

// block reads the mapping or sequence whose lines start at indent.
func (r *yamlReader) block(indent, depth int) *yamlNode {
	if depth > maxYAMLDepth || r.i >= len(r.lines) {
		r.ok = false
		return nil
	}
	if isYAMLSeqItem(r.lines[r.i].text) {
		return r.sequence(indent, depth)
	}
	return r.mapping(indent, depth)
}

func isYAMLSeqItem(text []byte) bool {
	return text[0] == '-' && (len(text) == 1 || text[1] == ' ')
}

// sequence reads "- item" lines at indent.
func (r *yamlReader) sequence(indent, depth int) *yamlNode {
	seq := r.node('s')
	for r.ok && r.i < len(r.lines) && r.lines[r.i].indent == indent && isYAMLSeqItem(r.lines[r.i].text) {
		line := r.lines[r.i]
		content := bytes.TrimLeft(line.text[1:], " ")
		if len(content) == 0 {
			r.i++
			if r.i >= len(r.lines) || r.lines[r.i].indent <= indent {
				seq.items = append(seq.items, r.node('v'))
				continue
			}
			seq.items = append(seq.items, r.block(r.lines[r.i].indent, depth+1))
			continue
		}
		// The item's content starts a node at its own column.
		column := indent + (len(line.text) - len(content))
		r.lines[r.i] = yamlLine{indent: column, text: content}
		if isYAMLSeqItem(content) {
			seq.items = append(seq.items, r.sequence(column, depth+1))
			continue
		}
		if _, _, isPair := splitYAMLPair(content); isPair {
			seq.items = append(seq.items, r.mapping(column, depth+1))
			continue
		}
		r.i++
		seq.items = append(seq.items, r.inline(content, depth+1))
	}
	return seq
}

// mapping reads "key: value" lines at indent.
func (r *yamlReader) mapping(indent, depth int) *yamlNode {
	m := r.node('m')
	for r.ok && r.i < len(r.lines) && r.lines[r.i].indent == indent {
		line := r.lines[r.i]
		if isYAMLSeqItem(line.text) {
			break
		}
		key, rest, isPair := splitYAMLPair(line.text)
		if !isPair {
			r.ok = false
			return m
		}
		r.i++
		var value *yamlNode
		switch {
		case len(rest) > 0 && (rest[0] == '|' || rest[0] == '>'):
			value = r.blockScalar(indent, rest[0] == '|')
		case len(rest) > 0:
			value = r.inline(rest, depth+1)
		case r.i < len(r.lines) && (r.lines[r.i].indent > indent ||
			(r.lines[r.i].indent == indent && isYAMLSeqItem(r.lines[r.i].text))):
			value = r.block(r.lines[r.i].indent, depth+1)
		default:
			value = r.node('v') // an empty value
		}
		m.keys = append(m.keys, key)
		m.values = append(m.values, value)
	}
	return m
}

// splitYAMLPair splits "key: value" or "key:" outside quotes; the key is a
// name, decoded when quoted.
func splitYAMLPair(text []byte) (string, []byte, bool) {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if quote == '"' && c == '\\' {
				i++
			}
		case (c == '"' || c == '\'') && i == 0:
			quote = c
		case c == '{' || c == '[':
			if i == 0 {
				return "", nil, false
			}
		case c == ':' && (i+1 == len(text) || text[i+1] == ' '):
			keyRaw := bytes.TrimSpace(text[:i])
			if len(keyRaw) == 0 {
				return "", nil, false
			}
			key, ok := yamlScalar(keyRaw)
			if !ok {
				return "", nil, false
			}
			defer clear(key)
			return string(key), bytes.TrimSpace(text[i+1:]), true
		}
	}
	return "", nil, false
}

// blockScalar reads a literal (|) or folded (>) scalar's lines.
func (r *yamlReader) blockScalar(indent int, literal bool) *yamlNode {
	v := r.node('v')
	first := true
	for r.i < len(r.lines) && r.lines[r.i].indent > indent {
		if !first {
			if literal {
				v.scalar = append(v.scalar, '\n')
			} else {
				v.scalar = append(v.scalar, ' ')
			}
		}
		v.scalar = append(v.scalar, r.lines[r.i].text...)
		first = false
		r.i++
	}
	return v
}

// inline reads a value on one line: a flow sequence or mapping, or a scalar.
func (r *yamlReader) inline(text []byte, depth int) *yamlNode {
	if depth > maxYAMLDepth {
		r.ok = false
		return nil
	}
	if text[0] == '[' || text[0] == '{' {
		n, rest, ok := r.flow(text, depth)
		if !ok || len(bytes.TrimSpace(rest)) != 0 {
			n.wipe()
			r.ok = false
			return nil
		}
		return n
	}
	if yamlNodeProperty(text) {
		r.ok = false // an anchor, alias or tag
		return nil
	}
	value, ok := yamlScalar(text)
	if !ok {
		r.ok = false
		return nil
	}
	v := r.node('v')
	v.scalar = value
	return v
}

// yamlNodeProperty reports a value that opens with an anchor (&), an alias
// (*) or a tag (!), which this reader does not follow.
func yamlNodeProperty(text []byte) bool {
	return len(text) > 0 && (text[0] == '&' || text[0] == '*' || text[0] == '!')
}

// flow reads a flow sequence or mapping and returns what follows it.
func (r *yamlReader) flow(text []byte, depth int) (*yamlNode, []byte, bool) {
	if depth > maxYAMLDepth || !r.ok {
		return nil, nil, false
	}
	open := text[0]
	closing := byte(']')
	n := r.node('s')
	if open == '{' {
		closing, n.kind = '}', 'm'
	}
	rest := bytes.TrimLeft(text[1:], " ")
	for {
		if len(rest) == 0 {
			return n, nil, false
		}
		if rest[0] == closing {
			return n, rest[1:], true
		}
		var key string
		if open == '{' {
			end := flowTokenEnd(rest, ':')
			if end >= len(rest) || rest[end] != ':' {
				return n, nil, false
			}
			k, ok := yamlScalar(bytes.TrimSpace(rest[:end]))
			if !ok {
				return n, nil, false
			}
			key = string(k)
			clear(k)
			rest = bytes.TrimLeft(rest[end+1:], " ")
		}
		var item *yamlNode
		if len(rest) > 0 && (rest[0] == '[' || rest[0] == '{') {
			var ok bool
			item, rest, ok = r.flow(rest, depth+1)
			if !ok {
				return n, nil, false
			}
		} else {
			end := flowTokenEnd(rest, 0)
			token := bytes.TrimSpace(rest[:end])
			if len(token) == 0 || yamlNodeProperty(token) {
				// No entry here (a stray closing bracket, an empty entry):
				// not a flow collection this reader takes.
				return n, nil, false
			}
			value, ok := yamlScalar(token)
			if !ok {
				return n, nil, false
			}
			item = r.node('v')
			item.scalar = value
			rest = rest[end:]
		}
		if open == '{' {
			n.keys, n.values = append(n.keys, key), append(n.values, item)
		} else {
			n.items = append(n.items, item)
		}
		rest = bytes.TrimLeft(rest, " ")
		if len(rest) > 0 && rest[0] == ',' {
			rest = bytes.TrimLeft(rest[1:], " ")
		}
	}
}

// flowTokenEnd is where a flow token ends: a comma, a closing bracket, or
// stop, outside quotes.
func flowTokenEnd(s []byte, stop byte) int {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if quote == '"' && c == '\\' {
				i++
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ',' || c == ']' || c == '}' || (stop != 0 && c == stop):
			return i
		}
	}
	return len(s)
}

// yamlScalar decodes a plain, single- or double-quoted scalar into a new
// buffer.
func yamlScalar(s []byte) ([]byte, bool) {
	if len(s) == 0 {
		return []byte{}, true
	}
	switch s[0] {
	case '\'':
		if len(s) < 2 || s[len(s)-1] != '\'' {
			return nil, false
		}
		inner := s[1 : len(s)-1]
		out := make([]byte, 0, len(inner))
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\'' {
				if i+1 < len(inner) && inner[i+1] == '\'' {
					i++
				} else {
					clear(out)
					return nil, false
				}
			}
			out = append(out, inner[i])
		}
		return out, true
	case '"':
		if len(s) < 2 || s[len(s)-1] != '"' {
			return nil, false
		}
		inner := s[1 : len(s)-1]
		out := make([]byte, 0, len(inner))
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if c == '"' {
				clear(out)
				return nil, false
			}
			if c != '\\' {
				out = append(out, c)
				continue
			}
			i++
			if i >= len(inner) {
				clear(out)
				return nil, false
			}
			switch e := inner[i]; e {
			case 'n':
				out = append(out, '\n')
			case 't':
				out = append(out, '\t')
			case 'r':
				out = append(out, '\r')
			case '0':
				out = append(out, 0)
			case '"', '\\', '/', ' ':
				out = append(out, e)
			case 'x', 'u', 'U':
				n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
				cp, ok := hexRune(inner, i+1, n)
				if !ok {
					clear(out)
					return nil, false
				}
				i += n
				out = utf8.AppendRune(out, cp)
			default:
				clear(out)
				return nil, false
			}
		}
		return out, true
	default:
		return append([]byte(nil), s...), true
	}
}
