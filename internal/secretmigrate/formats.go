// SPDX-License-Identifier: BUSL-1.1

package secretmigrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

// dotenv: KEY=VALUE lines, optionally "export KEY=VALUE". A double-quoted
// value may span lines and takes \n, \t, \r, \" and \\ escapes; a single-quoted
// one is literal; an unquoted one ends at " #". Comment lines directly above a
// key are its metadata: plain text is the description, "@tags: a, b", "@owner:
// x" and "@exportable: false" (the export could not carry this value) set the
// rest. A blank line ends a comment block.
func parseDotenv(src []byte) ([]entry, error) {
	out, err := readDotenv(src)
	if err != nil {
		wipeEntries(out)
		return nil, err
	}
	return out, nil
}

func wipeEntries(entries []entry) {
	for i := range entries {
		secret.Wipe(entries[i].value)
	}
}

func readDotenv(src []byte) ([]entry, error) {
	var out []entry
	meta := entry{exportable: true}
	line := 1
	for i := 0; i < len(src); {
		end := lineEnd(src, i)
		text := bytes.TrimSpace(bytes.TrimSuffix(src[i:end], []byte("\r")))
		switch {
		case len(text) == 0:
			meta = entry{exportable: true}
			i, line = end+1, line+1
			continue
		case text[0] == '#':
			applyComment(&meta, strings.TrimSpace(string(text[1:])))
			i, line = end+1, line+1
			continue
		}
		text = bytes.TrimPrefix(text, []byte("export "))
		eq := bytes.IndexByte(text, '=')
		if eq <= 0 {
			return out, fmt.Errorf("line %d is not KEY=VALUE", line)
		}
		e := meta
		e.key, e.line = string(bytes.TrimSpace(text[:eq])), line
		rest := bytes.TrimLeft(text[eq+1:], " \t")
		switch {
		case len(rest) > 0 && rest[0] == '"':
			// The value may span lines: read on from the opening quote, the
			// first quote after the line's '='.
			eqAt := i + bytes.IndexByte(src[i:end], '=')
			open := eqAt + 1 + bytes.IndexByte(src[eqAt+1:end], '"')
			value, consumed, err := doubleQuoted(src[open+1:])
			if err != nil {
				return out, fmt.Errorf("line %d: %w", line, err)
			}
			closeAt := open + 1 + consumed
			line += bytes.Count(src[open:closeAt], []byte("\n"))
			end = lineEnd(src, closeAt)
			if trailing := bytes.TrimSpace(src[closeAt:end]); len(trailing) > 0 && trailing[0] != '#' {
				secret.Wipe(value)
				return out, fmt.Errorf("line %d: text after a closing quote", line)
			}
			e.value = value
		case len(rest) > 0 && rest[0] == '\'':
			closing := bytes.IndexByte(rest[1:], '\'')
			if closing < 0 {
				return out, fmt.Errorf("line %d: unterminated single quote", line)
			}
			e.value = append([]byte(nil), rest[1:1+closing]...)
		default:
			if hash := bytes.Index(rest, []byte(" #")); hash >= 0 {
				rest = rest[:hash]
			}
			e.value = append([]byte(nil), bytes.TrimSpace(rest)...)
		}
		out = append(out, e)
		meta = entry{exportable: true}
		i, line = end+1, line+1
	}
	return out, nil
}

// lineEnd is the index of the newline ending the line that starts at i, or
// len(src).
func lineEnd(src []byte, i int) int {
	if nl := bytes.IndexByte(src[i:], '\n'); nl >= 0 {
		return i + nl
	}
	return len(src)
}

// doubleQuoted reads a double-quoted value up to its closing quote and
// returns it with the number of input bytes consumed (including the quote).
func doubleQuoted(in []byte) ([]byte, int, error) {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch c {
		case '"':
			return out, i + 1, nil
		case '\\':
			if i+1 >= len(in) {
				secret.Wipe(out)
				return nil, 0, errors.New("unterminated escape")
			}
			i++
			switch in[i] {
			case 'n':
				out = append(out, '\n')
			case 't':
				out = append(out, '\t')
			case 'r':
				out = append(out, '\r')
			case '"', '\\', '$':
				out = append(out, in[i])
			default:
				out = append(out, '\\', in[i])
			}
		case '\r':
			// CRLF inside a multiline value reads as LF.
		default:
			out = append(out, c)
		}
	}
	secret.Wipe(out)
	return nil, 0, errors.New("unterminated double quote")
}

// applyComment folds one comment line into the next key's metadata.
func applyComment(meta *entry, text string) {
	lower := strings.ToLower(text)
	switch {
	case strings.HasPrefix(lower, "@tags:"):
		for _, t := range strings.Split(text[len("@tags:"):], ",") {
			if t = strings.TrimSpace(t); t != "" {
				meta.tags = append(meta.tags, t)
			}
		}
	case strings.HasPrefix(lower, "@owner:"):
		meta.owner = strings.TrimSpace(text[len("@owner:"):])
	case strings.HasPrefix(lower, "@exportable:"):
		meta.exportable = strings.TrimSpace(lower[len("@exportable:"):]) != "false"
	case text != "":
		if meta.description != "" {
			meta.description += " "
		}
		meta.description += text
	}
}

// node is the shape JSON and YAML share: a map of folders and secrets, a
// record ({"$value": …} with "$description", "$tags", "$owner", "$exportable"),
// a list of records at the top level, or a scalar value.
type node struct {
	kind    int // nodeMap, nodeList, nodeScalar, nodeNull
	keys    []string
	values  []*node
	scalar  []byte
	line    int
	invalid string
}

const (
	nodeMap = iota
	nodeList
	nodeScalar
	nodeNull
)

func (n *node) get(key string) (*node, bool) {
	for i, k := range n.keys {
		if k == key {
			return n.values[i], true
		}
	}
	return nil, false
}

func (n *node) wipe() {
	if n == nil {
		return
	}
	secret.Wipe(n.scalar)
	for _, v := range n.values {
		v.wipe()
	}
}

// entries walks a parsed document into entries.
func entries(root *node) ([]entry, error) {
	var out []entry
	switch root.kind {
	case nodeMap:
		walkMap(root, nil, &out)
	case nodeList:
		for i, rec := range root.values {
			e := recordEntry(rec, nil)
			if e.key == "" && e.unsupported == "" {
				e.unsupported = fmt.Sprintf("record %d has no key", i+1)
			}
			out = append(out, e)
		}
	default:
		root.wipe()
		return nil, errors.New("the document is a map of folders and secrets, or a list of records")
	}
	return out, nil
}

func walkMap(n *node, folder []string, out *[]entry) {
	for i, key := range n.keys {
		v := n.values[i]
		switch {
		case v.kind == nodeMap && isRecord(v):
			e := recordEntry(v, folder)
			e.key = key
			*out = append(*out, e)
		case v.kind == nodeMap:
			walkMap(v, append(append([]string(nil), folder...), key), out)
		case v.kind == nodeList:
			v.wipe()
			*out = append(*out, entry{key: key, folder: folder, line: v.line, unsupported: "a list is not a secret value"})
		default:
			*out = append(*out, entry{key: key, folder: folder, value: v.scalar, null: v.kind == nodeNull,
				exportable: true, line: v.line, unsupported: v.invalid})
			v.scalar = nil
		}
	}
}

// isRecord reports whether a map is one secret with metadata.
func isRecord(n *node) bool {
	for _, k := range n.keys {
		if k == "$value" || k == "$exportable" {
			return true
		}
	}
	return false
}

// recordEntry reads one record: "$value" and "$"-prefixed metadata inside a
// map, or key/value/folder/… fields in a top-level list.
func recordEntry(n *node, folder []string) entry {
	e := entry{folder: folder, exportable: true, line: n.line}
	if n.kind != nodeMap {
		n.wipe()
		e.unsupported = "a record is a map"
		return e
	}
	prefix := "$"
	if _, ok := n.get("$value"); !ok {
		if _, ok := n.get("$exportable"); !ok {
			prefix = "" // a top-level list record
		}
	}
	text := func(name string) string {
		if v, ok := n.get(prefix + name); ok && v.kind == nodeScalar {
			return string(v.scalar) // metadata, not a value
		}
		return ""
	}
	if prefix == "" {
		e.key = text("key")
		if f := text("folder"); f != "" {
			e.folder = append(append([]string(nil), folder...), strings.Split(strings.Trim(f, "/"), "/")...)
		}
	}
	e.description, e.owner = text("description"), text("owner")
	if v, ok := n.get(prefix + "tags"); ok && v.kind == nodeList {
		for _, t := range v.values {
			if t.kind == nodeScalar {
				e.tags = append(e.tags, string(t.scalar))
			}
		}
	}
	if strings.EqualFold(text("exportable"), "false") {
		e.exportable = false
	}
	if v, ok := n.get(prefix + "value"); ok {
		switch v.kind {
		case nodeScalar:
			e.value, v.scalar = v.scalar, nil
			e.unsupported = v.invalid
		case nodeNull:
			e.null = true
		default:
			e.unsupported = "a value is text, not a map or list"
		}
	} else {
		e.null = true
	}
	n.wipe()
	return e
}

// parseJSON reads a JSON document with a token decoder, so string values go
// straight from the input to []byte without a Go string in between.
func parseJSON(src []byte) ([]entry, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	root, err := jsonNode(dec)
	if err != nil {
		root.wipe()
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		root.wipe()
		return nil, errors.New("trailing data after the document")
	}
	return entries(root)
}

// jsonNode reads one value. Strings are re-read from the input bytes at the
// decoder's offset so the value never becomes a Go string.
func jsonNode(dec *json.Decoder) (*node, error) {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return jsonRaw(raw)
}

func jsonRaw(raw json.RawMessage) (*node, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, errors.New("empty JSON value")
	}
	switch raw[0] {
	case '{':
		n := &node{kind: nodeMap}
		dec := json.NewDecoder(bytes.NewReader(raw))
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				n.wipe()
				return nil, err
			}
			key, _ := tok.(string)
			var child json.RawMessage
			if err := dec.Decode(&child); err != nil {
				n.wipe()
				return nil, err
			}
			v, err := jsonRaw(child)
			secret.Wipe(child)
			if err != nil {
				n.wipe()
				return nil, err
			}
			n.keys, n.values = append(n.keys, key), append(n.values, v)
		}
		return n, nil
	case '[':
		n := &node{kind: nodeList}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		for _, item := range items {
			v, err := jsonRaw(item)
			secret.Wipe(item)
			if err != nil {
				n.wipe()
				return nil, err
			}
			n.values = append(n.values, v)
		}
		return n, nil
	case '"':
		value, err := secretjson.UnquoteBytes(raw)
		if err != nil {
			return nil, err
		}
		return &node{kind: nodeScalar, scalar: value}, nil
	case 'n':
		return &node{kind: nodeNull}, nil
	default:
		// A number or boolean is stored as its text.
		return &node{kind: nodeScalar, scalar: append([]byte(nil), raw...)}, nil
	}
}

// parseYAML reads a YAML document. Block scalars carry multiline values. A
// YAML library holds scalars as Go strings while it parses; each is copied to
// []byte as soon as it is reached.
func parseYAML(src []byte) ([]entry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var doc, extra yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if err := dec.Decode(&extra); err != io.EOF || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("a source is one YAML document")
	}
	root, err := yamlNode(doc.Content[0], 0)
	if err != nil {
		root.wipe()
		return nil, err
	}
	return entries(root)
}

func yamlNode(y *yaml.Node, depth int) (*node, error) {
	if depth > 32 {
		return nil, errors.New("the document nests deeper than 32 levels")
	}
	switch y.Kind {
	case yaml.MappingNode:
		n := &node{kind: nodeMap, line: y.Line}
		for i := 0; i+1 < len(y.Content); i += 2 {
			v, err := yamlNode(y.Content[i+1], depth+1)
			if err != nil {
				n.wipe()
				return nil, err
			}
			n.keys, n.values = append(n.keys, y.Content[i].Value), append(n.values, v)
		}
		return n, nil
	case yaml.SequenceNode:
		n := &node{kind: nodeList, line: y.Line}
		for _, c := range y.Content {
			v, err := yamlNode(c, depth+1)
			if err != nil {
				n.wipe()
				return nil, err
			}
			n.values = append(n.values, v)
		}
		return n, nil
	case yaml.ScalarNode:
		if y.Tag == "!!null" {
			return &node{kind: nodeNull, line: y.Line}, nil
		}
		n := &node{kind: nodeScalar, line: y.Line, scalar: []byte(y.Value)}
		if y.Tag == "!!binary" {
			n.invalid = "a binary value is not supported; export it as text"
		}
		return n, nil
	case yaml.AliasNode:
		return nil, errors.New("YAML aliases are not supported; export each value in place")
	default:
		return nil, errors.New("unsupported YAML node")
	}
}
