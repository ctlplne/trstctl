// SPDX-License-Identifier: BUSL-1.1
package accessrules

import (
	"bytes"
	"slices"
	"unicode/utf8"
)

const MaxSSHCommandBytes = 64 << 10

// SSHOperations recognizes direct command positions, not shell containment.
// Only configured public program classes leave this lexer. Arguments, expansions
// and quoted nested programs never become policy input or source evidence.
func SSHOperations(raw []byte) ([]string, error) {
	if len(raw) > MaxSSHCommandBytes || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, ErrUninspectable
	}
	out := []string{}
	command, redirect := true, false
	for i := 0; i < len(raw); {
		c := raw[i]
		if c == ' ' || c == '\t' || c == '\r' {
			i++
			continue
		}
		if c == '\n' || c == ';' || c == '|' || c == '&' || c == '(' || c == '{' {
			command = true
			redirect = false
			i++
			continue
		}
		if c == ')' || c == '}' {
			command = false
			i++
			continue
		}
		if c == '#' {
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
			continue
		}
		if c >= '0' && c <= '9' && command {
			n := i
			for n < len(raw) && raw[n] >= '0' && raw[n] <= '9' {
				n++
			}
			if n < len(raw) && (raw[n] == '<' || raw[n] == '>') {
				i = n
				c = raw[i]
			}
		}
		if c == '<' || c == '>' {
			if c == '<' && i+1 < len(raw) && raw[i+1] == '<' {
				return nil, ErrUninspectable
			}
			redirect = true
			i++
			if i < len(raw) && raw[i] == c {
				i++
			}
			continue
		}
		capture := command && !redirect
		word, next, dynamic, quoted, err := sshCommandWord(raw, i, capture)
		if err != nil {
			return nil, err
		}
		i = next
		if redirect {
			redirect = false
			clear(word)
			continue
		}
		if !command {
			clear(word)
			continue
		}
		if sshAssignment(word) {
			clear(word)
			continue
		}
		if !quoted && (bytes.Equal(word, []byte("if")) || bytes.Equal(word, []byte("then")) || bytes.Equal(word, []byte("else")) || bytes.Equal(word, []byte("elif")) || bytes.Equal(word, []byte("while")) || bytes.Equal(word, []byte("until")) || bytes.Equal(word, []byte("do")) || bytes.Equal(word, []byte("!"))) {
			clear(word)
			continue
		}
		command = false
		if !dynamic {
			base := word
			if n := bytes.LastIndexByte(base, '/'); n >= 0 {
				base = base[n+1:]
			}
			for _, name := range sshOperationNames {
				if bytes.Equal(base, []byte(name)) && !slices.Contains(out, name) {
					out = append(out, name)
					break
				}
			}
		}
		clear(word)
	}
	slices.Sort(out)
	return out, nil
}

func sshCommandWord(raw []byte, start int, capture bool) ([]byte, int, bool, bool, error) {
	word := []byte{}
	dynamic, quoted := false, false
	overflow := false
	add := func(c byte) {
		if capture && len(word) < 4096 {
			word = append(word, c)
		} else if capture {
			overflow = true
		}
	}
	i := start
	for i < len(raw) {
		c := raw[i]
		if bytes.IndexByte([]byte(" \t\r\n;|&(){}<>"), c) >= 0 {
			break
		}
		if c == '\\' {
			if i+1 >= len(raw) {
				clear(word)
				return nil, 0, false, false, ErrUninspectable
			}
			i++
			if raw[i] != '\n' {
				add(raw[i])
			}
			i++
			continue
		}
		if c == '\'' || c == '"' {
			quoted = true
			quote := c
			i++
			closed := false
			for i < len(raw) {
				c = raw[i]
				if c == quote {
					i++
					closed = true
					break
				}
				if quote == '"' && (c == '$' || c == '`') {
					dynamic = true
				}
				if quote == '"' && c == '\\' {
					if i+1 >= len(raw) {
						break
					}
					i++
					c = raw[i]
				}
				add(c)
				i++
			}
			if !closed {
				clear(word)
				return nil, 0, false, false, ErrUninspectable
			}
			continue
		}
		if c == '$' || c == '`' {
			dynamic = true
		}
		add(c)
		i++
	}
	if i == start {
		clear(word)
		return nil, 0, false, false, ErrUninspectable
	}
	if overflow {
		clear(word)
		return nil, 0, false, false, ErrUninspectable
	}
	return word, i, dynamic, quoted, nil
}
func sshAssignment(word []byte) bool {
	n := bytes.IndexByte(word, '=')
	if n < 1 {
		return false
	}
	for i, c := range word[:n] {
		valid := c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9'
		if !valid {
			return false
		}
	}
	return true
}
