// SPDX-License-Identifier: BUSL-1.1

// Package synctarget describes the hosted secret-sync destinations (A241): for
// each target type, how a destination is bound (the binding grammar), its
// default API endpoint, the credential it takes and the keys it can hold.
// Config validation and the secretsync engine share it, so a binding that
// validates is one the engine can address.
package synctarget

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// KeyStyle is how a destination names what it holds.
type KeyStyle int

const (
	// FlatKeys are variable names: a scoped sync's destination prefix is a
	// name prefix ("APP_"), never a folder.
	FlatKeys KeyStyle = iota
	// PathKeys are slash-separated paths: a destination prefix is a folder.
	PathKeys
)

// Credential is what a target authenticates with, beside its token_ref.
type Credential int

const (
	// TokenOnly targets take token_ref alone.
	TokenOnly Credential = iota
	// UserAndToken targets also take username: a Basic-auth user, an API key
	// ID or a client name, depending on the vendor.
	UserAndToken
)

// Target describes one hosted secret-sync target type.
type Target struct {
	Type     string
	Name     string
	Platform string
	// Grammar is the binding's syntax, for errors and docs.
	Grammar string
	// Endpoint is the vendor's API base; empty means the target is
	// self-hosted and endpoint is required.
	Endpoint   string
	Credential Credential
	Keys       KeyStyle
	// keyRule and maxKey are the names the destination accepts.
	keyRule    *regexp.Regexp
	keyHelp    string
	maxKey     int
	denyPrefix []string
	parse      func(fields []string) (Binding, error)
}

// Binding is a parsed binding: named parts, for example app or project.
type Binding map[string]string

// ValidKey reports whether the destination can hold a key of this name.
func (t Target) ValidKey(key string) error {
	switch {
	case key == "":
		return errors.New("the key is empty")
	case t.maxKey > 0 && len(key) > t.maxKey:
		return fmt.Errorf("%s keys are at most %d characters", t.Name, t.maxKey)
	case t.keyRule != nil && !t.keyRule.MatchString(key):
		return fmt.Errorf("%s keys are %s", t.Name, t.keyHelp)
	}
	for _, prefix := range t.denyPrefix {
		if strings.HasPrefix(key, prefix) {
			return fmt.Errorf("%s reserves keys starting %s", t.Name, prefix)
		}
	}
	return nil
}

var targets = register(all()...)

func register(list ...Target) map[string]Target {
	out := make(map[string]Target, len(list))
	for _, t := range list {
		if _, dup := out[t.Type]; dup {
			panic("synctarget: duplicate type " + t.Type)
		}
		out[t.Type] = t
	}
	return out
}

// Lookup returns the hosted target type, if typ is one.
func Lookup(typ string) (Target, bool) {
	t, ok := targets[typ]
	return t, ok
}

// Types lists every hosted target type, sorted.
func Types() []string {
	out := make([]string, 0, len(targets))
	for typ := range targets {
		out = append(out, typ)
	}
	sort.Strings(out)
	return out
}

// ParseBinding parses a target's binding: whitespace-separated fields in the
// type's grammar.
func ParseBinding(typ, raw string) (Binding, error) {
	t, ok := targets[typ]
	if !ok {
		return nil, fmt.Errorf("%q is not a hosted secret-sync target", typ)
	}
	fields := strings.Fields(raw)
	b, err := t.parse(fields)
	if err != nil {
		return nil, fmt.Errorf("binding for %s is %q: %w", typ, t.Grammar, err)
	}
	return b, nil
}

// Grammar helpers. Each vendor's parse uses them so errors read alike.

var (
	envName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	envNameHelp = "letters, digits and underscores, not starting with a digit"
	uuidRule    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numeric     = regexp.MustCompile(`^[0-9]{1,19}$`)
)

// one takes exactly one field matching rule, named name.
func one(name string, rule *regexp.Regexp, what string) func([]string) (Binding, error) {
	return func(f []string) (Binding, error) {
		if len(f) != 1 {
			return nil, errors.New("one field")
		}
		if !rule.MatchString(f[0]) {
			return nil, fmt.Errorf("%s must be %s", name, what)
		}
		return Binding{name: f[0]}, nil
	}
}

// keyword parses "<word> <value>" pairs in any order; required names must
// appear, optional ones may. Each value must match its rule.
type pair struct {
	word     string
	rule     *regexp.Regexp
	what     string
	optional bool
}

func pairs(spec ...pair) func([]string) (Binding, error) {
	return func(f []string) (Binding, error) {
		if len(f)%2 != 0 {
			return nil, errors.New("keyword and value pairs")
		}
		b := Binding{}
		for i := 0; i < len(f); i += 2 {
			var p *pair
			for j := range spec {
				if spec[j].word == f[i] {
					p = &spec[j]
				}
			}
			if p == nil {
				return nil, fmt.Errorf("unknown keyword %q", f[i])
			}
			if _, dup := b[p.word]; dup {
				return nil, fmt.Errorf("%s given twice", p.word)
			}
			if !p.rule.MatchString(f[i+1]) {
				return nil, fmt.Errorf("%s must be %s", p.word, p.what)
			}
			b[p.word] = f[i+1]
		}
		for _, p := range spec {
			if _, ok := b[p.word]; !ok && !p.optional {
				return nil, fmt.Errorf("%s is required", p.word)
			}
		}
		return b, nil
	}
}
