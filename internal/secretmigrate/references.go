// SPDX-License-Identifier: BUSL-1.1

package secretmigrate

import (
	"bytes"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// nativeReferenceStart is the native store's reference syntax:
// ${secret.<name>}.
const nativeReferenceStart = "secret."

// translateReferences rewrites each exportable value's references into the
// native syntax and records their targets. ${NAME} names a key in the same
// folder, ${folder/NAME} one in the same environment and
// ${environment:folder/NAME} one in another environment of the project; a
// native ${secret.<name>} is kept. Anything else between ${ and } (a shell
// default such as ${HOME:-/root}) is not a reference and stays as written.
func translateReferences(p *Parsed) {
	for _, o := range p.Objects {
		if !o.Exportable || !bytes.Contains(o.Value, []byte("${")) {
			continue
		}
		out := make([]byte, 0, len(o.Value)+32)
		rest := o.Value
		for {
			idx := bytes.Index(rest, []byte("${"))
			if idx < 0 {
				out = append(out, rest...)
				break
			}
			body := rest[idx+2:]
			end := bytes.IndexByte(body, '}')
			if end < 0 {
				out = append(out, rest...)
				break
			}
			target, ok := referenceTarget(p.Project, o, string(body[:end])) // a reference's name, not a value
			if !ok {
				out = append(out, rest[:idx+2+end+1]...)
				rest = body[end+1:]
				continue
			}
			out = append(out, rest[:idx]...)
			out = append(out, "${"+nativeReferenceStart+target+"}"...)
			if !contains(o.References, target) {
				o.References = append(o.References, target)
			}
			rest = body[end+1:]
		}
		secret.Wipe(o.Value)
		o.Value = out
	}
}

// referenceTarget reads one reference body relative to the object holding it.
func referenceTarget(project string, o *Object, body string) (string, bool) {
	if strings.HasPrefix(body, nativeReferenceStart) {
		name := strings.TrimPrefix(body, nativeReferenceStart)
		return name, name != "" && len(name) <= maxNameBytes && !strings.ContainsAny(name, " \t\r\n")
	}
	env, path := o.Environment, body
	if i := strings.IndexByte(body, ':'); i >= 0 {
		env, path = body[:i], body[i+1:]
		if !slug.MatchString(env) {
			return "", false
		}
	}
	parts := strings.Split(path, "/")
	key := parts[len(parts)-1]
	if !keyPattern.MatchString(key) {
		return "", false
	}
	folder := o.Folder
	if len(parts) > 1 || env != o.Environment {
		folder = strings.Join(parts[:len(parts)-1], "/")
		if _, ok := cleanFolder(folder); !ok {
			return "", false
		}
	}
	return NativeName(project, env, folder, key), true
}

// referenceProblems finds each object whose references do not resolve: a
// target neither in the export nor already in the store (exists), or a chain
// that comes back to itself.
func referenceProblems(p *Parsed, exists func(string) bool) map[string]string {
	byName := map[string]*Object{}
	for _, o := range p.Objects {
		byName[o.Name] = o
	}
	problems := map[string]string{}
	for _, o := range p.Objects {
		for _, target := range o.References {
			if _, inExport := byName[target]; !inExport && !exists(target) {
				// The name is not echoed: text between ${ and } that names
				// nothing may be part of the value itself.
				problems[o.Name] = "a reference in its value names a secret that is neither in the export nor in the store"
				break
			}
		}
	}
	// A cycle among exported objects: depth-first, colouring each name.
	const (
		white = iota
		grey
		black
	)
	colour := map[string]int{}
	var visit func(name string, path []string) []string
	visit = func(name string, path []string) []string {
		colour[name] = grey
		for _, target := range byName[name].References {
			next, ok := byName[target]
			if !ok {
				continue
			}
			switch colour[next.Name] {
			case grey:
				return append(path, name, target)
			case white:
				if cycle := visit(target, append(path, name)); cycle != nil {
					return cycle
				}
			}
		}
		colour[name] = black
		return nil
	}
	for _, o := range p.Objects {
		if colour[o.Name] != white {
			continue
		}
		if cycle := visit(o.Name, nil); cycle != nil {
			for _, name := range cycle {
				if _, already := problems[name]; !already {
					problems[name] = "its references form a cycle: " + strings.Join(cycle, " → ")
				}
			}
		}
	}
	return problems
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
