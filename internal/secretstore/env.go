package secretstore

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"trustctl.io/trustctl/internal/auditsink"
)

// EnvResolver is the developer model over the store core (S16.4): environments
// with scoped overrides, folder inheritance (an environment falls back to the
// base store), and secret references (${ref:path}) resolved transitively.
type EnvResolver struct {
	tenantID string
	base     *Store
	envs     map[string]*Store
	audit    auditsink.Auditor
}

// NewEnvResolver constructs a resolver over a base store.
func NewEnvResolver(tenantID string, base *Store, audit auditsink.Auditor) *EnvResolver {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	return &EnvResolver{tenantID: tenantID, base: base, envs: map[string]*Store{}, audit: audit}
}

// AddEnvironment registers a per-environment override store (sharing the KEK).
func (e *EnvResolver) AddEnvironment(name string, override *Store) {
	e.envs[name] = override
}

// Resolve returns the value of path in env, applying environment override →
// base inheritance, then dereferencing ${ref:...} references transitively.
func (e *EnvResolver) Resolve(ctx context.Context, env, path string) ([]byte, error) {
	return e.resolve(ctx, env, path, 0)
}

func (e *EnvResolver) resolve(ctx context.Context, env, path string, depth int) ([]byte, error) {
	if depth > 16 {
		return nil, fmt.Errorf("secrets: reference too deep (possible cycle) at %q", path)
	}
	val, err := e.lookup(ctx, env, path)
	if err != nil {
		return nil, err
	}
	s := string(val)
	if strings.HasPrefix(s, "${ref:") && strings.HasSuffix(s, "}") {
		ref := s[len("${ref:") : len(s)-1]
		return e.resolve(ctx, env, ref, depth+1)
	}
	return val, nil
}

// lookup applies override→base inheritance.
func (e *EnvResolver) lookup(ctx context.Context, env, path string) ([]byte, error) {
	if env != "" {
		if o, ok := e.envs[env]; ok {
			if v, _, err := o.Get(ctx, path); err == nil {
				return v, nil
			}
		}
	}
	v, _, err := e.base.Get(ctx, path)
	return v, err
}

// ParseDotEnv parses KEY=VALUE lines into a map. Blank lines and #-comments are
// ignored; surrounding quotes on values are stripped.
func ParseDotEnv(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = strings.Trim(val, `"'`)
		out[key] = val
	}
	return out
}

// RenderDotEnv renders a map as sorted KEY=VALUE lines.
func RenderDotEnv(m map[string]string) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(m[k])
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}
