// Package privacy holds the product's subject-level privacy primitives. It keeps
// personal identifiers out of control events by converting a raw subject string
// into a tenant-bound reference through the crypto boundary.
package privacy

import (
	"encoding/json"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacyref"
)

// SubjectRef is the stable, tenant-bound identifier used in privacy events and
// erasure tables. It is deterministic so projections can rebuild, but it is not
// the raw email/OIDC subject that a data-subject erasure is meant to remove.
func SubjectRef(tenantID, subject string) string {
	return privacyref.SubjectRef(tenantID, subject)
}

// Placeholder is the non-PII string written back to read models after erasure.
func Placeholder(ref string) string {
	return privacyref.Placeholder(ref)
}

// IsPlaceholder reports whether s is an erasure placeholder.
func IsPlaceholder(s string) bool { return privacyref.IsPlaceholder(s) }

// Redactor hides raw subject values whose tenant-bound reference has been erased.
type Redactor struct {
	TenantID string
	Refs     map[string]struct{}
}

// Empty reports whether no erasure refs are configured.
func (r Redactor) Empty() bool { return len(r.Refs) == 0 || r.TenantID == "" }

// RedactActor returns a copy of a with the subject replaced when it matches an
// erased reference. Roles are authorization labels, not the direct subject value,
// so they are preserved.
func (r Redactor) RedactActor(a *events.Actor) *events.Actor {
	if a == nil {
		return nil
	}
	out := *a
	if ref, ok := r.match(out.Subject); ok {
		out.Subject = Placeholder(ref)
	}
	return &out
}

// RedactJSON replaces exact-string JSON values whose subject reference has been
// erased. Exact matching is deliberate: it removes the erased subject from event
// payloads without corrupting unrelated operational values that merely contain
// similar text.
func (r Redactor) RedactJSON(data []byte) []byte {
	if r.Empty() || len(data) == 0 {
		return data
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return data
	}
	changed := r.redactValue(&v)
	if !changed {
		return data
	}
	out, err := json.Marshal(v)
	if err != nil {
		return data
	}
	return out
}

func (r Redactor) redactValue(v *any) bool {
	switch x := (*v).(type) {
	case string:
		if ref, ok := r.match(x); ok {
			*v = Placeholder(ref)
			return true
		}
	case []any:
		var changed bool
		for i := range x {
			if r.redactValue(&x[i]) {
				changed = true
			}
		}
		return changed
	case map[string]any:
		var changed bool
		for k, val := range x {
			if r.redactValue(&val) {
				x[k] = val
				changed = true
			}
		}
		return changed
	}
	return false
}

func (r Redactor) match(s string) (string, bool) {
	if r.Empty() || s == "" || IsPlaceholder(s) {
		return "", false
	}
	ref := SubjectRef(r.TenantID, s)
	_, ok := r.Refs[ref]
	return ref, ok
}
