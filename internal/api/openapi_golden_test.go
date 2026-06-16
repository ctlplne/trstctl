package api_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

// updateGolden regenerates the checked-in OpenAPI golden when set:
//
//	go test ./internal/api -run TestOpenAPIGolden -update-openapi-golden
//
// Run it deliberately for an intended additive change, review the diff, and commit
// the new golden (SCHEMA-004).
var updateGolden = flag.Bool("update-openapi-golden", false, "regenerate the OpenAPI golden file")

const goldenPath = "testdata/openapi.golden.json"

// canonicalSpec returns the served OpenAPI document re-marshaled through a
// map[string]any so key ordering is canonical (encoding/json sorts map keys), giving
// a stable, diffable representation independent of struct field order.
func canonicalSpec(t *testing.T) ([]byte, map[string]any) {
	t.Helper()
	doc := api.New(nil, nil, nil).Spec()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	canon, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal canonical: %v", err)
	}
	return canon, m
}

// TestOpenAPIGolden is the SCHEMA-004 acceptance: the generated OpenAPI document is
// pinned to a checked-in golden, so any change to the served contract — a removed
// response field, a renamed operationId, a narrowed enum, a newly-required field —
// shows up as a failing diff that a reviewer must consciously accept (and
// regenerate). The pre-fix tree had no golden, so a backward-incompatible change
// shipped silently.
func TestOpenAPIGolden(t *testing.T) {
	canon, _ := canonicalSpec(t)

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, canon, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", goldenPath)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (regenerate with -update-openapi-golden): %v", err)
	}
	if string(want) != string(canon) {
		t.Errorf("OpenAPI spec drifted from %s.\nIf this change is intended and additive, regenerate with:\n"+
			"  go test ./internal/api -run TestOpenAPIGolden -update-openapi-golden\nand review the diff before committing.", goldenPath)
	}
}

// TestOpenAPINoBreakingChange enforces the additive-only / deprecation policy
// (SCHEMA-004): comparing the live spec to the golden, it fails on the specific
// backward-incompatible changes that the structural tests miss — a removed path or
// operation, a removed required field, or a narrowed enum. These are exactly the
// edits that break an external integration or the SPA. (Additive changes — new
// paths, new optional fields, widened enums — pass; regenerate the golden for them.)
func TestOpenAPINoBreakingChange(t *testing.T) {
	wantRaw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var oldDoc, newDoc map[string]any
	if err := json.Unmarshal(wantRaw, &oldDoc); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	_, newDoc = canonicalSpec(t)

	oldPaths := asMap(oldDoc["paths"])
	newPaths := asMap(newDoc["paths"])
	for p, oldPI := range oldPaths {
		newPI, ok := newPaths[p]
		if !ok {
			t.Errorf("breaking: path %q was removed", p)
			continue
		}
		oldOps := asMap(oldPI)
		newOps := asMap(newPI)
		for m := range oldOps {
			if !isHTTPMethod(m) {
				continue
			}
			if _, ok := asMap(newPI)[m]; !ok {
				_ = newOps
				t.Errorf("breaking: operation %s %s was removed", strings.ToUpper(m), p)
			}
		}
	}

	// Required fields must not be added or removed in a breaking way, and enums must
	// not be narrowed, across the component schemas.
	oldSchemas := asMap(asMap(oldDoc["components"])["schemas"])
	newSchemas := asMap(asMap(newDoc["components"])["schemas"])
	for name, oldS := range oldSchemas {
		newS, ok := newSchemas[name]
		if !ok {
			t.Errorf("breaking: schema %q was removed", name)
			continue
		}
		// A field that was required must still exist as a property (removing a
		// previously-guaranteed response field breaks consumers).
		for _, req := range asStrings(asMap(oldS)["required"]) {
			props := asMap(asMap(newS)["properties"])
			if _, ok := props[req]; !ok {
				t.Errorf("breaking: schema %q dropped previously-required property %q", name, req)
			}
		}
		// An optional field must not become required (would reject older clients).
		oldReq := strSet(asStrings(asMap(oldS)["required"]))
		for _, req := range asStrings(asMap(newS)["required"]) {
			if !oldReq[req] {
				t.Errorf("breaking: schema %q made property %q newly required", name, req)
			}
		}
		// Enums must not be narrowed (a value the server used to accept/return removed).
		checkEnumsNotNarrowed(t, name, asMap(oldS), asMap(newS))
	}
}

// checkEnumsNotNarrowed compares enum value sets on a schema's properties (one level
// deep — sufficient for this flat spec) and flags any removed value.
func checkEnumsNotNarrowed(t *testing.T, schema string, oldS, newS map[string]any) {
	oldProps := asMap(oldS["properties"])
	newProps := asMap(newS["properties"])
	for field, oldP := range oldProps {
		oldEnum := asStrings(asMap(oldP)["enum"])
		if len(oldEnum) == 0 {
			continue
		}
		newEnum := strSet(asStrings(asMap(newProps[field])["enum"]))
		for _, v := range oldEnum {
			if !newEnum[v] {
				t.Errorf("breaking: schema %q field %q removed enum value %q (narrowed enum)", schema, field, v)
			}
		}
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func strSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func isHTTPMethod(m string) bool {
	switch m {
	case "get", "post", "put", "delete", "patch":
		return true
	default:
		return false
	}
}

var _ = reflect.DeepEqual // reserved for future structural comparisons
