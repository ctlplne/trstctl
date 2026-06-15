package api_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// SURFACE-005 / EXC-WIRE-04 — FE↔BE contract-drift guard.
//
// The frontend's resource types are NOT hand-written: web/src/lib/api-types.gen.ts is
// generated from the SERVED OpenAPI contract by web/scripts/gen-api-types.mjs, and
// web/src/lib/api.ts re-exports them. TestOpenAPIGolden pins the golden spec
// (internal/api/testdata/openapi.golden.json) == the live served spec, so the chain is:
//
//     served spec  ==(TestOpenAPIGolden)==  golden.json  --(gen-api-types.mjs)-->  api-types.gen.ts
//
// This test is the Go-side checkpoint on that last hop — the equivalent of
// `npm run gen:api -- --check`, but runnable under `make test` with no Node toolchain:
// for every component schema in the served spec, the generated interface's FIELD SET
// must EXACTLY equal the schema's property set. A backend field add/rename/remove that
// is not regenerated into the FE types fails here (and in CI's `gen:api --check`), so a
// FE/BE mismatch cannot ship silently — which, with no generated client, was previously
// the default failure mode (the audit caught certificate.status drifting this way).

// genInterfaceField captures a field name from one TypeScript interface body line like
// `  status: "active" | "revoked";` or `  id?: string;` — the identifier before the
// optional `?` and the `:`.
var genInterfaceField = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\??\s*:`)

const genTypesPath = "../../web/src/lib/api-types.gen.ts"

// readGenInterfaces parses every `export interface Name { ... }` block out of the
// generated FE types file into name -> sorted field names.
func readGenInterfaces(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(genTypesPath))
	if err != nil {
		t.Fatalf("read generated FE types %s (run `npm run gen:api`): %v", genTypesPath, err)
	}
	return parseInterfaces(string(b))
}

// parseInterfaces extracts interface name -> sorted field names from TS source. It is a
// package-level function (not a closure) so the negative self-test below can feed it a
// deliberately-mutated source and assert the drift is detected.
func parseInterfaces(src string) map[string][]string {
	out := map[string][]string{}
	const kw = "export interface "
	for i := 0; ; {
		start := strings.Index(src[i:], kw)
		if start < 0 {
			break
		}
		start += i
		nameStart := start + len(kw)
		open := strings.Index(src[nameStart:], "{")
		if open < 0 {
			break
		}
		open += nameStart
		name := strings.TrimSpace(src[nameStart:open])
		close := strings.Index(src[open:], "}")
		if close < 0 {
			break
		}
		close += open
		body := src[open+1 : close]
		var fields []string
		for _, m := range genInterfaceField.FindAllStringSubmatch(body, -1) {
			fields = append(fields, m[1])
		}
		sort.Strings(fields)
		out[name] = fields
		i = close + 1
	}
	return out
}

// schemaProps returns the property names of a component schema from the served
// OpenAPI document (doc is the parsed /api/v1/openapi.json) as a presence set.
func schemaProps(t *testing.T, doc map[string]any, schema string) map[string]bool {
	t.Helper()
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	s, ok := schemas[schema].(map[string]any)
	if !ok {
		t.Fatalf("served OpenAPI spec has no %q component schema", schema)
	}
	props, _ := s["properties"].(map[string]any)
	out := map[string]bool{}
	for k := range props {
		out[k] = true
	}
	return out
}

// schemaPropNames returns the sorted property names of a component schema.
func schemaPropNames(t *testing.T, doc map[string]any, schema string) []string {
	t.Helper()
	props := schemaProps(t, doc, schema)
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGeneratedFETypesMatchServedContract asserts every served component schema has a
// generated FE interface whose fields EXACTLY match — the structural FE↔BE contract
// lock. (Directional FE⊆BE is not enough once the types are generated: a generated
// interface that is MISSING a served field, or carries an EXTRA one, is itself the drift
// we must catch.)
func TestGeneratedFETypesMatchServedContract(t *testing.T) {
	doc := fetchSpec(t)
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	if len(schemas) == 0 {
		t.Fatal("served spec has no component schemas")
	}
	gen := readGenInterfaces(t)
	if len(gen) == 0 {
		t.Fatal("no interfaces parsed from the generated FE types (regenerate with `npm run gen:api`)")
	}

	for schema := range schemas {
		want := schemaPropNames(t, doc, schema)
		got, ok := gen[schema]
		if !ok {
			t.Errorf("SURFACE-005 contract drift: served schema %q has no generated FE interface (regenerate web/src/lib/api-types.gen.ts with `npm run gen:api`)", schema)
			continue
		}
		if !equalStringSets(got, want) {
			t.Errorf("SURFACE-005 contract drift: FE interface %q fields %v != served schema properties %v (regenerate the FE types with `npm run gen:api`)", schema, got, want)
		}
	}

	// Reality anchor: the field whose drift the audit caught must exist on BOTH the
	// served Certificate schema AND the generated FE Certificate type.
	beProps := schemaProps(t, doc, "Certificate")
	if !beProps["status"] {
		t.Error("served Certificate schema no longer defines `status`; SURFACE-005's fixed drift has regressed on the BE side")
	}
	certFields := gen["Certificate"]
	if !containsStr(certFields, "status") {
		t.Error("generated FE Certificate type no longer carries `status`; SURFACE-005's anchor field is gone — the codegen or spec regressed")
	}
}

// TestContractDriftDetectsInjectedMismatch is the anti-vacuous-green proof: it takes the
// REAL generated FE types, injects a single FE/BE mismatch (renames a Certificate field),
// and asserts the same comparison this gate uses flags it. If this ever passes silently,
// the contract gate above is not actually checking anything.
func TestContractDriftDetectsInjectedMismatch(t *testing.T) {
	doc := fetchSpec(t)
	want := schemaPropNames(t, doc, "Certificate")

	b, err := os.ReadFile(filepath.FromSlash(genTypesPath))
	if err != nil {
		t.Fatalf("read generated FE types: %v", err)
	}
	src := string(b)

	// Sanity: the unmodified generated types must MATCH (otherwise the mutation below
	// proves nothing).
	if got := parseInterfaces(src)["Certificate"]; !equalStringSets(got, want) {
		t.Fatalf("precondition failed: unmodified FE Certificate %v already != served %v", got, want)
	}

	// Inject drift: rename the `subject` field to `subject_DRIFT` inside Certificate.
	if !strings.Contains(src, "\n  subject: ") {
		t.Skip("generated Certificate has no `subject` field to mutate (codegen shape changed); the positive test still guards the contract")
	}
	mutated := strings.Replace(src, "\n  subject: ", "\n  subject_DRIFT: ", 1)
	if mutated == src {
		t.Fatal("mutation did not change the source")
	}

	got := parseInterfaces(mutated)["Certificate"]
	if equalStringSets(got, want) {
		t.Fatalf("contract gate is VACUOUS: an injected FE field rename (subject -> subject_DRIFT) was NOT detected; got %v, served %v", got, want)
	}
	// And confirm the specific drift is visible.
	if !containsStr(got, "subject_DRIFT") || containsStr(got, "subject") {
		t.Errorf("injected mismatch not reflected as expected: %v", got)
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
