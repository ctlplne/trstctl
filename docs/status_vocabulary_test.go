// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/servedstatus"
)

var servedVerdictFields = map[string]bool{
	"status":       true,
	"outcome":      true,
	"verdict":      true,
	"health_gate":  true,
	"canary_state": true,
}

type openAPIVerdictDocument struct {
	Components struct {
		Schemas map[string]openAPIVerdictSchema `json:"schemas"`
	} `json:"components"`
}

type openAPIVerdictSchema struct {
	Properties map[string]json.RawMessage `json:"properties"`
}

// The served-status vocabulary contract (truth-integrity sweep, K2).
//
// A status string is a claim an operator acts on. "test_succeeded" on a route
// that opens no connection, and "passed" on a gate that evaluates nothing, are
// the two defects the 2026-08-02 gap analysis found: green tests, lying surface.
// internal/servedstatus is the single registry that records, as data, what each
// status value actually did; these tests keep the served code and the published
// contract tied to it.
//
// Three checks, in order of what they protect:
//  1. no registered status spells an action its own flags deny;
//  2. no served receipt or gate is built from a bare string literal, so a new
//     status cannot enter the API without passing check 1;
//  3. the retired overstating spellings do not come back anywhere an operator
//     could read them.

// statusVocabularyStructs are the served composite literals whose Status field
// must come from the registry rather than a string literal.
var statusVocabularyStructs = map[string]string{
	"ConnectorDeliveryReceipt":  "servedstatus.Connector*",
	"FleetReissuanceHealthGate": "servedstatus.FleetGate*",
	"FleetReissuanceBatch":      "servedstatus.FleetBatch*",
}

// statusVocabularyScanned is the served source the AST check covers. The
// orchestrator and API construct these receipts; stores and projections copy
// values that already passed through here.
var statusVocabularyScanned = []string{
	"internal/api/",
	"internal/orchestrator/",
	"internal/server/",
}

// A retired status is retired on ONE surface. "completed" is wrong for a fleet
// batch that never executed, and perfectly correct for a finished ceremony, a
// drained lease, or a code-signing run. So the retired-write check is scoped the
// same way the literal check is — to files that actually construct the tracked
// surface — rather than grepping the tree for a common English word.
//
// The generated OpenAPI contract, the generated clients, and the console's label
// map all still name retired values on purpose: receipts written before the
// correction still carry them, and an operator reading history is entitled to a
// rendered label. What must not come back is production code that WRITES one.

// retiredStatusWriteExempt is the registry that declares the retirements; it has
// to name the old values to retire them.
var retiredStatusWriteExempt = []string{
	"internal/servedstatus/",
}

// TestServedStatusVocabularyDoesNotOverstateItself is the contract: every status
// value trstctl serves is spelled no stronger than what the code performed.
func TestServedStatusVocabularyDoesNotOverstateItself(t *testing.T) {
	t.Parallel()
	for _, v := range servedstatus.Audit() {
		t.Errorf("served status vocabulary overstates itself: %s\n"+
			"either the code now performs the action (set the flag on the Claim) or the status needs a weaker, honest name",
			v.Error())
	}
}

// TestEveryServedVerdictHasAnEvidenceBinding closes the registration escape
// hatch in the original K2 guard. The old test named three Go structs by hand;
// a fourth status-bearing DTO therefore entered the generated API without the
// guard even seeing it. The generated OpenAPI document is the exhaustive served
// contract, so every operator-readable verdict field in it must resolve to one
// closed evidence predicate and one exact production writer declaration.
func TestEveryServedVerdictHasAnEvidenceBinding(t *testing.T) {
	t.Parallel()
	var doc openAPIVerdictDocument
	if err := json.Unmarshal([]byte(read(t, "../internal/api/testdata/openapi.golden.json")), &doc); err != nil {
		t.Fatalf("decode generated OpenAPI status census: %v", err)
	}
	for _, failure := range validateServedEvidenceBindings(doc, servedEvidenceBindings) {
		t.Error(failure)
	}
}

// TestANewServedVerdictFailsClosedUntilBound is the meta-negative proof. It
// plants a status-bearing DTO in a copy of the generated contract and proves
// the census rejects it. This test prevents a future refactor from accidentally
// turning the exhaustive registry back into a best-effort list.
func TestANewServedVerdictFailsClosedUntilBound(t *testing.T) {
	t.Parallel()
	var doc openAPIVerdictDocument
	if err := json.Unmarshal([]byte(read(t, "../internal/api/testdata/openapi.golden.json")), &doc); err != nil {
		t.Fatalf("decode generated OpenAPI status census: %v", err)
	}
	doc.Components.Schemas["FutureUnreviewedVerdict"] = openAPIVerdictSchema{
		Properties: map[string]json.RawMessage{"status": json.RawMessage(`{"type":"string"}`)},
	}
	failures := validateServedEvidenceBindings(doc, servedEvidenceBindings)
	for _, failure := range failures {
		if strings.Contains(failure, "FutureUnreviewedVerdict.status has no evidence binding") {
			return
		}
	}
	t.Fatalf("planted generated verdict escaped the fail-closed evidence census; failures=%v", failures)
}

func validateServedEvidenceBindings(doc openAPIVerdictDocument, bindings []EvidenceBinding) []string {
	var failures []string
	want := map[string]bool{}
	for schema, shape := range doc.Components.Schemas {
		for field := range shape.Properties {
			if servedVerdictFields[field] {
				want[schema+"."+field] = true
			}
		}
	}
	if len(want) == 0 {
		return []string{"generated OpenAPI status census found no verdict fields"}
	}
	got := map[string]bool{}
	for _, binding := range bindings {
		key := binding.Schema + "." + binding.Field
		if got[key] {
			failures = append(failures, "duplicate served-status evidence binding for "+key)
		}
		got[key] = true
		if !want[key] {
			failures = append(failures, "served-status evidence binding "+key+" is not present in generated OpenAPI")
		}
		if !validEvidenceClass(binding.Predicate.Class) {
			failures = append(failures, "served-status evidence binding "+key+" has unknown evidence class "+strconv.Quote(string(binding.Predicate.Class)))
		}
		if strings.TrimSpace(binding.Predicate.Requirement) == "" {
			failures = append(failures, "served-status evidence binding "+key+" has no required evidence predicate")
		}
		if failure := validateProductionWriter(binding.Writer); failure != "" {
			failures = append(failures, "served-status evidence binding "+key+" "+failure)
		}
	}
	for key := range want {
		if !got[key] {
			failures = append(failures, "generated OpenAPI verdict "+key+" has no evidence binding; register its required predicate and production writer before serving it")
		}
	}
	return failures
}

func validEvidenceClass(class EvidenceClass) bool {
	switch class {
	case evidenceEventProjection, evidenceWorkflow, evidenceObservation, evidenceConfiguration, evidenceProtocol, evidenceAttestation:
		return true
	default:
		return false
	}
}

// validateProductionWriter requires an exact production Go declaration, not a
// path that merely exists. The symbol grammar is function, Type.Method, type,
// var, or const; methods include their receiver so same-named methods cannot be
// confused.
func validateProductionWriter(writer string) string {
	parts := strings.SplitN(writer, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return "must name an exact production symbol as file.go:Type.Method or file.go:function, got " + strconv.Quote(writer)
	}
	writerPath, symbol := parts[0], strings.TrimSpace(parts[1])
	if !strings.HasSuffix(writerPath, ".go") || strings.HasSuffix(writerPath, "_test.go") {
		return "must point at a non-test Go source file, got " + strconv.Quote(writerPath)
	}
	body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(writerPath)))
	if err != nil {
		return "names missing production writer " + strconv.Quote(writerPath) + ": " + err.Error()
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, writerPath, body, 0)
	if err != nil {
		return "names unparsable production writer " + strconv.Quote(writerPath) + ": " + err.Error()
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) == 1 {
				name = receiverTypeName(d.Recv.List[0].Type) + "." + name
			}
			if name == symbol {
				return ""
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.Name == symbol {
						return ""
					}
				case *ast.ValueSpec:
					for _, name := range s.Names {
						if name.Name == symbol {
							return ""
						}
					}
				}
			}
		}
	}
	return "names no declaration " + strconv.Quote(symbol) + " in " + strconv.Quote(writerPath)
}

func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	case *ast.IndexExpr:
		return receiverTypeName(e.X)
	case *ast.IndexListExpr:
		return receiverTypeName(e.X)
	default:
		return ""
	}
}

// TestServedStatusLiteralsComeFromTheRegistry stops a bare string from entering a
// served receipt. Without this, check 1 only covers statuses somebody remembered
// to register, which is exactly how test_succeeded survived.
func TestServedStatusLiteralsComeFromTheRegistry(t *testing.T) {
	t.Parallel()
	checked := 0
	for _, rel := range gitTrackedFiles(t) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		if !hasAnyPrefix(rel, statusVocabularyScanned) {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("status vocabulary gate: read %s: %v", rel, err)
		}
		// Cheap pre-filter: only files naming one of the served structs are parsed.
		named := false
		for name := range statusVocabularyStructs {
			if strings.Contains(string(body), name) {
				named = true
				break
			}
		}
		if !named {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, rel, body, 0)
		if err != nil {
			t.Fatalf("status vocabulary gate: parse %s: %v", rel, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			want, ok := statusVocabularyStructs[statusVocabularyTypeName(lit.Type)]
			if !ok {
				return true
			}
			checked++
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Status" {
					continue
				}
				basic, ok := kv.Value.(*ast.BasicLit)
				if !ok || basic.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(basic.Value)
				if err != nil {
					value = basic.Value
				}
				pos := fset.Position(basic.Pos())
				t.Errorf("%s:%d: served status %q is a bare string literal; use a %s constant so internal/servedstatus can hold it to what the code actually did",
					rel, pos.Line, value, want)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("status vocabulary gate found no served receipt or gate literals to check; the scan list or struct names have drifted from the code")
	}
}

// TestRetiredStatusSpellingsAreNeverWrittenAgain keeps a corrected status from
// coming back through a copy-paste. Retired values stay readable — they are still
// in the served enum and still render in the console — but no production Go path
// may construct one.
func TestRetiredStatusSpellingsAreNeverWrittenAgain(t *testing.T) {
	t.Parallel()
	if len(servedstatus.AllRetired()) == 0 {
		t.Fatal("no retired statuses declared; this gate exists because two of them were found in the served surface")
	}
	scanned := 0
	for _, rel := range gitTrackedFiles(t) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		if !hasAnyPrefix(rel, statusVocabularyScanned) || hasAnyPrefix(rel, retiredStatusWriteExempt) {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("status vocabulary gate: read %s: %v", rel, err)
		}
		// Only files that construct one of the tracked surfaces are checked, so a
		// retired word stays legal on every other surface that means it honestly.
		reg, ok := statusVocabularyRegistryFor(string(body))
		if !ok {
			continue
		}
		scanned++
		for _, r := range reg.Retired {
			if strings.Contains(string(body), strconv.Quote(r.Value)) {
				t.Errorf("%s constructs the retired %s status %q; it %s. Write %q instead — the old value stays in the served enum for historical rows only",
					rel, reg.Surface, r.Value, r.Why, r.Replacement)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("status vocabulary gate scanned no files constructing a tracked surface; the scan list or struct names have drifted from the code")
	}
}

// statusVocabularyRegistryFor returns the registry a file's surface belongs to,
// keyed off the struct type it constructs.
func statusVocabularyRegistryFor(body string) (servedstatus.Registry, bool) {
	switch {
	case strings.Contains(body, "ConnectorDeliveryReceipt{"):
		return servedstatus.ConnectorDelivery, true
	case strings.Contains(body, "FleetReissuanceBatch{"):
		return servedstatus.FleetBatch, true
	case strings.Contains(body, "FleetReissuanceHealthGate{"):
		return servedstatus.FleetHealthGate, true
	default:
		return servedstatus.Registry{}, false
	}
}

// TestRetiredStatusesStayInTheServedContract is the other half: retiring a value
// must not narrow the published enum, because rows written before the rename are
// still served and the additive-only schema policy forbids removing an enum member.
func TestRetiredStatusesStayInTheServedContract(t *testing.T) {
	t.Parallel()
	golden := read(t, "../internal/api/testdata/openapi.golden.json")
	for _, r := range servedstatus.AllRetired() {
		if !strings.Contains(golden, strconv.Quote(r.Value)) {
			t.Errorf("the served OpenAPI contract dropped the retired status %q; historical receipts still carry it, so removing it puts stored rows outside the published contract",
				r.Value)
		}
		if !strings.Contains(golden, strconv.Quote(r.Replacement)) {
			t.Errorf("the served OpenAPI contract is missing the replacement status %q for retired %q", r.Replacement, r.Value)
		}
	}
}

// TestLimitationsRecordsTheStatusVocabularyContract keeps the served-state page
// honest about what these statuses do and do not mean, since that page is what an
// evaluator reads before trusting the surface.
func TestLimitationsRecordsTheStatusVocabularyContract(t *testing.T) {
	t.Parallel()
	limitations := read(t, "limitations.md")
	for _, want := range []string{
		"config_validated",
		"not_evaluated",
		"internal/servedstatus",
	} {
		if !strings.Contains(limitations, want) {
			t.Errorf("docs/limitations.md must record the served status vocabulary token %q so the page states what each status does and does not claim", want)
		}
	}
}

// statusVocabularyTypeName reduces a composite-literal type to its bare type
// name, so both `store.ConnectorDeliveryReceipt{}` and `ConnectorDeliveryReceipt{}`
// are recognized.
func statusVocabularyTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.StarExpr:
		return statusVocabularyTypeName(t.X)
	default:
		return ""
	}
}
