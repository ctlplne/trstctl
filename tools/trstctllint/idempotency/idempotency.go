// SPDX-License-Identifier: MPL-2.0

// Package idempotency implements the AN-5 architecture rule: a mutating handler
// must accept and honor an idempotency key, so a retried request cannot execute
// the same mutation twice.
//
// A handler enters this rule either by carrying the //trstctl:mutation marker on
// its doc comment, or by being referenced from the HTTP route registry with
// mutation: true. It then honors the rule only when the idempotency key actually
// FLOWS INTO A RECOGNIZED DEDUPE SINK — a call that genuinely collapses retries:
//
//   - the canonical sink, (*orchestrator.Idempotency).Do(ctx, tenant, key, fn),
//     resolved by type (the receiver's method, not its spelling); or
//   - a forwarding call whose callee declares an idempotency-named parameter in
//     the position the key is passed to (for example the served handlers'
//     a.mutate(w, r, idempotencyKey, fn), whose third parameter is itself the
//     idempotency key it threads to Idempotency.Do).
//
// The rule is deliberately NOT satisfied by:
//
//   - merely mentioning the key (reading the "Idempotency-Key" header into a
//     variable and discarding it — the key flows nowhere); the earlier revision
//     already closed that;
//   - passing the key to ANY call (e.g. a logger) — a previous loophole
//     (ARCH-002): the callee must be a real dedupe sink, not an arbitrary
//     function that happens to receive the value;
//   - declaring an idempotency-named parameter that is never used — a parameter
//     by itself is not "honoring"; it must reach a sink (ARCH-002).
//   - passing a generated, fixed, or wrong-header value named idempotencyKey into
//     a real sink. The value must come from r.Header.Get("Idempotency-Key") or a
//     narrow documented compatibility helper.
//
// Detection is type-resolved (pass.TypesInfo), so the sink cannot be evaded by
// aliasing a receiver or shadowing a name.
package idempotency

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"

	"trstctl.com/trstctl/tools/trstctllint/internal/servedmutation"
)

const (
	// idempotencyPkgPath and idempotencyTypeName/Method name the canonical
	// dedupe sink: orchestrator.Idempotency.Do. A call resolving to this method
	// honors AN-5 outright.
	idempotencyPkgPath = "trstctl.com/trstctl/internal/orchestrator"
	idempotencyType    = "Idempotency"
	idempotencyMethod  = "Do"
	apiPkgPath         = "trstctl.com/trstctl/internal/api"
	idempotencyHeader  = "Idempotency-Key"
)

// Analyzer enforces AN-5.
var Analyzer = &analysis.Analyzer{
	Name: "idempotency",
	Doc:  "AN-5: served mutation handlers must thread an idempotency key into a real dedupe sink.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	decls := funcDecls(pass)
	for fn := range servedmutation.Funcs(pass) {
		if !honorsIdempotency(pass, decls, fn) {
			pass.Reportf(fn.Pos(),
				"mutating handler must thread an approved Idempotency-Key value into a dedupe sink (direct request header or documented compatibility helper), not a generated, fixed, or wrong-header value (AN-5)")
		}
	}
	return nil, nil
}

// honorsIdempotency reports whether a mutating function threads an
// idempotency-named value into a recognized dedupe sink somewhere in its body.
// A parameter, or a header read, is necessary but NOT sufficient: the value must
// reach a sink call.
func honorsIdempotency(pass *analysis.Pass, decls map[*types.Func]*ast.FuncDecl, fn *ast.FuncDecl) bool {
	fnObj, _ := pass.TypesInfo.Defs[fn.Name].(*types.Func)
	return functionHonorsIdempotency(pass, decls, fnObj, fn, approvedEntryParams(fnObj), map[*types.Func]bool{})
}

func approvedEntryParams(fnObj *types.Func) map[*types.Var]bool {
	if fnObj == nil {
		return nil
	}
	sig, ok := fnObj.Type().(*types.Signature)
	if !ok {
		return nil
	}
	params := sig.Params()
	out := map[*types.Var]bool{}
	for i := 0; i < params.Len(); i++ {
		param := params.At(i)
		if mentionsIdempotency(param.Name()) {
			out[param] = true
		}
	}
	return out
}

func functionHonorsIdempotency(pass *analysis.Pass, decls map[*types.Func]*ast.FuncDecl, fnObj *types.Func, fn *ast.FuncDecl, approvedParams map[*types.Var]bool, visiting map[*types.Func]bool) bool {
	if fn == nil || fn.Body == nil {
		return false
	}
	if fnObj != nil {
		if visiting[fnObj] {
			return false
		}
		visiting[fnObj] = true
		defer delete(visiting, fnObj)
	}
	approved := map[types.Object]bool{}
	for param := range approvedParams {
		approved[param] = true
	}
	honored := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			recordApprovedAssignments(pass, approved, stmt.Lhs, stmt.Rhs)
		case *ast.ValueSpec:
			recordApprovedValueSpec(pass, approved, stmt)
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := calleeFunc(pass, call.Fun)
		if callee == nil {
			return true
		}
		if isCanonicalIdempotencyDo(callee) && callPassesApprovedIdempotencyKey(pass, call, approved) {
			honored = true
			return false
		}
		if param, ok := callForwardsApprovedIdempotencyArgToParam(pass, call, callee.Type(), approved); ok {
			if calleeDecl := decls[callee]; calleeDecl != nil &&
				functionHonorsIdempotency(pass, decls, callee, calleeDecl, map[*types.Var]bool{param: true}, visiting) {
				honored = true
				return false
			}
		}
		return true
	})
	return honored
}

func callPassesApprovedIdempotencyKey(pass *analysis.Pass, call *ast.CallExpr, approved map[types.Object]bool) bool {
	if len(call.Args) < 3 {
		return false
	}
	return exprHasApprovedProvenance(pass, call.Args[2], approved)
}

func recordApprovedAssignments(pass *analysis.Pass, approved map[types.Object]bool, lhs, rhs []ast.Expr) {
	for i, left := range lhs {
		if i >= len(rhs) {
			continue
		}
		recordApprovedObject(pass, approved, left, exprHasApprovedProvenance(pass, rhs[i], approved))
	}
}

func recordApprovedValueSpec(pass *analysis.Pass, approved map[types.Object]bool, spec *ast.ValueSpec) {
	for i, name := range spec.Names {
		if i >= len(spec.Values) {
			continue
		}
		recordApprovedObject(pass, approved, name, exprHasApprovedProvenance(pass, spec.Values[i], approved))
	}
}

func recordApprovedObject(pass *analysis.Pass, approved map[types.Object]bool, expr ast.Expr, isApproved bool) {
	id, ok := expr.(*ast.Ident)
	if !ok {
		return
	}
	obj := objectForIdent(pass, id)
	if obj == nil {
		return
	}
	if isApproved {
		approved[obj] = true
		return
	}
	delete(approved, obj)
}

func exprHasApprovedProvenance(pass *analysis.Pass, expr ast.Expr, approved map[types.Object]bool) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return approved[objectForIdent(pass, e)]
	case *ast.ParenExpr:
		return exprHasApprovedProvenance(pass, e.X, approved)
	case *ast.CallExpr:
		if isDirectIdempotencyHeaderGet(e) || isApprovedIdempotencyHelper(pass, e) {
			return true
		}
		if isTransparentStringWrapper(pass, e) && len(e.Args) == 1 {
			return exprHasApprovedProvenance(pass, e.Args[0], approved)
		}
	}
	return false
}

func objectForIdent(pass *analysis.Pass, id *ast.Ident) types.Object {
	if obj := pass.TypesInfo.Defs[id]; obj != nil {
		return obj
	}
	return pass.TypesInfo.Uses[id]
}

func isDirectIdempotencyHeaderGet(call *ast.CallExpr) bool {
	if len(call.Args) != 1 || stringLiteralValue(call.Args[0]) != idempotencyHeader {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Get" {
		return false
	}
	headerSel, ok := sel.X.(*ast.SelectorExpr)
	return ok && headerSel.Sel.Name == "Header"
}

func isApprovedIdempotencyHelper(pass *analysis.Pass, call *ast.CallExpr) bool {
	fn := calleeFunc(pass, call.Fun)
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != apiPkgPath {
		return false
	}
	switch fn.Name() {
	case "vaultIdempotencyKey", "scimIdempotencyKey":
		// Vault and SCIM compatibility routes intentionally preserve the header
		// when present and derive a documented deterministic fallback for legacy
		// clients that cannot set arbitrary headers.
		return true
	default:
		return false
	}
}

func isTransparentStringWrapper(pass *analysis.Pass, call *ast.CallExpr) bool {
	fn := calleeFunc(pass, call.Fun)
	return fn != nil && fn.Pkg() != nil &&
		fn.Pkg().Path() == "strings" &&
		(fn.Name() == "TrimSpace" || fn.Name() == "Trim")
}

func stringLiteralValue(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return s
}

// calleeFunc resolves the function/method object a call expression targets,
// seeing through selector expressions (pkg.Fn, recv.Method). It returns nil for
// calls whose target is not a resolvable func (e.g. a type conversion, or a
// dynamic func value with no declared signature name).
func calleeFunc(pass *analysis.Pass, fun ast.Expr) *types.Func {
	switch e := fun.(type) {
	case *ast.Ident:
		if obj, ok := pass.TypesInfo.Uses[e].(*types.Func); ok {
			return obj
		}
	case *ast.SelectorExpr:
		if sel, ok := pass.TypesInfo.Selections[e]; ok {
			if fn, ok := sel.Obj().(*types.Func); ok {
				return fn
			}
		}
		// A qualified package function (orchestrator.NewX) resolves via Uses on
		// the selector's Sel identifier.
		if obj, ok := pass.TypesInfo.Uses[e.Sel].(*types.Func); ok {
			return obj
		}
	}
	return nil
}

func funcDecls(pass *analysis.Pass) map[*types.Func]*ast.FuncDecl {
	decls := map[*types.Func]*ast.FuncDecl{}
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if obj, ok := pass.TypesInfo.Defs[fn.Name].(*types.Func); ok {
				decls[obj] = fn
			}
		}
	}
	return decls
}

// isCanonicalIdempotencyDo reports whether fn is
// (*orchestrator.Idempotency).Do — the canonical dedupe sink.
func isCanonicalIdempotencyDo(fn *types.Func) bool {
	if fn.Name() != idempotencyMethod {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	recv := derefNamed(sig.Recv().Type())
	if recv == nil {
		return false
	}
	obj := recv.Obj()
	return obj != nil && obj.Name() == idempotencyType &&
		obj.Pkg() != nil && obj.Pkg().Path() == idempotencyPkgPath
}

// callForwardsApprovedIdempotencyArgToParam reports whether this call passes an
// approved idempotency value into the corresponding idempotency-named parameter
// of the callee. The callee is not accepted on that signature alone; the analyzer
// must also recursively prove that callee reaches Idempotency.Do.
func callForwardsApprovedIdempotencyArgToParam(pass *analysis.Pass, call *ast.CallExpr, t types.Type, approved map[types.Object]bool) (*types.Var, bool) {
	sig, ok := t.(*types.Signature)
	if !ok {
		return nil, false
	}
	params := sig.Params()
	for i, arg := range call.Args {
		if i >= params.Len() || !exprHasApprovedProvenance(pass, arg, approved) {
			continue
		}
		param := params.At(i)
		if mentionsIdempotency(param.Name()) {
			return param, true
		}
	}
	return nil, false
}

// derefNamed returns the *types.Named behind a possibly-pointer receiver type.
func derefNamed(t types.Type) *types.Named {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		return named
	}
	return nil
}

func mentionsIdempotency(s string) bool {
	return strings.Contains(strings.ToLower(s), "idempotency")
}
