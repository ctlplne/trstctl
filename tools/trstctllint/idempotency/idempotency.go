// Package idempotency implements the AN-5 architecture rule: a mutating handler
// must accept and honor an idempotency key, so a retried request cannot execute
// the same mutation twice.
//
// A handler opts in by carrying the //trstctl:mutation marker on its doc
// comment. It then honors the rule only when the idempotency key actually FLOWS
// INTO A RECOGNIZED DEDUPE SINK — a call that genuinely collapses retries:
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
//
// Detection is type-resolved (pass.TypesInfo), so the sink cannot be evaded by
// aliasing a receiver or shadowing a name.
package idempotency

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"

	"trstctl.com/trstctl/tools/trstctllint/internal/directive"
)

const (
	mutationMarker = "trstctl:mutation"

	// idempotencyPkgPath and idempotencyTypeName/Method name the canonical
	// dedupe sink: orchestrator.Idempotency.Do. A call resolving to this method
	// honors AN-5 outright.
	idempotencyPkgPath = "trstctl.com/trstctl/internal/orchestrator"
	idempotencyType    = "Idempotency"
	idempotencyMethod  = "Do"
)

// Analyzer enforces AN-5.
var Analyzer = &analysis.Analyzer{
	Name: "idempotency",
	Doc:  "AN-5: handlers marked //trstctl:mutation must thread an idempotency key into a real dedupe sink.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !directive.OnFunc(fn, mutationMarker) {
				continue
			}
			if !honorsIdempotency(pass, fn) {
				pass.Reportf(fn.Pos(),
					"mutating handler must thread an idempotency key into a dedupe sink (Idempotency.Do or a key-accepting mutate), not merely name or log it (AN-5)")
			}
		}
	}
	return nil, nil
}

// honorsIdempotency reports whether a mutating function threads an
// idempotency-named value into a recognized dedupe sink somewhere in its body.
// A parameter, or a header read, is necessary but NOT sufficient: the value must
// reach a sink call.
func honorsIdempotency(pass *analysis.Pass, fn *ast.FuncDecl) bool {
	honored := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callIsDedupeSink(pass, call) && callPassesIdempotencyArg(call) {
			honored = true
			return false
		}
		return true
	})
	return honored
}

// callPassesIdempotencyArg reports whether any argument of the call is, or
// contains, an identifier whose name mentions idempotency. A bare string literal
// (the header name spelled at a call site) does not count: the key must be a
// value that flows through the program.
func callPassesIdempotencyArg(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if exprMentionsIdempotency(arg) {
			return true
		}
	}
	return false
}

// callIsDedupeSink reports whether the call targets a recognized dedupe sink:
// either orchestrator.Idempotency.Do (resolved by type), or a function/method
// whose signature declares an idempotency-named parameter (a forwarding sink
// such as API.mutate that threads the key onward to Idempotency.Do). Resolution
// is by type so an arbitrary call that merely receives the value (e.g. a logger)
// is rejected.
func callIsDedupeSink(pass *analysis.Pass, call *ast.CallExpr) bool {
	fnObj := calleeFunc(pass, call.Fun)
	if fnObj == nil {
		return false
	}
	if isCanonicalIdempotencyDo(fnObj) {
		return true
	}
	return signatureHasIdempotencyParam(fnObj.Type())
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

// signatureHasIdempotencyParam reports whether a function signature declares a
// parameter whose name mentions idempotency. Such a callee is a forwarding sink:
// it accepts the key in order to thread it onward (the served API.mutate
// pattern). This is what lets a handler satisfy AN-5 by calling
// mutate(w, r, idempotencyKey, fn) rather than Idempotency.Do directly.
func signatureHasIdempotencyParam(t types.Type) bool {
	sig, ok := t.(*types.Signature)
	if !ok {
		return false
	}
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		if mentionsIdempotency(params.At(i).Name()) {
			return true
		}
	}
	return false
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

// exprMentionsIdempotency reports whether an argument expression is, or contains,
// an identifier whose name mentions idempotency.
func exprMentionsIdempotency(arg ast.Expr) bool {
	found := false
	ast.Inspect(arg, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && mentionsIdempotency(id.Name) {
			found = true
			return false
		}
		return true
	})
	return found
}

func mentionsIdempotency(s string) bool {
	return strings.Contains(strings.ToLower(s), "idempotency")
}
