// Package idempotency implements the AN-5 architecture rule: a mutating handler
// must accept and honor an idempotency key, so a retried request cannot execute
// the same mutation twice.
//
// A handler opts in by carrying the //certctl:mutation marker on its doc
// comment. It then honors the rule when it either (a) accepts an idempotency key
// as a parameter (the orchestrator-path style, where the key is threaded in by
// the caller), or (b) passes an idempotency-named value as an argument to a call
// (the HTTP style, where the handler reads the key and hands it to the dedupe
// store).
//
// The rule is deliberately NOT satisfied by merely mentioning the word: reading
// the "Idempotency-Key" header into a variable and discarding it does not count,
// because the key never flows into the operation. (Earlier, narrower revisions
// accepted any mention; S2.4 closed that loophole now that the orchestrator
// records keys for real.) The rule will tighten further to auto-detect mutating
// handlers from their route/method as the API lands.
package idempotency

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"

	"certctl.io/certctl/tools/certctllint/internal/directive"
)

const mutationMarker = "certctl:mutation"

// Analyzer enforces AN-5.
var Analyzer = &analysis.Analyzer{
	Name: "idempotency",
	Doc:  "AN-5: handlers marked //certctl:mutation must accept and honor an idempotency key.",
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
			if !honorsIdempotency(fn) {
				pass.Reportf(fn.Pos(),
					"mutating handler must accept and honor an idempotency key (AN-5)")
			}
		}
	}
	return nil, nil
}

// honorsIdempotency reports whether a mutating function threads an idempotency
// key through, rather than merely naming it. It is satisfied when the function
// either accepts an idempotency-named parameter, or passes an idempotency-named
// value as an argument to a call.
func honorsIdempotency(fn *ast.FuncDecl) bool {
	if hasIdempotencyParam(fn.Type.Params) {
		return true
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if exprMentionsIdempotency(arg) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// hasIdempotencyParam reports whether any parameter is named like an idempotency
// key (for example idempotencyKey).
func hasIdempotencyParam(params *ast.FieldList) bool {
	if params == nil {
		return false
	}
	for _, field := range params.List {
		for _, name := range field.Names {
			if mentionsIdempotency(name.Name) {
				return true
			}
		}
	}
	return false
}

// exprMentionsIdempotency reports whether an argument expression is, or contains,
// an identifier whose name mentions idempotency. A bare string literal does not
// count: the key must be a value that flows through the program, not the header
// name spelled out at a call site.
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
