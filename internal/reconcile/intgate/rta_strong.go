//go:build xrecrta

// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"fmt"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

var inScopeBinaries = []string{
	"trstctl.com/trstctl/cmd/trstctl",
	"trstctl.com/trstctl/cmd/trstctl-signer",
}

func rtaReachability() (unreachable []Constructor, loadedPkgCount int, err error) {
	root, err := moduleRoot()
	if err != nil {
		return nil, 0, err
	}
	ctors, err := LiveConstructors(root)
	if err != nil {
		return nil, 0, err
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule,
		Tests: false,
	}
	initial, err := packages.Load(cfg, inScopeBinaries...)
	if err != nil {
		return nil, 0, fmt.Errorf("packages.Load: %w", err)
	}
	if n := packages.PrintErrors(initial); n > 0 {
		return nil, 0, fmt.Errorf("packages.Load reported %d error(s)", n)
	}
	prog, _ := ssautil.AllPackages(initial, ssa.InstantiateGenerics)
	prog.Build()
	loadedPkgCount = len(prog.AllPackages())

	var roots []*ssa.Function
	for _, p := range prog.AllPackages() {
		if p == nil || p.Pkg == nil {
			continue
		}
		if !isInScopeMain(p.Pkg.Path()) {
			continue
		}
		if mainFn := p.Func("main"); mainFn != nil {
			roots = append(roots, mainFn)
		}
		if initFn := p.Func("init"); initFn != nil {
			roots = append(roots, initFn)
		}
	}
	if len(roots) == 0 {
		return nil, loadedPkgCount, fmt.Errorf("no in-scope main.main SSA functions found")
	}

	res := rta.Analyze(roots, true)
	reachable := map[string]bool{}
	addReachable := func(fn *ssa.Function) {
		if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
			return
		}
		if fn.Signature != nil && fn.Signature.Recv() != nil {
			return
		}
		reachable[fn.Pkg.Pkg.Path()+"\x00"+fn.Name()] = true
	}
	for fn := range res.Reachable {
		addReachable(fn)
	}
	if res.CallGraph != nil {
		_ = callgraph.GraphVisitEdges(res.CallGraph, func(e *callgraph.Edge) error {
			addReachable(e.Callee.Func)
			addReachable(e.Caller.Func)
			return nil
		})
	}
	for _, c := range ctors {
		if !reachable[modulePath+"/"+c.Pkg+"\x00"+c.Name] {
			unreachable = append(unreachable, c)
		}
	}
	return unreachable, loadedPkgCount, nil
}

func isInScopeMain(importPath string) bool {
	for _, b := range inScopeBinaries {
		if importPath == b {
			return true
		}
	}
	return false
}
