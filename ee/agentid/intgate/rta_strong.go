//go:build agidrta

// SPDX-License-Identifier: LicenseRef-trstctl-EE

package intgate

// rta_strong.go is the STRONG check (CI-only, //go:build agidrta): an RTA call graph
// over the WHOLE program, seeded from the main.main of the in-scope binaries built
// WITHOUT -tags trstctl_core (so the ee_attach seam is linked), used to prove every
// REQUIRED ee/agentid constructor is a REACHABLE node.
//
// It is behind the agidrta build tag because loading the whole program (911+ packages)
// via go/packages + go/ssa is memory- and disk-heavy and is not appropriate for the
// default `go test` / `make lint` floor path on a constrained sandbox. CI runs
// `go test -tags agidrta ./ee/agentid/intgate/...` to exercise it. The floor
// (TestProdCaller_EveryConstructorHasNonTestCaller) and the seam assertion remain the
// always-on defaults.

import (
	"fmt"
	"go/types"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// inScopeBinaries are the cmd/* mains RTA seeds from. All three are compiled WITHOUT
// -tags trstctl_core so the //go:build !trstctl_core ee_attach seams are linked.
// cmd/trstctl links the AGID API + orchestrator worker; cmd/trstctl-signer links the
// in-signer delegation gate; cmd/trstctl-agent links neither AGID package but is
// included per the card (its reachable set simply contributes nothing to ee/agentid).
var inScopeBinaries = []string{
	"trstctl.com/trstctl/cmd/trstctl",
	"trstctl.com/trstctl/cmd/trstctl-signer",
	"trstctl.com/trstctl/cmd/trstctl-agent",
}

// rtaReachability loads the in-scope binaries as WHOLE PROGRAMS (all dependency bodies
// built from source, ssautil.AllPackages), seeds RTA from each main.main (plus package
// init), and returns the set of REQUIRED inventory constructors that are NOT reachable
// nodes. An empty result means every REQUIRED constructor is reachable from a running
// binary built without the core build tag.
//
// Loading ALL dependency bodies from source (not export data) is essential: the AGID
// attach seam composes the licensed factories through function-typed struct fields via
// appendAPIFactory / appendOutboxFactory (cmd/trstctl/ee_attach.go). The value the
// server invokes at internal/server/server.go is a CLOSURE that calls another closure
// returned by eeagentapi.NewAPIOptionsFactory() / eeagentorch.NewLicensedOutboxFactory().
// With export-data-only SSA those returned closures are not built (their bodies are
// absent), so RTA cannot follow them and a constructor invoked only inside such a
// closure (NewService, the orchestrator worker's reach/revoke/brokerstore constructors)
// looks unreachable. ssautil.AllPackages builds every body, so RTA follows the composed
// closures the running binary really executes and the reachability is exact.
func rtaReachability() (unreachable []Constructor, loadedPkgCount int, err error) {
	cfg := &packages.Config{
		// Whole-program load: names, files, types, syntax, and ALL deps -- required for a
		// source-built SSA program where every function (incl. returned closures) has a body.
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule,
		// EE build: NO -tags trstctl_core, so the ee_attach seam (//go:build !trstctl_core)
		// is linked. BuildFlags left empty == default tags.
		Tests: false,
	}
	initial, err := packages.Load(cfg, inScopeBinaries...)
	if err != nil {
		return nil, 0, fmt.Errorf("packages.Load: %w", err)
	}
	if n := packages.PrintErrors(initial); n > 0 {
		return nil, 0, fmt.Errorf("packages.Load reported %d error(s) (see stderr)", n)
	}

	// AllPackages: build SSA for the initial packages AND every dependency, from source,
	// so returned closures have analyzable bodies (see the function doc above).
	prog, _ := ssautil.AllPackages(initial, ssa.InstantiateGenerics)
	prog.Build()
	loadedPkgCount = len(prog.AllPackages())

	// Seeds: each binary's main.main and its package init. That is the faithful
	// "reachable from a running binary main" root set the card asks for.
	var roots []*ssa.Function
	for _, p := range prog.AllPackages() {
		if p == nil || p.Pkg == nil {
			continue
		}
		if isInScopeMain(p.Pkg.Path()) {
			if mainFn := p.Func("main"); mainFn != nil {
				roots = append(roots, mainFn)
			}
			if initFn := p.Func("init"); initFn != nil {
				roots = append(roots, initFn)
			}
		}
	}
	if len(roots) == 0 {
		return nil, loadedPkgCount, fmt.Errorf("no in-scope main.main SSA functions found among seeds %v", inScopeBinaries)
	}

	res := rta.Analyze(roots, true)

	// Lookup of reachable top-level (non-method) funcs, keyed "pkgPath\x00Name".
	reachable := map[string]bool{}
	addReachable := func(fn *ssa.Function) {
		if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
			return
		}
		if fn.Signature != nil && fn.Signature.Recv() != nil {
			return // methods are not our constructors
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

	for _, c := range requiredConstructors() {
		full := modulePath + "/" + c.Pkg + "\x00" + c.Name
		if !reachable[full] {
			unreachable = append(unreachable, c)
		}
	}
	return unreachable, loadedPkgCount, nil
}

// isInScopeMain reports whether importPath is one of the seeded cmd/* mains.
func isInScopeMain(importPath string) bool {
	for _, b := range inScopeBinaries {
		if importPath == b {
			return true
		}
	}
	return false
}

// assertNoTypesError is a compile-time anchor so an accidental unused import of types is
// caught; types is used indirectly through ssa/packages APIs in some toolchains.
var _ = func() *types.Package { return nil }
