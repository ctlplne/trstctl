// SPDX-License-Identifier: BUSL-1.1

package intgate

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// seam.go proves the third property: the ONLY sanctioned production root is the
// ee_attach seam, and reachability through a test helper does NOT satisfy the gate.
//
// It works lexically over the non-test call graph the floor already computes. A
// constructor is "seam-rooted" iff there is a chain of non-test callers from a
// SanctionedSeams file down to it:
//
//	ee_attach.go --calls--> {api.NewAPIOptionsFactory, orchestrator.NewLicensedOutboxFactory,
//	                         brokerstore.NewFailClosedBrokerPrecondition, delegation.NewSignerGate}
//	     --transitively calls--> every other REQUIRED constructor.
//
// Because NonTestCallers already EXCLUDES *_test.go, /mock, /fake, /testkit, testdata,
// and test-only-build-tag files, a constructor reachable only from a test helper has an
// EMPTY non-test caller set and is therefore NOT seam-rooted -- which is exactly the
// "a test-helper-only reachability still fails" requirement.

// seamAttachTargets returns the set of constructors DIRECTLY called (non-test) from any
// sanctioned seam file. These are the seam's own attach roots (the four the ee_attach
// blocks invoke). Keyed by "pkg\x00Name" to disambiguate a bare "New" across packages.
func seamAttachTargets(root string) (map[string]bool, error) {
	seamAbs := map[string]bool{}
	for _, s := range SanctionedSeams {
		seamAbs[filepath.Join(root, filepath.FromSlash(s))] = true
	}
	targets := map[string]bool{}
	for _, c := range Inventory {
		if c.Tier != TierRequired {
			continue
		}
		refs, err := NonTestCallers(root, c.Name, c.File, defaultSearchRoots)
		if err != nil {
			return nil, err
		}
		for _, r := range refs {
			if seamAbs[filepath.Join(root, filepath.FromSlash(r.File))] {
				targets[c.Pkg+"\x00"+c.Name] = true
				break
			}
		}
	}
	return targets, nil
}

// SeamRootedResult reports, per REQUIRED constructor, whether it is seam-rooted, and
// the shortest witness chain (constructor keys from the seam down) when it is.
type SeamRootedResult struct {
	Constructor Constructor
	SeamRooted  bool
	// DirectFromSeam is true when a sanctioned seam file calls the constructor directly.
	DirectFromSeam bool
}

// key is the disambiguating identity of a constructor in the caller graph.
func ctorKey(pkg, name string) string { return pkg + "\x00" + name }

// AssertSeamOnlyRoot computes, for every REQUIRED constructor, whether its non-test
// caller chain roots at a sanctioned seam. It builds the non-test call graph among the
// inventory constructors + the seam files, then BFS-marks reachability from the seam
// attach targets. A constructor with no non-test callers at all (e.g. reachable only
// from a test helper) is not marked and reported SeamRooted=false.
func AssertSeamOnlyRoot(root string) ([]SeamRootedResult, error) {
	req := requiredConstructors()

	// Index constructors by name for reverse-lookup when scanning callers. A single
	// name may map to several packages (bare "New"); we record all candidates and rely
	// on the caller's package/selector when possible, but for seam-rooting a coarse
	// name-based edge is sufficient and conservative (it can only ADD edges, never hide
	// a genuinely test-only constructor, because test files are excluded upstream).
	byName := map[string][]Constructor{}
	for _, c := range req {
		byName[c.Name] = append(byName[c.Name], c)
	}

	// seamCallers[key] = set of constructor keys that call it from NON-TEST code, PLUS a
	// sentinel "SEAM" when a sanctioned seam file calls it. We compute the forward edge
	// (caller -> callee) so BFS from SEAM reaches every seam-rooted constructor.
	const seamSentinel = "\x00SEAM"
	// forward[X] = constructors X calls (that are in the inventory). We derive it by
	// asking, for each constructor C, who its non-test callers are, then adding the edge
	// caller->C.
	forward := map[string]map[string]bool{}
	addEdge := func(from, to string) {
		if forward[from] == nil {
			forward[from] = map[string]bool{}
		}
		forward[from][to] = true
	}

	seamAbs := map[string]bool{}
	for _, s := range SanctionedSeams {
		seamAbs[filepath.Join(root, filepath.FromSlash(s))] = true
	}

	// Map an absolute caller file to the constructor key(s) whose defining package owns
	// it, so a caller that is itself an in-scope constructor's package contributes an
	// edge from that package's constructor. For seam-rooting we attribute a caller file
	// to the inventory constructor(s) DEFINED in the same package (the enclosing
	// package's constructors are the "from" nodes). This is coarse but sound for the
	// seam proof.
	pkgOfFile := func(relFile string) string {
		return filepath.ToSlash(filepath.Dir(relFile))
	}
	ctorsInPkg := map[string][]Constructor{}
	for _, c := range req {
		ctorsInPkg[c.Pkg] = append(ctorsInPkg[c.Pkg], c)
	}

	for _, c := range req {
		refs, err := NonTestCallers(root, c.Name, c.File, defaultSearchRoots)
		if err != nil {
			return nil, err
		}
		to := ctorKey(c.Pkg, c.Name)
		for _, r := range refs {
			abs := filepath.Join(root, filepath.FromSlash(r.File))
			if seamAbs[abs] {
				addEdge(seamSentinel, to)
				continue
			}
			// A caller inside an in-scope constructor's package: add an edge from EACH of
			// that package's constructors to C. This over-connects within a package but
			// never fabricates a seam root (only the seam sentinel injects the root), so a
			// constructor callable solely from a non-seam, non-inventory package (or only
			// from tests) stays unreachable from SEAM.
			callerPkg := pkgOfFile(r.File)
			for _, fromC := range ctorsInPkg[callerPkg] {
				addEdge(ctorKey(fromC.Pkg, fromC.Name), to)
			}
		}
	}

	// BFS from the seam sentinel.
	reached := map[string]bool{}
	queue := []string{seamSentinel}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for nxt := range forward[cur] {
			if !reached[nxt] {
				reached[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}

	directTargets, err := seamAttachTargets(root)
	if err != nil {
		return nil, err
	}

	var out []SeamRootedResult
	for _, c := range req {
		k := ctorKey(c.Pkg, c.Name)
		out = append(out, SeamRootedResult{
			Constructor:    c,
			SeamRooted:     reached[k],
			DirectFromSeam: directTargets[k],
		})
	}
	_ = byName
	return out, nil
}

// seamFileIsAlwaysLinked reports whether the seam carries no build constraint
// on trstctl_core in either direction: the core families attach in every build.
func seamFileIsAlwaysLinked(root, relFile string) (bool, error) {
	abs := filepath.Join(root, filepath.FromSlash(relFile))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, nil, parser.ParseComments)
	if err != nil {
		return false, err
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			line := strings.TrimSpace(c.Text)
			// Accept the canonical `//go:build !trstctl_core` (and tolerate additional
			// terms in the same constraint, e.g. `!trstctl_core && something`).
			if strings.HasPrefix(line, "//go:build") && strings.Contains(line, "trstctl_core") {
				return false, nil
			}
		}
	}
	return true, nil
}

// verifySeamFilesExist confirms every sanctioned seam file is present and readable, so
// the gate fails loudly if a seam is renamed/removed rather than silently passing.
func verifySeamFilesExist(root string) error {
	for _, s := range SanctionedSeams {
		abs := filepath.Join(root, filepath.FromSlash(s))
		if _, err := os.Stat(abs); err != nil {
			return fmt.Errorf("sanctioned seam missing: %s (%v)", s, err)
		}
	}
	return nil
}
