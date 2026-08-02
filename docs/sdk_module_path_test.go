// SPDX-License-Identifier: MPL-2.0

package docs

// SDKPATH-001 / SDKPATH-002 — the Go SDK's module path is a VANITY path.
//
// clients/sdk/go/go.mod declares `module trstctl.com/sdk/go`, but the code is
// hosted at github.com/ctlplne/trstctl. `go get trstctl.com/sdk/go` therefore
// resolves only if trstctl.com serves a `go-import` meta tag for that path —
// and nothing in this repository serves one. That is a hosting prerequisite an
// integrator cannot guess, so the SDK README must state it (or state a fallback
// that works without it). These guards fail if the README stops documenting the
// prerequisite while the module path still points at a host that is not the
// repository host, and if .github/CODEOWNERS re-asserts that the `ctlplne` org
// namespace is "the same one used for the module path" (it is not).
//
// Helper `read` is defined in docs/docs_test.go (same package).

import (
	"strings"
	"testing"
)

// canonicalRepoHost is the host that actually serves this repository (README.md:
// `git clone https://github.com/ctlplne/trstctl`). Go resolves module paths under
// that host natively; a module path under any OTHER host resolves only through a
// `go-import` meta tag served by that other host.
const canonicalRepoHost = "github.com"

// goSDKModulePath returns the module path declared by clients/sdk/go/go.mod.
func goSDKModulePath(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(read(t, "../clients/sdk/go/go.mod"), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatal("SDKPATH-001: clients/sdk/go/go.mod declares no module path")
	return ""
}

// TestSDKPATH001GoSDKVanityModulePathDocumented locks the SDK README to the
// resolution story its own go.mod implies.
func TestSDKPATH001GoSDKVanityModulePathDocumented(t *testing.T) {
	mod := goSDKModulePath(t)
	readme := read(t, "../clients/sdk/README.md")

	if !strings.Contains(readme, "Module: `"+mod+"`") {
		t.Errorf("SDKPATH-001: clients/sdk/README.md must name the SDK module path %q as declared by clients/sdk/go/go.mod", mod)
	}
	if !strings.Contains(readme, "go get "+mod) {
		t.Errorf("SDKPATH-001: clients/sdk/README.md must print the install command %q an integrator will actually run", "go get "+mod)
	}

	host, _, _ := strings.Cut(mod, "/")
	if host == canonicalRepoHost {
		// The module path is under the repository host, so `go get` resolves with
		// no extra hosting. The README must not scare integrators off with a
		// go-import prerequisite that no longer applies.
		if strings.Contains(readme, "go-import") {
			t.Errorf("SDKPATH-001: module path %q is under the repository host %q and resolves natively, but clients/sdk/README.md still documents a go-import prerequisite; drop that section", mod, canonicalRepoHost)
		}
		return
	}

	// Vanity path: the README must document the meta tag, where it is served,
	// the repo-root constraint that makes the obvious mapping wrong, and a
	// fallback that works before the endpoint exists.
	for _, want := range []string{
		`<meta name="go-import" content="` + mod + ` git https://`,
		"?go-get=1",
		"at the root of that repository",
		"go mod edit -replace " + mod + "=./trstctl/clients/sdk/go",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("SDKPATH-001: module path %q is not under the repository host %q, so `go get %s` resolves only via a go-import meta tag; clients/sdk/README.md must still document %q", mod, canonicalRepoHost, mod, want)
		}
	}
}

// TestSDKPATH002CodeownersDoesNotClaimTheOrgIsTheModuleNamespace stops the
// CODEOWNERS header from re-asserting a false equivalence between the GitHub
// org namespace and the Go module namespace.
func TestSDKPATH002CodeownersDoesNotClaimTheOrgIsTheModuleNamespace(t *testing.T) {
	codeowners := read(t, "../.github/CODEOWNERS")
	if strings.Contains(codeowners, "same one used for the module path") {
		t.Error("SDKPATH-002: .github/CODEOWNERS claims the ctlplne org namespace is the same one used for the module path; the module paths are trstctl.com/* and do not match the host")
	}
	if host, _, _ := strings.Cut(goSDKModulePath(t), "/"); host != canonicalRepoHost {
		if !strings.Contains(codeowners, "vanity paths under trstctl.com") {
			t.Error("SDKPATH-002: the Go module paths are not under the repository host, so .github/CODEOWNERS must say they are vanity paths under trstctl.com rather than imply the org namespace matches")
		}
	}
}
