// SPDX-License-Identifier: BUSL-1.1

// Package cryptoboundary implements the AN-3 architecture rule: the standard
// library's crypto and crypto/* packages may be imported only from within
// internal/crypto (and its subpackages), which is the one sanctioned
// cryptography boundary. Every other package must route crypto operations
// through that boundary's interfaces.
//
// AN-3 covers more than the standard library. The AN-3 invariant is that "no
// crypto imports exist anywhere else", and its intent is one auditable
// cryptography boundary; a package that pulled a third-party cipher
// (golang.org/x/crypto, github.com/cloudflare/circl) outside internal/crypto
// would defeat that just as surely as importing crypto/x509 (CRYPTO-002).
// So third-party crypto modules are forbidden outside the boundary too — but
// only in production (non-test) files: differential/conformance tests
// legitimately drive a reference implementation (the upstream ACME or SSH
// client) as a known-good oracle (the conformance-oracle carve-out), which is a test concern, not a
// handler/service pulling crypto outside the boundary. The stdlib crypto/* ban
// stays absolute (every file) as before.
package cryptoboundary

import (
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	modulePath = "trstctl.com/trstctl"
	// boundaryPkg = modulePath + "/internal/crypto" remains the canonical MPL
	// crypto boundary; ee/pqc is the proprietary PQC implementation boundary.
	boundaryPkg      = modulePath + "/internal/crypto"
	eePQCBoundaryPkg = modulePath + "/ee/pqc"
)

// thirdPartyCryptoPrefixes are third-party cryptography module path prefixes that,
// like the stdlib crypto/*, must not be imported outside the crypto boundary.
// Extending this list is a deliberate, reviewed change (with a fixture).
var thirdPartyCryptoPrefixes = []string{
	"golang.org/x/crypto/",
	"github.com/cloudflare/circl/",
}

// Analyzer enforces AN-3.
var Analyzer = &analysis.Analyzer{
	Name: "cryptoboundary",
	Doc:  "AN-3: crypto/* (and third-party crypto in non-test code) may be imported only inside internal/crypto and its subpackages.",
	Run:  run,
}

func run(pass *analysis.Pass) (interface{}, error) {
	if withinBoundary(pass.Pkg.Path()) {
		// AN-3 has two halves and only one was enforced.
		//
		// Outward: nothing outside internal/crypto may import crypto/* or a
		// third-party crypto library. That is the rule everyone thinks of, and
		// it is checked below.
		//
		// Inward: the boundary must stay SMALL. A package inside it that
		// imports the platform drags the platform's dependencies into the
		// boundary, and the value of a boundary is precisely that you can read
		// all of it. Nothing enforced this — a package under internal/crypto
		// was exempt from every check, so the boundary could have quietly grown
		// to include the store, the API, or anything else.
		//
		// It exists because the first convenient violation is always the one
		// that looks harmless: importing internal/protocols/acme into acmekey
		// to reuse one record-name helper would pull in internal/ca and take
		// the boundary from two internal dependencies to most of the platform.
		if withinMPLBoundary(pass.Pkg.Path()) {
			return nil, checkInboundImports(pass)
		}
		return nil, nil
	}
	for _, file := range pass.Files {
		isTest := strings.HasSuffix(pass.Fset.File(file.Pos()).Name(), "_test.go")
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			switch {
			case isStdlibCryptoImport(path):
				pass.Reportf(imp.Pos(),
					"import %q is not allowed outside internal/crypto (AN-3); route crypto through the internal/crypto boundary",
					path)
			case !isTest && isThirdPartyCryptoImport(path):
				pass.Reportf(imp.Pos(),
					"import %q is third-party cryptography and is not allowed outside internal/crypto (AN-3); route it through the internal/crypto boundary",
					path)
			}
		}
	}
	return nil, nil
}

// withinBoundary reports whether pkgPath may import crypto/* and third-party
// cryptography: the MPL boundary, or the proprietary PQC boundary under ee/.
func withinBoundary(pkgPath string) bool {
	return withinMPLBoundary(pkgPath) ||
		pkgPath == eePQCBoundaryPkg || strings.HasPrefix(pkgPath, eePQCBoundaryPkg+"/")
}

// withinMPLBoundary reports whether pkgPath is internal/crypto or a subpackage.
//
// The two boundaries are one set for the OUTWARD rule and two different things
// for the INWARD one, and conflating them is a mistake worth naming: this check
// originally used withinBoundary for both, which made ee/pqc subject to the
// inward rule and reported its imports of internal/signing as violations. Those
// imports are not violations. ee/pqc reaches the runtime by implementing
// signing.KeyFactory at the attach seam, so importing core is how AN-9 says an
// ee/ package is supposed to work ("ee/ may import core") — the alternative
// would be duplicating the signer's proto types into ee/, which is strictly
// worse for the property this rule protects.
//
// So: ee/pqc is inside the boundary for "may hold crypto" and outside it for
// "must stay small". Only internal/crypto — the auditable MPL boundary whose
// whole value is that a reader can hold it in their head — is subject to the
// inward half.
func withinMPLBoundary(pkgPath string) bool {
	return pkgPath == boundaryPkg || strings.HasPrefix(pkgPath, boundaryPkg+"/")
}

// isStdlibCryptoImport reports whether an import path is the stdlib crypto
// package or one of its subpackages (crypto, crypto/x509, crypto/ecdsa, ...).
func isStdlibCryptoImport(path string) bool {
	return path == "crypto" || strings.HasPrefix(path, "crypto/")
}

// isThirdPartyCryptoImport reports whether an import path is one of the
// recognized third-party cryptography modules that must also stay behind the
// boundary.
func isThirdPartyCryptoImport(path string) bool {
	for _, p := range thirdPartyCryptoPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// checkInboundImports enforces the inward half of AN-3: a package inside the
// crypto boundary may not import a trstctl package from outside it.
//
// Test files are exempt. A boundary test may legitimately reach for a fixture
// or a harness, and the property being protected is what the SHIPPED boundary
// depends on.
func checkInboundImports(pass *analysis.Pass) error {
	for _, file := range pass.Files {
		if strings.HasSuffix(pass.Fset.File(file.Pos()).Name(), "_test.go") {
			continue
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if !strings.HasPrefix(path, modulePath+"/") {
				continue
			}
			// internal/crypto only, not withinBoundary: core importing ee/pqc
			// would break AN-9 in the other direction, so the boundary may
			// import itself and nothing else in the module.
			if withinMPLBoundary(path) {
				continue
			}
			pass.Reportf(imp.Pos(),
				"AN-3: %s is inside the crypto boundary and may not import %s from outside it. "+
					"The boundary's value is that it is small enough to read; importing the platform "+
					"into it drags the platform's dependencies in behind the import. Pass the value "+
					"across the boundary as a neutral type instead.",
				pass.Pkg.Path(), path)
		}
	}
	return nil
}
