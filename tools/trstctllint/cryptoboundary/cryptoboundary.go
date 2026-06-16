// Package cryptoboundary implements the AN-3 architecture rule: the standard
// library's crypto and crypto/* packages may be imported only from within
// internal/crypto (and its subpackages), which is the one sanctioned
// cryptography boundary. Every other package must route crypto operations
// through that boundary's interfaces.
//
// AN-3 covers more than the standard library. CLAUDE.md §2 says "no crypto
// imports exist anywhere else" and the contract's intent is one auditable
// cryptography boundary; a package that pulled a third-party cipher
// (golang.org/x/crypto, github.com/cloudflare/circl) outside internal/crypto
// would defeat that just as surely as importing crypto/x509 (CRYPTO-002).
// So third-party crypto modules are forbidden outside the boundary too — but
// only in production (non-test) files: differential/conformance tests
// legitimately drive a reference implementation (the upstream ACME or SSH
// client) as a known-good oracle (CLAUDE.md §6), which is a test concern, not a
// handler/service pulling crypto outside the boundary. The stdlib crypto/* ban
// stays absolute (every file) as before.
package cryptoboundary

import (
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	modulePath  = "trstctl.com/trstctl"
	boundaryPkg = modulePath + "/internal/crypto"
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

// withinBoundary reports whether pkgPath is the crypto boundary or a subpackage
// of it (for example a backend implementation under internal/crypto).
func withinBoundary(pkgPath string) bool {
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
