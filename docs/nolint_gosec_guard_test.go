// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- CWEREG-001: gosec is suppressible only through the #nosec register --------
//
// The repository accepts exactly one way to waive a gosec finding: an inline
// `#nosec G### -- reason` at the call site. scripts/ci/gen-cwe-docs.py harvests
// every one of those into docs/security/cwe-register.md and refuses the tree
// when the rule id or a substantive reason is missing, so an accepted weakness
// is always attributable to a line and a stated reason.
//
// golangci-lint's own `nolint` directive suppresses the same gosec finding
// without leaving any row in the register, because the generator only knows
// about `#nosec`. That is a second, unaccountable door into the same room.
// TestNoNolintGosecEscapeHatch bricks it up.

// nolintDirectiveAt reports the linter list of a golangci-lint suppression
// directive that begins the first comment on line, and whether such a directive
// is present at all. golangci-lint honours the directive only when the marker
// is the first token of a comment, with no space between the comment slashes
// and it, so a mention of the marker inside ordinary comment prose — as in
// tools/trstctllint/doc.go, which documents that the architecture linter has no
// per-line escape hatch — is not a directive and is not reported here. This
// mirrors how scripts/ci/gen-cwe-docs.py distinguishes a real `#nosec`
// annotation from prose about one.
func nolintDirectiveAt(line, marker string) (list string, ok bool) {
	for i := 0; i+1 < len(line); i++ {
		if line[i] != '/' || (line[i+1] != '/' && line[i+1] != '*') {
			continue
		}
		if i > 0 && line[i-1] == ':' {
			continue // "https://…" is a scheme separator, not a comment opener
		}
		rest := line[i+2:]
		if !strings.HasPrefix(rest, marker) {
			// The first comment on this line opens with something else, so any
			// later occurrence of the marker is prose inside that comment.
			return "", false
		}
		rest = strings.TrimPrefix(rest, marker)
		if rest == "" || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '*' {
			return "", true // blanket directive: no list, every linter silenced
		}
		if rest[0] != ':' {
			return "", false // e.g. "nolintlint", not a directive
		}
		rest = rest[1:]
		if cut := strings.IndexAny(rest, " \t"); cut >= 0 {
			rest = rest[:cut]
		}
		return rest, true
	}
	return "", false
}

// TestNoNolintGosecEscapeHatch locks CWEREG-001: no tracked Go file may silence
// gosec with a golangci-lint suppression directive. A directive naming gosec —
// or a blanket directive naming no linter at all, which silences gosec along
// with everything else — bypasses the two-file `#nosec` + cwe-register contract
// and leaves an accepted weakness with no registered reason. Every such site
// must instead carry `#nosec G### -- <reason> (CWE-###)`, which the generator
// harvests into docs/security/cwe-register.md.
//
// The scan covers every tracked *.go file, including `ee/`, which sits outside
// the gosec scan scope and therefore outside the generator's reach.
//
// ELI5: there is one door for "we looked at this and accepted it", and walking
// through it writes your name in the visitors' book. This test bricks up the
// side window.
func TestNoNolintGosecEscapeHatch(t *testing.T) {
	t.Parallel()

	// Assembled at runtime so this guard is not itself a match, the same trick
	// TestDebtMarkersRequireOwnerOrIssue (CODE-101) uses for debt markers.
	marker := "no" + "lint"

	var offenders []string
	for _, rel := range gitTrackedFiles(t) {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel))) // #nosec G304 -- test reads a path listed by this repository's own git index (CWE-22)
		if err != nil {
			t.Fatalf("CWEREG-001: read %s: %v", rel, err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			list, ok := nolintDirectiveAt(line, marker)
			if !ok {
				continue
			}
			named := strings.Split(list, ",")
			blanket := strings.TrimSpace(list) == ""
			silencesGosec := blanket
			for _, one := range named {
				if strings.TrimSpace(one) == "gosec" {
					silencesGosec = true
				}
			}
			if !silencesGosec {
				continue
			}
			why := "names gosec"
			if blanket {
				why = "is blanket, so it silences gosec too"
			}
			offenders = append(offenders, rel+":"+itoa(i+1)+" ("+why+")")
		}
	}
	if len(offenders) > 0 {
		t.Errorf("CWEREG-001: %d golangci-lint suppression directive(s) silence gosec without a cwe-register row; "+
			"replace each with `#nosec G### -- <reason> (CWE-###)` at the same call site and regenerate "+
			"docs/security/cwe-register.md (make cwe-docs-check): %s",
			len(offenders), strings.Join(offenders, ", "))
	}
}

// TestGosecWaiversForTrustAnchorPathsAreRegistered is the positive half of
// CWEREG-001: the sites that used to carry an unregistered suppression must now
// appear in the generated register. Paths, not line numbers, are asserted — the
// generator owns the line anchors and rewrites them on every regeneration.
func TestGosecWaiversForTrustAnchorPathsAreRegistered(t *testing.T) {
	t.Parallel()

	register := read(t, "security/cwe-register.md")
	for _, want := range []string{
		"`internal/crypto/mtls/signer.go:",
		"`internal/server/agentchannel.go:",
		"`internal/crypto/mtls/reload_test.go:",
	} {
		if !strings.Contains(register, want) {
			t.Errorf("CWEREG-001: cwe-register.md has no waiver row for %s...; a gosec suppression there is unregistered again", want)
		}
	}
}
