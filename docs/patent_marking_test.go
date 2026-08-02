// SPDX-License-Identifier: MPL-2.0

package docs

// LEGAL-001 (audit finding AH-e1107297): patent marking under ee/ must match the
// filings that actually exist. certctl LLC has four US provisional applications on
// file — PCAS, XREC, VDEC and AGID, filed July 2026 — and nothing has issued, so
// "patent pending" is the only accurate marking. Describing an unpatented article
// as patented is false marking under 35 U.S.C. section 292, so this is a legal
// guard, not a style guard.
//
// Two locks:
//
//   - TestEEPatentMarkingClaimsOnlyPendingStatus scans every TRACKED prose file
//     under ee/ and fails if any of them asserts a granted patent, then requires
//     the two PCAS marking sites (ee/README.md, ee/succession/doc.go) to carry the
//     pending wording, the filing that backs it, and the owning entity.
//   - TestPatentStatusIsPendingNotGranted holds the same line for the two public
//     license-facing documents outside ee/ (README.md, ee/LICENSE) and — when a
//     maintainer checkout sits beside the out-of-tree filings directory — verifies
//     that every filed application really is a provisional.
//
// The scan asks git for the tracked set rather than walking the filesystem, the
// same way CODE-105 (docs/agent_contract_files_test.go) does. An agent tool or an
// editor that leaves an untracked file in a working tree is not a published patent
// marking: AH-0002 relocated ee/succession/AGENTS.md — the third original site of
// this finding — out of the repository and into .gitignore, yet a copy can still
// sit in a maintainer's tree, and that copy must not turn the suite red.
//
// Helper `read` is defined in docs/docs_test.go (same package).

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// patentMarkingExtensions are the file kinds under ee/ that carry prose a reader
// could take as a patent marking. Fuzz corpora and binaries are not markings.
var patentMarkingExtensions = map[string]bool{
	".go":    true,
	".json":  true,
	".md":    true,
	".proto": true,
	".sql":   true,
}

// grantedPatentClaims are phrasings that assert an ISSUED patent. None may appear
// while only provisional applications are on file. Phrase every correction so it
// does not need one of these — say "nothing has issued", not "not a granted
// patent" — because this is a substring test with no notion of negation.
var grantedPatentClaims = []string{
	"granted patent",
	"patent granted",
	"issued patent",
	"patent issued",
	"patent no.",
	"patent number",
}

// isPatentMarkingFile reports whether a repository-relative path is prose that a
// patent marking could live in.
func isPatentMarkingFile(rel string) bool {
	switch filepath.Base(rel) {
	case "LICENSE", "NOTICE":
		return true
	}
	return patentMarkingExtensions[strings.ToLower(filepath.Ext(rel))]
}

// unqualifiedPatentedOffsets returns every offset in body where the word
// "patented" appears WITHOUT the forward-looking "future " qualifier that
// ee/LICENSE legitimately uses ("future patented features belong behind this ee/
// boundary"). Saying a feature will be patented one day is a plan; saying it is
// patented today is a marking.
func unqualifiedPatentedOffsets(body string) []int {
	const word = "patented"
	const qualifier = "future "
	low := strings.ToLower(body)
	var out []int
	for i := 0; ; {
		j := strings.Index(low[i:], word)
		if j < 0 {
			return out
		}
		at := i + j
		if at < len(qualifier) || low[at-len(qualifier):at] != qualifier {
			out = append(out, at)
		}
		i = at + len(word)
	}
}

// excerpt returns a short single-line window of body around at, so a failure
// names the offending sentence instead of only a byte offset.
func excerpt(body string, at int) string {
	lo := at - 60
	if lo < 0 {
		lo = 0
	}
	hi := at + 60
	if hi > len(body) {
		hi = len(body)
	}
	return strings.Join(strings.Fields(strings.ToValidUTF8(body[lo:hi], "")), " ")
}

// TestEEPatentMarkingClaimsOnlyPendingStatus is the load-bearing half of
// LEGAL-001: no tracked prose file under ee/ may assert a granted patent, and the
// two PCAS marking sites must state the true status.
func TestEEPatentMarkingClaimsOnlyPendingStatus(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "-z", "--", "ee")
	cmd.Dir = ".."
	out, err := cmd.Output()
	if err != nil {
		// This guard asks the git index on purpose, so it cannot run against an
		// exported tree or a build context that omits .git. Say so, and surface
		// git's own stderr rather than a bare exit code.
		detail := ""
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			detail = ": " + strings.TrimSpace(string(exitErr.Stderr))
		}
		t.Fatalf("LEGAL-001: list tracked ee/ files: %v%s — this guard reads the git index, so it requires a real git checkout", err, detail)
	}

	scanned := 0
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" || !isPatentMarkingFile(rel) {
			continue
		}
		scanned++
		body := read(t, filepath.FromSlash("../"+rel))
		for _, at := range unqualifiedPatentedOffsets(body) {
			t.Errorf("LEGAL-001: %s marks an ee/ feature as already patented, but certctl LLC holds provisional applications only and nothing has issued — use the pending wording: ...%s...", rel, excerpt(body, at))
		}
		low := strings.ToLower(body)
		for _, claim := range grantedPatentClaims {
			if k := strings.Index(low, claim); k >= 0 {
				t.Errorf("LEGAL-001: %s asserts a granted patent (%q); only provisional applications are on file: ...%s...", rel, claim, excerpt(body, k))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("LEGAL-001: git reported no tracked prose files under ee/; this guard is not scanning the tree it thinks it is")
	}

	// The two sites this finding corrected must keep saying what is true, in the
	// words the operator picked: pending status, the filing that backs it, and the
	// owning entity. Dropping any one of the three turns an accurate marking back
	// into a vague one.
	for _, f := range []string{"../ee/README.md", "../ee/succession/doc.go"} {
		body := read(t, f)
		for _, want := range []string{"patent-pending", "provisional application", "certctl LLC"} {
			if !strings.Contains(body, want) {
				t.Errorf("LEGAL-001: %s no longer states %q; the PCAS patent marking must name its pending status, the provisional filing behind it, and the owning entity", f, want)
			}
		}
	}
}

// TestPatentStatusIsPendingNotGranted guards the license-facing documents outside
// ee/ and, on a maintainer checkout, cross-checks the filings themselves.
func TestPatentStatusIsPendingNotGranted(t *testing.T) {
	// In-tree half — always runs, in CI too. The two public license-facing
	// documents may use "patented" only in the forward-looking form.
	for _, f := range []string{"../README.md", "../ee/LICENSE"} {
		body := read(t, f)
		for _, at := range unqualifiedPatentedOffsets(body) {
			t.Errorf("LEGAL-001: %s uses \"patented\" outside the forward-looking \"future patented features\" form; nothing has issued: ...%s...", f, excerpt(body, at))
		}
	}

	// Out-of-tree half. The applications are not publishable and live beside the
	// repository, so this half only has something to check on a maintainer
	// checkout; CI has no such directory and the half above is load-bearing.
	// Deliberately not t.Skip — the assertions above already ran and stand.
	const filings = "../../patents"
	entries, err := os.ReadDir(filepath.FromSlash(filings))
	if err != nil {
		t.Logf("LEGAL-001: filings directory %s not reachable (%v); the in-tree marking assertions above still ran", filings, err)
		return
	}
	filed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.EqualFold(filepath.Ext(name), ".pdf") || !strings.Contains(name, "FILING-FINAL") {
			continue
		}
		filed++
		if !strings.Contains(name, "-PROV-") {
			t.Errorf("LEGAL-001: %s/%s is a filed application that is not a provisional; the patent-pending marking under ee/ must be re-reviewed with counsel before it stays as written", filings, name)
		}
	}
	if filed == 0 {
		t.Errorf("LEGAL-001: %s exists but holds no *FILING-FINAL*.pdf application; this cross-check is not looking at the filings it thinks it is", filings)
	}
}
