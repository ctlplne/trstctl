// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// agentContractFilenames are the agent-tooling contract filenames that must never
// be tracked in this repository again. Matching is case-insensitive: `agents.md`
// and `AGENTS.md` are the same file to every tool that loads them, and only a
// case-sensitive filesystem would present them as two distinct paths.
var agentContractFilenames = []string{"AGENTS.md", "CLAUDE.md"}

// TestAgentContractFilesStayUnshipped is the CODE-105 gate. AH-0002 relocated every
// AGENTS.md and CLAUDE.md out of this repository: they are agent-tooling working
// files, not product documentation, and this repository ships publicly. This test
// is the INVERSION of the two guards it replaces — the CLAUDE.md clause of CODE-004
// (TestKeyPackagesHaveLeafClaudeMd) and CODE-006 (TestKeyPackagesHaveAgentsMdShims)
// — which failed when those files were missing or too short. This one fails if any
// such file is tracked again, at any path, at any depth, in any letter case.
//
// It asks git, not the filesystem, deliberately. An agent tool that writes a local
// CLAUDE.md into a working tree is not a repository defect and must not turn the
// suite red; a file that enters the index is. .gitignore carries both bare names so
// an ordinary `git add -A` never gets that far, but .gitignore is advisory — it has
// no effect on an already-tracked path and `git add -f` walks straight past it — so
// the tracked-file assertion below is the load-bearing half, and the ignore rule is
// asserted here too so the soft half cannot be dropped without this noticing.
//
// CODE-004 keeps its unrelated protocol-doc clause; CODE-006 is not reused because
// internal/cloudhttp already carries an unrelated CODE-006.
func TestAgentContractFilesStayUnshipped(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = ".."
	out, err := cmd.Output()
	if err != nil {
		// This gate asks the git index on purpose, so it cannot run against an
		// exported tree, a vendored copy, or a Docker build context that omits
		// .git. Say so, and surface git's own stderr rather than a bare exit code.
		detail := ""
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			detail = ": " + strings.TrimSpace(string(exitErr.Stderr))
		}
		t.Fatalf("CODE-105: list tracked files: %v%s — this gate reads the git index, so it requires a real git checkout", err, detail)
	}

	scanned := 0
	var tracked []string
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		scanned++
		base := filepath.Base(filepath.FromSlash(rel))
		for _, name := range agentContractFilenames {
			if strings.EqualFold(base, name) {
				tracked = append(tracked, rel)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("CODE-105: git reported zero tracked files; this gate is not scanning the repository it thinks it is")
	}
	if len(tracked) > 0 {
		t.Errorf("CODE-105: %d agent-contract file(s) are tracked again (%s); AGENTS.md/CLAUDE.md are agent working files kept outside this repository and must not be republished — untrack them with `git rm --cached`", len(tracked), strings.Join(tracked, ", "))
	}

	ignore := read(t, "../.gitignore")
	for _, name := range agentContractFilenames {
		if !gitignoreHasBarePattern(ignore, name) {
			t.Errorf("CODE-105: .gitignore no longer carries a bare %q pattern; the accidental `git add -A` must be stopped before it reaches the tracked-file assertion above", name)
		}
	}
}

// gitignoreHasBarePattern reports whether the .gitignore body carries name as its
// own depth-independent pattern — a bare `AGENTS.md` line, which git matches at
// every directory level — rather than a rooted `/AGENTS.md` (repository root only)
// or an incidental substring of some other rule.
func gitignoreHasBarePattern(ignore, name string) bool {
	for _, line := range strings.Split(ignore, "\n") {
		if strings.TrimSpace(line) == name {
			return true
		}
	}
	return false
}
