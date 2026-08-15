// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// deferredWipeOfField matches `defer secret.Wipe(x.Field...)` — a wipe whose
// argument is a STRUCT FIELD evaluated at defer-statement time.
var deferredWipeOfField = regexp.MustCompile(`defer\s+secret\.Wipe\([a-zA-Z_][A-Za-z0-9_]*\.[A-Za-z]`)

// TestNoDeferredWipeOfAnUnpopulatedField is the regression guard for the
// silent-no-op secret wipe (AN-8).
//
// `defer secret.Wipe(out.Token)` evaluates out.Token AT THE DEFER STATEMENT.
// When the field is only populated afterwards — which is the whole shape of
// "declare a response struct, defer the wipe, then decode into it" — the defer
// captures a nil slice, wipes nothing, and the decoder's fresh backing array is
// never zeroed. The secret then lives in the heap for the process lifetime while
// the code reads as though it were being cleaned up, which is worse than no
// wipe at all because it looks handled.
//
// Seven sites had exactly this shape (GCP STS tokens, AWS/GCP/Azure dynamic
// secret material, GCP/Azure secret-sync payloads). The correct form defers a
// CLOSURE, so the field is read when the function returns:
//
//	defer func() { secret.Wipe(out.Token) }()
//
// Wiping a field that is already populated (a pem.Block, a request being sent)
// is fine, so this guard names the known-good sites explicitly rather than
// banning the shape outright.
func TestNoDeferredWipeOfAnUnpopulatedField(t *testing.T) {
	// The docs test package runs from docs/, so the repo root is one level up.
	const root = ".."
	for _, dir := range []string{"internal", "ee", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			raw, readErr := os.ReadFile(path) // #nosec G304 -- walking the repo's own tree (CWE-22)
			if readErr != nil {
				return readErr
			}
			for _, hit := range findDeferredWipeBeforeDecode(string(raw)) {
				t.Errorf("%s:%d: `defer secret.Wipe(%s.%s)` evaluates the field NOW, but %q is decoded into at line %d — "+
					"the defer captures a nil slice, wipes nothing, and the secret survives in the heap (AN-8). "+
					"Use: defer func() { secret.Wipe(%s.%s) }()",
					filepath.ToSlash(rel), hit.deferLine, hit.recv, hit.field, hit.recv, hit.decodeLine, hit.recv, hit.field)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}

type deferredWipeHit struct {
	deferLine  int
	decodeLine int
	recv       string
	field      string
}

var (
	deferWipeField = regexp.MustCompile(`^\s*defer\s+secret\.Wipe\(([a-zA-Z_][A-Za-z0-9_]*)\.([A-Za-z][A-Za-z0-9_.]*)\)`)
	funcStart      = regexp.MustCompile(`^func\s`)
)

// findDeferredWipeBeforeDecode reports each `defer secret.Wipe(v.Field)` that is
// followed, IN THE SAME FUNCTION, by a decode into &v. That ordering is what
// makes the wipe a no-op; wiping a field that was already populated is correct
// and is not reported.
func findDeferredWipeBeforeDecode(src string) []deferredWipeHit {
	lines := strings.Split(src, "\n")
	var hits []deferredWipeHit
	type pending struct {
		line  int
		recv  string
		field string
	}
	var open []pending
	flush := func() { open = nil }
	for i, line := range lines {
		if funcStart.MatchString(line) {
			flush()
		}
		if m := deferWipeField.FindStringSubmatch(line); m != nil {
			open = append(open, pending{line: i + 1, recv: m[1], field: m[2]})
			continue
		}
		for _, p := range open {
			// A decode INTO the same variable, after the defer.
			if strings.Contains(line, "&"+p.recv) &&
				(strings.Contains(line, "Unmarshal") || strings.Contains(line, "Decode") ||
					strings.Contains(line, "JSON(") || strings.Contains(line, "decodeJSON")) {
				hits = append(hits, deferredWipeHit{deferLine: p.line, decodeLine: i + 1, recv: p.recv, field: p.field})
			}
		}
	}
	return hits
}
