// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryEmbeddedPostgresHarnessStopsWhatItStarts guards against a test harness
// leaking a database server.
//
// ee/agentid/delegation/brokerstore called inst.Start() and never stopped it, so
// every invocation of that package left a PostgreSQL server running for the life
// of the machine, each holding a SysV shared-memory segment. macOS allows 32
// (kern.sysv.shmmni), so after roughly thirty runs NO Postgres-backed test in the
// repository can start: initdb fails with "could not create shared memory
// segment".
//
// What makes this worth a guard rather than a one-time fix is where the damage
// shows up. The package that leaks keeps passing; the failure lands on whichever
// Postgres-backed package happens to run next, as a setup error with no named
// test. It reads exactly like flakiness under load, which is how it survives.
func TestEveryEmbeddedPostgresHarnessStopsWhatItStarts(t *testing.T) {
	root := ".."
	var checked int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable trees are not this guard's business
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".sandbox-build", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path) // #nosec G304 G122 -- walks this repository's own test sources (CWE-22)
		if readErr != nil {
			return nil
		}
		src := string(body)
		if !strings.Contains(src, "embeddedpostgres") || !hasPostgresStart(src) {
			return nil
		}
		checked++
		if !hasPostgresCleanup(src) {
			t.Errorf("%s starts an embedded PostgreSQL and never stops it; every run of that "+
				"package leaks a server holding a shared-memory segment, and the resulting "+
				"failure lands on some OTHER package as an unexplained setup error", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
	if checked == 0 {
		t.Fatal("no embedded-postgres harnesses found; this guard is not testing anything")
	}
	t.Logf("checked %d embedded-postgres harnesses", checked)
}

func hasPostgresStart(src string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
	if err != nil {
		return false
	}
	start := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return true
		}
		if method, ok := call.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Start" {
			start = true
		}
		return true
	})
	return start
}

// Recognize actual method references, not comments containing "Stop". An
// owned foreground process is also cleaned up when the same command is
// signalled, reaped with Wait, and has a Kill fallback for a shutdown timeout.
// This remains a source guard, not proof that every runtime path reaches cleanup.
func hasPostgresCleanup(src string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
	if err != nil {
		return false
	}
	stop := false
	signalled, reaped, killed := map[string]bool{}, map[string]bool{}, map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		selector, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "Stop" {
			stop = true // also accepts a method value saved for TestMain cleanup
		}
		if command, ok := selector.X.(*ast.Ident); ok && selector.Sel.Name == "Wait" {
			reaped[command.Name] = true
		}
		process, ok := selector.X.(*ast.SelectorExpr)
		if !ok || process.Sel.Name != "Process" {
			return true
		}
		command, ok := process.X.(*ast.Ident)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "Signal":
			signalled[command.Name] = true
		case "Kill":
			killed[command.Name] = true
		}
		return true
	})
	for command := range signalled {
		if reaped[command] && killed[command] {
			return true
		}
	}
	return stop
}

func TestPostgresCleanupGuardRecognizesOnlyCleanupCode(t *testing.T) {
	if hasPostgresStart("package fixture\n// pg.Start()\nvar example = `pg.Start()`") ||
		!hasPostgresStart("package fixture\nfunc start() { pg.Start() }") {
		t.Fatal("start detection must inspect calls, not fixture strings or comments")
	}
	for _, fixture := range []struct {
		name, body string
		want       bool
	}{
		{"method value", "cleanup := pg.Stop; _ = cleanup", true},
		{"foreground", "cmd.Process.Signal(signal); cmd.Wait(); cmd.Process.Kill()", true},
		{"unreaped", "cmd.Process.Signal(signal); cmd.Process.Kill()", false},
		{"different process", "cmd.Process.Signal(signal); other.Wait(); cmd.Process.Kill()", false},
		{"comment", "// remember to call Stop\n", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if got := hasPostgresCleanup("package fixture\nfunc test() {\n" + fixture.body + "\n}"); got != fixture.want {
				t.Fatalf("cleanup evidence=%v, want %v", got, fixture.want)
			}
		})
	}
}
