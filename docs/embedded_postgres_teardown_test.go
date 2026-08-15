// SPDX-License-Identifier: MPL-2.0

package docs

import (
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
		if !strings.Contains(src, "embeddedpostgres") || !strings.Contains(src, ".Start()") {
			return nil
		}
		checked++
		// Stop may be called directly or captured as a function value first
		// (ee/federation stores pg.Stop and invokes it from TestMain), so this
		// looks for the identifier rather than a specific call shape.
		if !strings.Contains(src, "Stop") {
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
