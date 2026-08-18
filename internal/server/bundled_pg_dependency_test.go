// SPDX-License-Identifier: MPL-2.0

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedCommandsExcludeLibPQ locks the actual compiled dependency graph.
// Think of it as checking every box packed for delivery, not merely checking the
// shopping list: lib/pq must not be linked into any shipped command after its five
// reachable GO-2026 vulnerabilities were published without a fixed release.
func TestShippedCommandsExcludeLibPQ(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-deps", "./cmd/...") // #nosec G204 -- fixed local Go tool and package pattern (CWE-78)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list shipped command dependencies: %v\n%s", err, out)
	}
	for _, dependency := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(dependency) == "github.com/lib/pq" {
			t.Fatal("shipped command dependency graph still links github.com/lib/pq; GO-2026-6166/6168/6170/6171/6172 remain reachable")
		}
	}

	patchedSource := filepath.Join(root, "third_party", "embedded-postgres", "prepare_database.go")
	source, err := os.ReadFile(patchedSource) // #nosec G304 -- fixed repository source path (CWE-22)
	if err != nil {
		t.Fatalf("read embedded-postgres security patch: %v", err)
	}
	text := string(source)
	if strings.Contains(text, "github.com/lib/pq") {
		t.Fatal("embedded-postgres security patch regressed to lib/pq")
	}
	for _, anchor := range []string{"github.com/jackc/pgx/v5", "stdlib.GetConnector"} {
		if !strings.Contains(text, anchor) {
			t.Fatalf("embedded-postgres security patch lost pgx anchor %q", anchor)
		}
	}
}
