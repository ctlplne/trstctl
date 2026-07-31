// SPDX-License-Identifier: MPL-2.0

package server

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProductionIdempotencyConstructorsAttachTenantResultProtector is the
// regression wall for S-3def6339. The two non-test constructors are split
// across the walking-skeleton app and the served server; both must keep the
// explicit option, while Run and bootstrap must build the real tenant-aware
// protector rather than relying on a nil test seam.
func TestProductionIdempotencyConstructorsAttachTenantResultProtector(t *testing.T) {
	t.Parallel()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	serverDir := filepath.Dir(current)
	assertSourceContains(t, filepath.Join(serverDir, "server.go"),
		"orchestrator.WithResultProtector(d.IdempotencyResultProtector)")
	assertSourceContains(t, filepath.Join(serverDir, "run.go"),
		"IdempotencyResultProtector: resultProtector")
	assertSourceContains(t, filepath.Join(serverDir, "run.go"),
		"IdempotencyResultMigrator:  resultMigrator")
	assertSourceContains(t, filepath.Join(serverDir, "bootstrap.go"),
		"idempotencyResultProtectionFromConfig(cfg.Secrets, st, kek)")
	assertSourceContains(t, filepath.Join(serverDir, "bootstrap.go"),
		"resultMigrator.MigrateAll(ctx)")
	assertSourceContains(t, filepath.Join(serverDir, "bootstrap.go"),
		"app.New(log, st, resultProtector)")
	assertSourceContains(t, filepath.Join(serverDir, "..", "app", "app.go"),
		"orchestrator.WithResultProtector(resultProtector)")
}

func assertSourceContains(t *testing.T, path, anchor string) {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(source), anchor) {
		t.Fatalf("%s no longer contains production result-protector anchor %q", path, anchor)
	}
}
