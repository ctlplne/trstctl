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
// regression wall for S-3def6339 and I-aa8623a3. The two non-test
// constructors are split across the walking-skeleton app and the served
// server; both must keep the explicit option, while Run and bootstrap must
// build the real tenant-aware protector rather than relying on a nil test
// seam. The served server must also attach the lifecycle built from that same
// wrapper registry and the production history-proof chain.
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
		"IdempotencyResultProtector:  resultProtector")
	assertSourceContains(t, filepath.Join(serverDir, "run.go"),
		"IdempotencyResultMigrator:   resultMigrator")
	assertSourceContains(t, filepath.Join(serverDir, "run.go"),
		"IdempotencyResultFleetReady: cfg.Secrets.IdempotencyResultFleetReady")
	assertSourceContains(t, filepath.Join(serverDir, "run.go"),
		"tenantseal.NewLifecycle(")
	assertSourceContains(t, filepath.Join(serverDir, "run.go"),
		"historyRewriteProofOptions(st, auditKey)...")
	assertSourceContains(t, filepath.Join(serverDir, "run.go"),
		"TenantKeyDomains:            tenantKeyDomains")
	assertSourceContains(t, filepath.Join(serverDir, "run.go"),
		"TenantCrypto:                tenantCrypto")
	assertSourceContains(t, filepath.Join(serverDir, "server.go"),
		"api.WithTenantKeyDomainLifecycle(d.TenantKeyDomains)")
	assertSourceContains(t, filepath.Join(serverDir, "secrets.go"),
		"TenantCrypto:       d.TenantCrypto")
	assertSourceContains(t, filepath.Join(serverDir, "..", "api", "secrets.go"),
		"TenantCrypto tenantseal.Access")
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
	source, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(source), anchor) {
		t.Fatalf("%s no longer contains production result-protector anchor %q", path, anchor)
	}
}
