// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secrets"
	"trstctl.com/trstctl/internal/store"
)

// CR-045: production source constructors must carry tenant custody before
// events.Open can inspect history or accept any event, including public events.
func TestProductionEventLogConstructorsUsePrebuiltTenantCustodyCR045(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if ok && ident.Name == "openConfiguredEventSource" {
				t.Errorf("%s opens production event source without prebuilt tenant custody", name)
			}
			return true
		})
	}
}

// CR-045: a restore projector needs the same keyring that opened its retained
// event source, or changed rewrap pairs fail only after restore has mutated state.
func TestProductionRestoreProjectorsCarryPrebuiltTenantCustodyCR045(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "backup.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if ok && ident.Name == "recoveryProjectionOptions" {
			t.Error("production restore projector omitted its prebuilt tenant custody")
		}
		return true
	})
}

func TestConfiguredEventSourceWithoutTenantCustodyRefusesPublicAppend(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	log, protection, err := openConfiguredEventSource(t.Context(), cfg, st, testAuditSigningKey(t), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = protection.Close() })
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(t.Context(), events.Event{TenantID: "49900000-0000-4000-8000-0000000000cb",
		Type: "tenant.registered", Data: []byte(`{"name":"unadmitted"}`)}); err == nil {
		t.Fatal("production event source without tenant custody published a public event")
	}
	if head, err := log.LastSequence(t.Context()); err != nil || head != 0 {
		t.Fatalf("missing custody changed event head=%d err=%v", head, err)
	}
}

func TestRunTenantCustodyCoreReusesResolverAndKeyring(t *testing.T) {
	st := newServerTestStore(t)
	key, err := secrets.LoadOrCreateKEK(filepath.Join(t.TempDir(), "deployment.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	cfg := &config.Config{}
	core, err := newRunTenantCustodyCore(cfg, st, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	protector, migrator, lifecycle, access, deployment, err := runTenantCustodyFromCore(cfg, st, nil, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycle != nil || protector != core.protector || migrator != core.migrator ||
		access != core.access || deployment.keyring != core.keyring || deployment.registry != core.registry {
		t.Fatal("log-attached stage rebuilt or replaced the early custody core")
	}
}

func TestRunConstructsTenantCustodyBeforeEventLogOpen(t *testing.T) {
	code, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(code), "func RunWithExtraMigrations(")
	end := strings.Index(string(code), "// openArchiveObjectStore")
	if start < 0 || end <= start {
		t.Fatal("cannot locate production Run assembly")
	}
	assembly := string(code[start:end])
	early := strings.Index(assembly, "newRunTenantCustodyCore(")
	open := strings.Index(assembly, "openConfiguredEventSourceWithCustody(")
	build := strings.Index(assembly, "buildRunDepsWithCustody(")
	if early < 0 || open <= early || build <= open {
		t.Fatal("production Run must assemble one custody core before event-log Open and reuse it in Build deps")
	}
}

func TestRunRebuildRefusesMissingDeploymentKEKWithoutCreatingIt(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = serverTestPostgresDSN(t)
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = startBackupTestNATS(t).ClientURL()
	cfg.NATS.Replicas, cfg.NATS.AllowSingleReplica = 1, true
	installSiblingSignerBinary(t)
	cfg.Signer.AllowInsecureDevNonLinux = runtime.GOOS != "linux"
	cfg.Signer.Socket = filepath.Join(t.TempDir(), "signer.sock")
	if _, err := RunRebuild(t.Context(), cfg); !errors.Is(err, os.ErrNotExist) ||
		!strings.Contains(err.Error(), "deployment KEK") {
		t.Fatalf("rebuild without existing deployment KEK=%v, want missing-custody refusal", err)
	}
	if _, err := os.Stat(cfg.Secrets.KEKFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rebuild created or changed missing deployment KEK: %v", err)
	}
	var unresolved int
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND activity_kind='maintenance' AND lane='standalone-rebuild' AND phase='started'`,
		store.RestoreControlTenantID).Scan(&unresolved); err != nil || unresolved != 0 {
		t.Fatalf("missing-key refusal left %d unresolved rebuild starts: %v", unresolved, err)
	}
}
